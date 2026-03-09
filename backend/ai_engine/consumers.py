"""
Industry-grade Network Analysis WebSocket Consumer

Real-time network monitoring with:
- Process name/path resolution
- IP reputation checking (local threat feed + optional AbuseIPDB)
- Port risk classification
- GeoIP lookup
- Beaconing detection
- Connection risk scoring (0-100)
- Structured AI analysis with enriched context
"""
import json
import asyncio
import psutil
import time
import logging
from collections import defaultdict
from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings
from langchain_groq import ChatGroq
from langchain_core.prompts import PromptTemplate

from .threat_feeds import (
    is_ip_malicious, classify_port, calculate_connection_risk,
    is_private_ip, load_threat_feed, download_threat_feed_async,
)

logger = logging.getLogger(__name__)

# Try to import GeoIP
try:
    import geoip2.database
    import geoip2.errors
    HAS_GEOIP = False  # Will be set True if DB is found
    _geoip_reader = None
except ImportError:
    HAS_GEOIP = False
    _geoip_reader = None


def _init_geoip():
    """Initialize GeoIP reader if database is available."""
    global HAS_GEOIP, _geoip_reader
    import os
    
    # Common GeoLite2 database locations
    possible_paths = [
        os.path.join(settings.BASE_DIR, 'geoip', 'GeoLite2-Country.mmdb'),
        os.path.join(settings.BASE_DIR, 'GeoLite2-Country.mmdb'),
        '/usr/share/GeoIP/GeoLite2-Country.mmdb',
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            try:
                _geoip_reader = geoip2.database.Reader(path)
                HAS_GEOIP = True
                logger.info(f"GeoIP database loaded from {path}")
                return
            except Exception as e:
                logger.error(f"Failed to load GeoIP database: {e}")
    
    logger.info("GeoIP database not found. Country lookup disabled.")


def get_geo_country(ip_str):
    """Look up the country code for an IP address."""
    if not HAS_GEOIP or not _geoip_reader or is_private_ip(ip_str):
        return ''
    try:
        response = _geoip_reader.country(ip_str)
        return response.country.iso_code or ''
    except Exception:
        return ''


# Virtual adapter MAC prefixes to ignore in ARP checks
VIRTUAL_MAC_PREFIXES = [
    '00-50-56',  # VMware
    '00-0c-29',  # VMware
    '08-00-27',  # VirtualBox
    '00-15-5d',  # Hyper-V
    '02-42-',    # Docker
    '00-1c-42',  # Parallels
]


class NetworkAnalysisConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope.get("user")
        await self.accept()
        self.is_monitoring = False
        self.monitor_task = None
        self.feed_update_task = None
        
        # Beaconing detection state
        self.connection_history = defaultdict(list)  # IP -> [timestamps]
        self.seen_remote_ips = set()
        self.new_ips_since_start = set()
        self.monitoring_start_time = None
        
        # ARP check throttle
        self.last_arp_check = 0
        self.ARP_CHECK_INTERVAL = 30  # seconds
        
        # Initialize threat intelligence
        load_threat_feed()
        
        # Initialize GeoIP
        _init_geoip()
        
        # Initialize Groq if available
        self.llm = None
        if getattr(settings, 'GROQ_API_KEY', None):
            try:
                self.llm = ChatGroq(
                    model_name="llama-3.1-8b-instant",
                    temperature=0.3,
                    groq_api_key=settings.GROQ_API_KEY
                )
                self.prompt_template = PromptTemplate.from_template(
                    """You are 'Ransomware Shield Live Network Analyst', an expert network security AI.
You are analyzing ENRICHED real-time network connection data from the host machine.
Each connection includes: process name, remote IP reputation status, port risk classification, 
country of origin, and a computed risk score (0-100).

ENRICHED Connection Data:
{network_data}

Network Statistics:
- Total active connections: {total_connections}
- New IPs since monitoring started: {new_ip_count}
- Connections flagged as risky (score >= 30): {risky_count}

Beaconing Analysis:
{beaconing_data}

Provide a CONCISE but actionable security analysis:
1. Flag any HIGH-RISK connections (score >= 50) with specific remediation steps
2. Note any suspicious patterns (beaconing, unusual processes, known-bad IPs)
3. If everything looks normal, state that clearly
Keep it brief (max 4-5 sentences) as this updates in real-time."""
                )
            except Exception as e:
                logger.error(f"Failed to init Groq in Consumer: {e}")

    async def disconnect(self, close_code):
        self.is_monitoring = False
        if self.monitor_task:
            self.monitor_task.cancel()
        if self.feed_update_task:
            self.feed_update_task.cancel()

    async def receive(self, text_data):
        data = json.loads(text_data)
        command = data.get('command')

        if command == 'start':
            if not self.is_monitoring:
                self.is_monitoring = True
                self.monitoring_start_time = time.time()
                self.seen_remote_ips.clear()
                self.new_ips_since_start.clear()
                self.connection_history.clear()
                
                self.monitor_task = asyncio.create_task(self.monitor_loop())
                
                # Schedule async threat feed update
                self.feed_update_task = asyncio.create_task(self._update_feed_periodically())
                
                await self.send(text_data=json.dumps({"status": "monitoring_started"}))
        
        elif command == 'stop':
            self.is_monitoring = False
            if self.monitor_task:
                self.monitor_task.cancel()
            if self.feed_update_task:
                self.feed_update_task.cancel()
            await self.send(text_data=json.dumps({"status": "monitoring_stopped"}))

    async def _update_feed_periodically(self):
        """Periodically update threat feeds in the background."""
        while self.is_monitoring:
            try:
                await download_threat_feed_async()
            except Exception as e:
                logger.debug(f"Threat feed update error: {e}")
            await asyncio.sleep(3600)  # Every hour

    async def monitor_loop(self):
        while self.is_monitoring:
            try:
                # Get enriched connections
                connections = await asyncio.to_thread(self.get_enriched_connections)
                
                # Track new IPs and connection history for beaconing
                for conn in connections:
                    remote_ip = conn.get('remote_ip', '')
                    if remote_ip and not is_private_ip(remote_ip):
                        if remote_ip not in self.seen_remote_ips:
                            self.new_ips_since_start.add(remote_ip)
                        self.seen_remote_ips.add(remote_ip)
                        self.connection_history[remote_ip].append(time.time())
                
                # Detect beaconing patterns
                beaconing_alerts = self.detect_beaconing()
                
                # Count risky connections
                risky_count = sum(1 for c in connections if c.get('risk_score', 0) >= 30)
                
                # Send enriched data to frontend
                await self.send(text_data=json.dumps({
                    'type': 'network_data',
                    'connections': connections,
                    'stats': {
                        'total': len(connections),
                        'new_ips': len(self.new_ips_since_start),
                        'risky_count': risky_count,
                    }
                }))

                # Send beaconing alerts if any
                if beaconing_alerts:
                    await self.send(text_data=json.dumps({
                        'type': 'beaconing_alert',
                        'alerts': beaconing_alerts
                    }))

                # Check for ARP spoofing (throttled to every 30s)
                current_time = time.time()
                if current_time - self.last_arp_check >= self.ARP_CHECK_INTERVAL:
                    self.last_arp_check = current_time
                    mitm_alert = await self.check_arp_spoofing()
                    if mitm_alert:
                        await self.send(text_data=json.dumps({
                            'type': 'mitm_alert',
                            'alert': mitm_alert
                        }))
                
                # AI Analysis with enriched context
                if self.llm and len(connections) > 0:
                    analysis = await self.analyze_with_ai(
                        connections, beaconing_alerts, risky_count
                    )
                    if analysis:
                        await self.send(text_data=json.dumps({
                            'type': 'ai_analysis',
                            'analysis': analysis
                        }))
                
                await asyncio.sleep(5)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
                await self.send(text_data=json.dumps({'error': str(e)}))
                await asyncio.sleep(5)

    def get_enriched_connections(self):
        """
        Get active connections enriched with:
        - Process name and path
        - IP reputation
        - Port classification
        - GeoIP country
        - Risk score (0-100)
        """
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status not in ('ESTABLISHED', 'LISTEN'):
                    continue
                
                # Parse addresses
                local_ip = conn.laddr.ip if conn.laddr else None
                local_port = conn.laddr.port if conn.laddr else None
                remote_ip = conn.raddr.ip if conn.raddr else None
                remote_port = conn.raddr.port if conn.raddr else None
                
                # --- Process resolution ---
                process_name = 'unknown'
                process_path = ''
                process_user = ''
                try:
                    if conn.pid and conn.pid > 0:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                        try:
                            process_path = proc.exe()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            process_path = ''
                        try:
                            process_user = proc.username()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            process_user = ''
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                # --- IP reputation ---
                ip_reputation = 'unknown'
                is_known_bad = False
                if remote_ip:
                    if is_private_ip(remote_ip):
                        ip_reputation = 'private'
                    elif is_ip_malicious(remote_ip):
                        ip_reputation = 'malicious'
                        is_known_bad = True
                    else:
                        ip_reputation = 'clean'
                
                # --- Port classification ---
                port_class = 'unknown'
                port_desc = ''
                if remote_port:
                    port_class, port_desc = classify_port(remote_port)
                
                # --- GeoIP ---
                geo_country = ''
                if remote_ip and not is_private_ip(remote_ip):
                    geo_country = get_geo_country(remote_ip)
                
                # --- Risk scoring ---
                risk_score, risk_reasons = calculate_connection_risk({
                    'remote_ip': remote_ip or '',
                    'remote_port': remote_port or 0,
                    'process_name': process_name,
                    'is_ip_known_bad': is_known_bad,
                    'port_class': port_class,
                    'geo_country': geo_country,
                })
                
                connections.append({
                    'pid': conn.pid,
                    'process_name': process_name,
                    'process_path': process_path,
                    'process_user': process_user,
                    'family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                    'type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                    'local_address': f"{local_ip}:{local_port}" if local_ip else None,
                    'remote_address': f"{remote_ip}:{remote_port}" if remote_ip else None,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'status': conn.status,
                    'ip_reputation': ip_reputation,
                    'port_class': port_class,
                    'port_desc': port_desc,
                    'geo_country': geo_country,
                    'risk_score': risk_score,
                    'risk_reasons': risk_reasons,
                })
                
        except psutil.AccessDenied:
            logger.warning("Access denied reading network connections. Run as administrator for full visibility.")
        except Exception as e:
            logger.error(f"psutil error: {e}")
        
        # Sort by risk score (highest first), then limit to 30
        connections.sort(key=lambda c: c.get('risk_score', 0), reverse=True)
        return connections[:30]

    def detect_beaconing(self):
        """
        Detect periodic connection patterns (C2 beaconing).
        
        Beaconing = regular-interval callbacks to the same remote IP.
        If connection intervals have < 15% standard deviation, flag it.
        """
        alerts = []
        
        for ip, timestamps in self.connection_history.items():
            # Need at least 4 data points to detect a pattern
            if len(timestamps) < 4:
                continue
            
            # Only look at recent history (last 5 minutes)
            recent = [t for t in timestamps if time.time() - t < 300]
            if len(recent) < 4:
                continue
            
            # Calculate intervals between connections
            intervals = [recent[i+1] - recent[i] for i in range(len(recent) - 1)]
            
            if not intervals:
                continue
            
            mean_interval = sum(intervals) / len(intervals)
            
            if mean_interval <= 0:
                continue
            
            # Calculate coefficient of variation (stddev / mean)
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            stddev = variance ** 0.5
            cv = stddev / mean_interval
            
            # CV < 0.15 means very regular timing = probable beaconing
            if cv < 0.15 and mean_interval < 60:
                alerts.append({
                    'ip': ip,
                    'interval_seconds': round(mean_interval, 1),
                    'coefficient_of_variation': round(cv, 3),
                    'data_points': len(recent),
                    'severity': 'HIGH',
                    'description': f'Regular beaconing detected to {ip} every ~{mean_interval:.0f}s (CV={cv:.3f})'
                })
        
        return alerts

    async def check_arp_spoofing(self):
        """Detect ARP spoofing with virtual adapter filtering."""
        import subprocess
        import re
        
        try:
            result = await asyncio.to_thread(
                subprocess.run, ['arp', '-a'], capture_output=True, text=True, timeout=10
            )
            output = result.stdout
            
            arp_entries = re.findall(r'([0-9\.]+)\s+([0-9a-f\-]{17})\s+', output, re.IGNORECASE)
            
            mac_to_ips = {}
            for ip, mac in arp_entries:
                mac = mac.lower()
                
                # Ignore broadcast/multicast MACs
                if mac == 'ff-ff-ff-ff-ff-ff' or mac.startswith('01-00-5e'):
                    continue
                
                # Filter virtual adapter MACs
                is_virtual = any(mac.startswith(prefix.lower()) for prefix in VIRTUAL_MAC_PREFIXES)
                if is_virtual:
                    continue
                
                if mac not in mac_to_ips:
                    mac_to_ips[mac] = set()
                mac_to_ips[mac].add(ip)
            
            for mac, ips in mac_to_ips.items():
                if len(ips) > 1:
                    logger.warning(f"ARP SPOOFING DETECTED: MAC {mac} -> IPs: {ips}")
                    return {
                        'title': 'Man-in-the-Middle Attack Detected (ARP Spoofing)',
                        'description': f"A single physical device (MAC: {mac}) is claiming to be multiple IP addresses: {', '.join(ips)}. This strongly indicates an active interception attack.",
                        'severity': 'CRITICAL',
                        'mac': mac,
                        'ips': list(ips)
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking ARP table: {e}")
            return None

    async def analyze_with_ai(self, connections, beaconing_alerts, risky_count):
        """Send enriched network data to AI for analysis."""
        try:
            # Build a concise but informative summary for the AI
            conn_summary = []
            for c in connections[:15]:  # Limit to top 15 for prompt size
                entry = {
                    'process': c['process_name'],
                    'remote': c['remote_address'] or 'N/A',
                    'status': c['status'],
                    'reputation': c['ip_reputation'],
                    'port_class': c['port_class'],
                    'country': c['geo_country'] or 'Unknown',
                    'risk_score': c['risk_score'],
                    'risk_reasons': c['risk_reasons'],
                }
                conn_summary.append(entry)
            
            conn_str = json.dumps(conn_summary, indent=2)
            
            beaconing_str = "No beaconing patterns detected."
            if beaconing_alerts:
                beaconing_str = json.dumps(beaconing_alerts, indent=2)
            
            response = await asyncio.to_thread(
                self.llm.invoke,
                self.prompt_template.format(
                    network_data=conn_str,
                    total_connections=len(connections),
                    new_ip_count=len(self.new_ips_since_start),
                    risky_count=risky_count,
                    beaconing_data=beaconing_str,
                )
            )
            return response.content
        except Exception as e:
            logger.error(f"Groq API error in consumer: {e}")
            return "Analysis temporarily unavailable due to API error."
