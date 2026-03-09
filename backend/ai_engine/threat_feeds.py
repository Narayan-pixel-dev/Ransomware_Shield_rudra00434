"""
Threat Intelligence Feed Manager

Downloads, caches, and provides lookup against known-malicious IP lists
from open threat intelligence sources.
"""
import os
import time
import logging
import ipaddress
from pathlib import Path

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# KNOWN MALICIOUS PORTS (C2, Mining, Exploit)
# ═══════════════════════════════════════════════════════════════════════════════
C2_PORTS = {
    4444, 4445, 5555, 6666, 8443, 8888, 9001, 9002, 1234, 31337,
    4443, 8080, 8081, 1337, 3389,  # RDP when unexpected
    6667, 6668, 6669,  # IRC (commonly used by botnets)
    1723,  # PPTP VPN (tunneling)
}

MINING_PORTS = {
    3333, 5555, 7777, 8332, 8333,  # Bitcoin
    14433, 14444, 45560,  # Monero
    9999, 8899,  # Various altcoins
}

NORMAL_PORTS = {
    80, 443, 53, 22, 21, 25, 587, 993, 995, 110, 143, 3306, 5432,
    27017, 6379, 11211, 8000, 8080, 5173, 3000, 8443, 9200,
}

# Well-known safe IP ranges
SAFE_IP_RANGES = [
    '127.0.0.0/8',      # Loopback
    '10.0.0.0/8',       # Private
    '172.16.0.0/12',    # Private
    '192.168.0.0/16',   # Private
    '169.254.0.0/16',   # Link-local
    '::1/128',          # IPv6 loopback
    'fe80::/10',        # IPv6 link-local
]

_safe_networks = [ipaddress.ip_network(r) for r in SAFE_IP_RANGES]

# In-memory cache of known-bad IPs
_malicious_ips = set()
_feed_last_updated = 0
_FEED_CACHE_TTL = 86400  # 24 hours

# Local hardcoded threat list (curated from public threat intel)
# These are well-known C2 / ransomware infrastructure IPs 
# In production, this would be loaded from a constantly-updated feed
HARDCODED_BAD_IPS = {
    # Example known botnets/C2 (illustrative — update with real intel)
    '185.220.100.240', '185.220.100.241', '185.220.100.242',
    '45.154.98.0', '45.154.98.1',
    '194.26.192.0', '194.26.192.1',
    '23.129.64.0',  # Known tor exit node ranges
}


def is_private_ip(ip_str):
    """Check if an IP is in a private/reserved range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _safe_networks)
    except ValueError:
        return False


def load_threat_feed():
    """
    Load threat intelligence feeds into memory.
    Uses a combination of hardcoded lists and (optionally) downloaded feeds.
    """
    global _malicious_ips, _feed_last_updated
    
    current_time = time.time()
    
    # Only refresh if cache has expired
    if _malicious_ips and (current_time - _feed_last_updated) < _FEED_CACHE_TTL:
        return
    
    logger.info("Loading threat intelligence feeds...")
    new_ips = set(HARDCODED_BAD_IPS)
    
    # Try to load from a local file if it exists (can be populated by a cron job)
    feed_dir = Path(__file__).parent.parent / 'threat_feeds'
    feed_file = feed_dir / 'compromised_ips.txt'
    
    if feed_file.exists():
        try:
            with open(feed_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            ipaddress.ip_address(line)
                            new_ips.add(line)
                        except ValueError:
                            continue
            logger.info(f"Loaded {len(new_ips)} IPs from local threat feed.")
        except Exception as e:
            logger.error(f"Error loading local feed: {e}")
    
    # Try to download Emerging Threats feed (non-blocking, graceful failure)
    try:
        import aiohttp
        # Download is handled asynchronously in the consumer
        # Here we just load from the cache file
    except ImportError:
        pass
    
    _malicious_ips = new_ips
    _feed_last_updated = current_time
    logger.info(f"Threat feed loaded: {len(_malicious_ips)} known-bad IPs in memory.")


async def download_threat_feed_async():
    """
    Asynchronously download the Emerging Threats compromised IP list.
    Call this periodically from the WebSocket consumer.
    """
    global _malicious_ips, _feed_last_updated
    
    feed_url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    feed_dir = Path(__file__).parent.parent / 'threat_feeds'
    feed_file = feed_dir / 'compromised_ips.txt'
    
    try:
        import aiohttp
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.get(feed_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Parse and validate IPs
                    new_ips = set(HARDCODED_BAD_IPS)
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                ipaddress.ip_address(line)
                                new_ips.add(line)
                            except ValueError:
                                continue
                    
                    # Save to local cache file
                    os.makedirs(feed_dir, exist_ok=True)
                    with open(feed_file, 'w') as f:
                        f.write(f"# Downloaded from {feed_url}\n")
                        f.write(f"# Updated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        for ip in sorted(new_ips):
                            f.write(ip + '\n')
                    
                    _malicious_ips = new_ips
                    _feed_last_updated = time.time()
                    logger.info(f"Downloaded and cached {len(new_ips)} IPs from Emerging Threats.")
                    return True
    except ImportError:
        logger.warning("aiohttp not installed. Cannot download threat feeds.")
    except Exception as e:
        logger.error(f"Failed to download threat feed: {e}")
    
    return False


def is_ip_malicious(ip_str):
    """Check if an IP is in the known-malicious list."""
    # Lazy-load the feed on first call
    if not _malicious_ips:
        load_threat_feed()
    return ip_str in _malicious_ips


def classify_port(port):
    """
    Classify a port number by risk level.
    Returns: ('normal'|'suspicious'|'c2'|'mining'|'unknown', description)
    """
    if port is None:
        return ('unknown', 'No port')
    
    port = int(port)
    
    if port in C2_PORTS:
        return ('c2', f'Known C2/backdoor port {port}')
    elif port in MINING_PORTS:
        return ('mining', f'Known crypto mining port {port}')
    elif port in NORMAL_PORTS:
        return ('normal', f'Standard service port {port}')
    elif port > 49152:
        return ('ephemeral', f'Ephemeral port {port}')
    elif port > 1024:
        return ('unknown', f'Non-standard port {port}')
    else:
        return ('normal', f'Well-known port {port}')


def calculate_connection_risk(conn_info):
    """
    Calculate a 0-100 risk score for a network connection.
    
    Args:
        conn_info: dict with keys: remote_ip, remote_port, process_name, 
                   is_ip_known_bad, port_class, geo_country
    Returns:
        int: risk score 0-100
    """
    score = 0
    reasons = []
    
    remote_ip = conn_info.get('remote_ip', '')
    remote_port = conn_info.get('remote_port', 0)
    process_name = conn_info.get('process_name', 'unknown')
    port_class = conn_info.get('port_class', 'unknown')
    
    # Known malicious IP — very high risk
    if conn_info.get('is_ip_known_bad', False):
        score += 50
        reasons.append('Known malicious IP')
    
    # C2 port
    if port_class == 'c2':
        score += 30
        reasons.append(f'C2 port {remote_port}')
    elif port_class == 'mining':
        score += 25
        reasons.append(f'Mining port {remote_port}')
    elif port_class == 'unknown' and remote_port and int(remote_port) > 1024:
        score += 5
        reasons.append('Non-standard port')
    
    # Suspicious process names
    suspicious_processes = {
        'powershell', 'cmd', 'wscript', 'cscript', 'mshta',
        'regsvr32', 'rundll32', 'certutil', 'bitsadmin',
    }
    if process_name and process_name.lower().rstrip('.exe') in suspicious_processes:
        score += 20
        reasons.append(f'Suspicious process: {process_name}')
    
    # External IP (not private)
    if remote_ip and not is_private_ip(remote_ip):
        score += 5  # Slight bump for any external connection
    
    # Unusual countries (if GeoIP available)
    geo_country = conn_info.get('geo_country', '')
    high_risk_countries = {'RU', 'CN', 'KP', 'IR', 'BY', 'VE'}
    if geo_country and geo_country.upper() in high_risk_countries:
        score += 15
        reasons.append(f'High-risk country: {geo_country}')
    
    return min(score, 100), reasons
