import os
import time
import json
import logging
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

logger = logging.getLogger(__name__)

# Bait files designed to attract ransomware
DECOY_FILES = [
    'passwords.txt',
    'tax_returns_2025.pdf',
    'bitcoin_wallet.dat',
    'finance_q4.xlsx',
    'employee_records.csv',
    'bank_statements_2025.pdf',
]

# Realistic fake content for decoy files (ransomware skips trivially small files)
DECOY_CONTENT = {
    '.txt': "CONFIDENTIAL: Internal Access Credentials\n" + "=" * 50 + "\n" +
            "System: Production DB\nUsername: admin\nPassword: P@$$w0rd!2025\n" * 20,
    '.pdf': "%PDF-1.4 CONFIDENTIAL FINANCIAL DOCUMENT\n" + "X" * 5000,
    '.dat': "WALLET_DATA=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\nBALANCE=3.14159\n" * 100,
    '.xlsx': "PK" + "\x00" * 100 + "FINANCIAL_DATA" * 500,
    '.csv': "Employee ID,Name,SSN,Salary\n" + "\n".join(
        [f"{i},Employee_{i},XXX-XX-{1000+i},{50000+i*1000}" for i in range(200)]
    ),
}


class HoneyfileEventHandler(FileSystemEventHandler):
    """
    Industry-grade honeyfile event handler with:
    - Process identification (which process triggered the event)
    - Entropy monitoring (detect encryption in progress)
    - Alert rate limiting
    """
    def __init__(self, watch_dir):
        self.watch_dir = watch_dir
        self.decoy_paths = [os.path.join(watch_dir, f) for f in DECOY_FILES]
        self._original_entropy = {}
        self._last_alert_time = 0
        self._alert_cooldown = 10  # seconds
        
        # Store original entropy values for comparison
        self._compute_original_entropy()

    def _compute_original_entropy(self):
        """Pre-compute entropy of original decoy files for comparison."""
        import math
        from collections import Counter
        
        for path in self.decoy_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        data = f.read()
                    if data:
                        length = len(data)
                        counts = Counter(data)
                        entropy = -sum(
                            (c / length) * math.log2(c / length)
                            for c in counts.values() if c > 0
                        )
                        self._original_entropy[path] = entropy
                except Exception:
                    pass

    def _identify_process(self, file_path):
        """Try to identify which process modified the file."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'open_files']):
                try:
                    open_files = proc.info.get('open_files') or []
                    for f in open_files:
                        if f.path and os.path.normpath(f.path) == os.path.normpath(file_path):
                            return {
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'exe': proc.info.get('exe', 'unknown'),
                            }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.debug(f"Process identification error: {e}")
        
        return {'pid': None, 'name': 'unknown', 'exe': 'unknown'}

    def _check_entropy_change(self, file_path):
        """Check if a modified decoy file's entropy jumped (encryption indicator)."""
        import math
        from collections import Counter
        
        original = self._original_entropy.get(file_path, 4.5)
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            if data:
                length = len(data)
                counts = Counter(data)
                new_entropy = -sum(
                    (c / length) * math.log2(c / length)
                    for c in counts.values() if c > 0
                )
                
                entropy_jump = new_entropy - original
                is_encrypted = new_entropy > 7.0 and entropy_jump > 1.5
                
                return {
                    'original_entropy': round(original, 2),
                    'new_entropy': round(new_entropy, 2),
                    'entropy_jump': round(entropy_jump, 2),
                    'likely_encrypted': is_encrypted,
                }
        except Exception:
            pass
        
        return None

    def _trigger_alert(self, event_type, file_path):
        """Send a critical alert with process attribution and entropy analysis."""
        # Rate limiting
        current_time = time.time()
        if current_time - self._last_alert_time < self._alert_cooldown:
            return
        self._last_alert_time = current_time
        
        logger.warning(f"RANSOMWARE TRAP TRIPPED: {event_type} on {file_path}")
        
        # Identify the offending process
        process_info = self._identify_process(file_path)
        
        # Check entropy change (only for modifications, not deletions)
        entropy_info = None
        if event_type == 'modified' and os.path.exists(file_path):
            entropy_info = self._check_entropy_change(file_path)
        
        channel_layer = get_channel_layer()
        if channel_layer:
            alert_message = {
                'type': 'RANSOMWARE_HONEYPOT_ALERT',
                'severity': 'CRITICAL',
                'title': 'Ransomware Activity Detected!',
                'description': (
                    f"A critical decoy file ({os.path.basename(file_path)}) was just {event_type}. "
                    f"This is highly indicative of active ransomware encrypting your files."
                ),
                'filepath': file_path,
                'event': event_type,
                'process': process_info,
                'entropy_analysis': entropy_info,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            }
            
            async_to_sync(channel_layer.group_send)(
                'user_alerts_guest',
                {
                    'type': 'send_alert',
                    'message': alert_message
                }
            )

    def on_modified(self, event):
        if not event.is_directory and event.src_path in self.decoy_paths:
            self._trigger_alert('modified', event.src_path)

    def on_deleted(self, event):
        if not event.is_directory and event.src_path in self.decoy_paths:
            self._trigger_alert('deleted', event.src_path)

    def on_moved(self, event):
        if not event.is_directory and event.src_path in self.decoy_paths:
            self._trigger_alert('moved', event.src_path)


class HoneyfileMonitor:
    def __init__(self, watch_dir):
        self.watch_dir = watch_dir
        self.observer = Observer()
        self.event_handler = HoneyfileEventHandler(self.watch_dir)

    def setup_decoys(self):
        """Create decoy directory and realistic bait files."""
        if not os.path.exists(self.watch_dir):
            os.makedirs(self.watch_dir)
            logger.info(f"Created honeyfile directory at {self.watch_dir}")

        for filename in DECOY_FILES:
            filepath = os.path.join(self.watch_dir, filename)
            if not os.path.exists(filepath):
                ext = os.path.splitext(filename)[1]
                content = DECOY_CONTENT.get(ext, "CONFIDENTIAL INFORMATION. DO NOT DISTRIBUTE.\n" * 50)
                with open(filepath, 'w', errors='replace') as f:
                    f.write(content)
                logger.info(f"Created decoy file: {filepath}")

        # Attempt to hide the directory on Windows
        if os.name == 'nt':
            try:
                import ctypes
                FILE_ATTRIBUTE_HIDDEN = 0x02
                ctypes.windll.kernel32.SetFileAttributesW(self.watch_dir, FILE_ATTRIBUTE_HIDDEN)
            except Exception:
                pass

    def start(self):
        """Start the watchdog observer."""
        self.setup_decoys()
        self.observer.schedule(self.event_handler, self.watch_dir, recursive=False)
        self.observer.start()
        logger.info(f"Honeyfile monitor started on {self.watch_dir}")

    def stop(self):
        """Stop the watchdog observer."""
        self.observer.stop()
        self.observer.join()
        logger.info("Honeyfile monitor stopped.")
