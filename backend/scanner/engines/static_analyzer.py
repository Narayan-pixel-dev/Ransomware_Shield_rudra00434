import pefile
import math
import hashlib
import time
import os
import struct
import logging
from collections import Counter

logger = logging.getLogger(__name__)

# Try to import blake3, fallback gracefully
try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False
    logger.warning("blake3 not installed. Using SHA-256 as primary hash.")

# ═══════════════════════════════════════════════════════════════════════════════
# SUSPICIOUS API LIST — Industry-grade ransomware-focused import detection
# ═══════════════════════════════════════════════════════════════════════════════
SUSPICIOUS_APIS = {
    # --- Cryptographic operations (ransomware encryption) ---
    b'CryptEncrypt', b'CryptDecrypt', b'CryptAcquireContextW', b'CryptAcquireContextA',
    b'CryptGenKey', b'CryptDeriveKey', b'CryptImportKey', b'CryptExportKey',
    b'CryptCreateHash', b'CryptHashData', b'CryptDestroyKey',
    b'BCryptEncrypt', b'BCryptDecrypt', b'BCryptGenerateSymmetricKey',
    b'BCryptOpenAlgorithmProvider', b'BCryptGenRandom',

    # --- File enumeration (ransomware file discovery) ---
    b'FindFirstFileW', b'FindFirstFileA', b'FindNextFileW', b'FindNextFileA',
    b'FindFirstFileExW', b'GetLogicalDriveStringsW', b'GetLogicalDriveStringsA',
    b'GetDriveTypeW', b'GetDriveTypeA',

    # --- Process injection / manipulation ---
    b'VirtualAlloc', b'VirtualAllocEx', b'VirtualProtectEx',
    b'CreateRemoteThread', b'WriteProcessMemory', b'NtWriteVirtualMemory',
    b'OpenProcess', b'CreateProcessW', b'CreateProcessA',
    b'QueueUserAPC', b'NtQueueApcThread',

    # --- Anti-debugging / anti-analysis ---
    b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent',
    b'NtQueryInformationProcess', b'NtSetInformationThread',
    b'GetTickCount', b'QueryPerformanceCounter',
    b'OutputDebugStringA',

    # --- Lateral movement ---
    b'WNetAddConnection2W', b'WNetOpenEnumW', b'WNetEnumResourceW',
    b'NetShareEnum', b'NetServerEnum',

    # --- Shadow copy deletion (ransomware recovery prevention) ---
    b'ShellExecuteW', b'ShellExecuteA', b'ShellExecuteExW',
    b'WinExec', b'CreateProcessW',

    # --- Privilege escalation ---
    b'AdjustTokenPrivileges', b'LookupPrivilegeValueW',
    b'OpenProcessToken', b'ImpersonateLoggedOnUser',

    # --- Registry manipulation ---
    b'RegSetValueExW', b'RegCreateKeyExW', b'RegDeleteValueW',

    # --- Network (C2 communication) ---
    b'InternetOpenA', b'InternetOpenW', b'InternetConnectA',
    b'HttpOpenRequestA', b'HttpSendRequestA',
    b'URLDownloadToFileA', b'URLDownloadToFileW',

    # --- System manipulation ---
    b'Wow64DisableWow64FsRedirection',
    b'SetFileAttributesW',
    b'NtQuerySystemInformation',
}

KNOWN_PACKERS = {
    b'.upx', b'.aspack', b'.enigma', b'.themida', b'.vmp', b'.kdb',
    b'.mpress', b'.poly', b'pecompact', b'.nsp', b'.ndata',
    b'.petite', b'.yoda', b'.fsg', b'.mew',
}

# Ransomware-specific strings to search for in binary content
RANSOM_STRINGS = [
    b'bitcoin', b'btc', b'wallet', b'.onion', b'tor browser',
    b'decrypt', b'encrypt', b'ransom', b'locked',
    b'AES-256', b'AES256', b'RSA-2048', b'RSA2048', b'RSA-4096',
    b'YOUR FILES', b'your files', b'your documents',
    b'recover your', b'restore your', b'pay the', b'payment',
    b'send bitcoin', b'send btc', b'cryptocurrency',
    b'.onion/', b'readme.txt', b'README.txt', b'HOW_TO_DECRYPT',
    b'HOW_TO_RECOVER', b'DECRYPT_INSTRUCTIONS', b'RECOVERY_KEY',
    b'personal key', b'unique key', b'decryption key',
    b'vssadmin delete shadows', b'wmic shadowcopy delete',
    b'bcdedit /set', b'wbadmin delete catalog',
]


def calculate_entropy(data):
    """O(n) entropy calculation using Counter — 10-50× faster than naive approach."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)


def compute_hashes(file_path):
    """Compute BLAKE3 (primary), SHA-256, SHA-1, and MD5 hashes in a single pass."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    b3 = blake3.blake3() if HAS_BLAKE3 else None
    
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(65536)  # 64KB chunks for efficient I/O
            if not chunk:
                break
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            if b3:
                b3.update(chunk)
    
    return {
        'blake3': b3.hexdigest() if b3 else None,
        'sha256': sha256.hexdigest(),
        'sha1': sha1.hexdigest(),
        'md5': md5.hexdigest(),
    }


def detect_ransom_strings(data):
    """Scan binary content for ransomware-specific strings."""
    found = []
    data_lower = data.lower()
    for pattern in RANSOM_STRINGS:
        if pattern.lower() in data_lower:
            found.append(pattern.decode('utf-8', errors='ignore'))
    return found


def check_digital_signature(pe):
    """Check if PE has an Authenticode digital signature."""
    try:
        # Security directory is at index 4 in the optional header data directories
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        has_signature = security_dir.VirtualAddress != 0 and security_dir.Size != 0
        return {
            'has_signature': has_signature,
            'signature_size': security_dir.Size if has_signature else 0,
        }
    except (IndexError, AttributeError):
        return {'has_signature': False, 'signature_size': 0}


def analyze_resources(pe):
    """Analyze PE resources for suspicious embedded content."""
    resource_info = {
        'total_resources': 0,
        'resource_entropy': 0.0,
        'has_suspicious_resources': False,
    }
    
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return resource_info
    
    total_size = 0
    resource_data = b''
    
    try:
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            resource_info['total_resources'] += 1
                            data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                             resource_lang.data.struct.Size)
                            total_size += len(data)
                            # Sample up to 1MB of resource data for entropy
                            if len(resource_data) < 1048576:
                                resource_data += data
        
        if resource_data:
            resource_info['resource_entropy'] = calculate_entropy(resource_data)
            # Resources with very high entropy may contain encrypted/packed payloads
            if resource_info['resource_entropy'] > 7.2:
                resource_info['has_suspicious_resources'] = True
                
    except Exception as e:
        logger.debug(f"Resource analysis error: {e}")
    
    return resource_info


def analyze_pe(file_path):
    """
    Industry-grade PE static analysis with multi-hash, ransomware detection,
    signature verification, and expanded feature extraction.
    """
    results = {
        'is_pe': False,
        'file_size_bytes': 0,
        'entropy': 0.0,
        'hashes': {},
        'imphash': None,
        'suspicious_sections': [],
        'suspicious_imports': [],
        'compiler_timestamp_anomaly': False,
        'ransom_strings': [],
        'signature': {'has_signature': False, 'signature_size': 0},
        'resources': {'total_resources': 0, 'resource_entropy': 0.0, 'has_suspicious_resources': False},
        'section_details': [],
        'num_sections': 0,
        'num_imports': 0,
        'num_exports': 0,
        'has_debug_info': False,
        'has_tls_callbacks': False,
        'has_relocations': False,
        'has_overlay': False,
        'overlay_entropy': 0.0,
        'text_section_entropy': 0.0,
        'max_section_raw_size_ratio': 0.0,
        'section_name_anomaly_count': 0,
        'error': None
    }

    try:
        # --- File-level analysis ---
        file_size = os.path.getsize(file_path)
        results['file_size_bytes'] = file_size

        with open(file_path, 'rb') as f:
            data = f.read()

        results['entropy'] = calculate_entropy(data)
        results['hashes'] = compute_hashes(file_path)
        results['ransom_strings'] = detect_ransom_strings(data)

        # --- PE-specific analysis ---
        pe = pefile.PE(file_path)
        results['is_pe'] = True
        results['imphash'] = pe.get_imphash()
        results['num_sections'] = pe.FILE_HEADER.NumberOfSections

        # Standard PE section names
        STANDARD_SECTION_NAMES = {
            '.text', '.rdata', '.data', '.rsrc', '.reloc', '.idata',
            '.edata', '.pdata', '.tls', '.bss', '.crt', '.sxdata',
            '.debug', '.didat', '.CRT',
        }

        # --- Section analysis ---
        for section in pe.sections:
            sec_entropy = section.get_entropy()
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            lower_name = section.Name.lower().strip(b'\x00')

            # Section detail record for feature extraction
            sec_detail = {
                'name': name,
                'entropy': round(sec_entropy, 4),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
            }
            results['section_details'].append(sec_detail)

            # Track .text section entropy
            if name.strip() in ('.text', '.code', 'CODE'):
                results['text_section_entropy'] = sec_entropy

            # Raw size to virtual size ratio (large ratios = suspicious)
            if section.SizeOfRawData > 0:
                ratio = section.Misc_VirtualSize / section.SizeOfRawData
                if ratio > results['max_section_raw_size_ratio']:
                    results['max_section_raw_size_ratio'] = round(ratio, 4)

            # Check for non-standard section names
            if name.strip() not in STANDARD_SECTION_NAMES:
                results['section_name_anomaly_count'] += 1

            # High entropy implies packing/encryption, or known packer signature
            is_suspicious_packer = any(packer in lower_name for packer in KNOWN_PACKERS)
            if sec_entropy > 7.0 or is_suspicious_packer:
                results['suspicious_sections'].append({
                    'name': name,
                    'entropy': round(sec_entropy, 4),
                    'reason': 'high_entropy' if sec_entropy > 7.0 else 'known_packer'
                })

        # --- Timestamp anomaly ---
        timestamp = pe.FILE_HEADER.TimeDateStamp
        current_time = int(time.time())
        if timestamp < 946684800 or timestamp > current_time:  # Before 2000 or future
            results['compiler_timestamp_anomaly'] = True

        # --- Import analysis ---
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            total_imports = 0
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    total_imports += 1
                    if imp.name:
                        for suspicious_api in SUSPICIOUS_APIS:
                            if suspicious_api.lower() in imp.name.lower():
                                api_name = imp.name.decode('utf-8', errors='ignore')
                                if api_name not in results['suspicious_imports']:
                                    results['suspicious_imports'].append(api_name)
            results['num_imports'] = total_imports

        # --- Export analysis ---
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            results['num_exports'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

        # --- Debug info check ---
        results['has_debug_info'] = hasattr(pe, 'DIRECTORY_ENTRY_DEBUG')

        # --- TLS callbacks (anti-debugging technique) ---
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
            tls = pe.DIRECTORY_ENTRY_TLS
            if tls.struct.AddressOfCallBacks:
                results['has_tls_callbacks'] = True

        # --- Relocation table ---
        results['has_relocations'] = hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC')

        # --- Overlay detection (data after PE structure) ---
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None:
            results['has_overlay'] = True
            overlay_data = data[overlay_offset:]
            if overlay_data:
                results['overlay_entropy'] = calculate_entropy(overlay_data[:1048576])  # First 1MB

        # --- Digital signature ---
        results['signature'] = check_digital_signature(pe)

        # --- Resource analysis ---
        results['resources'] = analyze_resources(pe)

        pe.close()

    except pefile.PEFormatError:
        results['error'] = 'Not a valid PE file.'
        # Still compute hashes even for non-PE files
        if not results['hashes']:
            try:
                results['hashes'] = compute_hashes(file_path)
                results['file_size_bytes'] = os.path.getsize(file_path)
                with open(file_path, 'rb') as f:
                    data = f.read()
                results['entropy'] = calculate_entropy(data)
                results['ransom_strings'] = detect_ransom_strings(data)
            except Exception:
                pass
    except Exception as e:
        results['error'] = str(e)

    return results
