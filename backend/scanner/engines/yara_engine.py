import yara
import os
import threading
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

# Thread-safe compiled rules cache
_rules_lock = threading.Lock()
_compiled_rules = None
_compiled_rules_mtime = 0


def _get_max_mtime(rule_dir):
    """Get the most recent modification time across all .yar files."""
    max_mtime = 0
    for root, dirs, files in os.walk(rule_dir):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                fpath = os.path.join(root, file)
                mtime = os.path.getmtime(fpath)
                if mtime > max_mtime:
                    max_mtime = mtime
    return max_mtime


def load_yara_rules():
    """Thread-safe YARA rule loading with proper cache invalidation."""
    global _compiled_rules, _compiled_rules_mtime
    
    rule_dir = os.path.join(settings.BASE_DIR, 'yara_rules')
    
    if not os.path.exists(rule_dir):
        logger.warning(f"Yara rules directory not found: {rule_dir}")
        return None
    
    current_max_mtime = _get_max_mtime(rule_dir)
    
    # Return cached rules if still valid
    with _rules_lock:
        if _compiled_rules and current_max_mtime <= _compiled_rules_mtime:
            return _compiled_rules
    
    # Compile fresh rules
    filepaths = {}
    for root, dirs, files in os.walk(rule_dir):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                # Use relative path as namespace to avoid collisions
                namespace = os.path.relpath(os.path.join(root, file), rule_dir)
                namespace = namespace.replace(os.sep, '_').replace('.', '_')
                filepaths[namespace] = os.path.join(root, file)
    
    if not filepaths:
        logger.warning("No Yara rules found in directory.")
        return None
    
    try:
        with _rules_lock:
            _compiled_rules = yara.compile(filepaths=filepaths)
            _compiled_rules_mtime = current_max_mtime
            logger.info(f"Successfully compiled {len(filepaths)} YARA rule files.")
            return _compiled_rules
    except Exception as e:
        logger.error(f"Failed to compile YARA rules: {e}")
        return None


def analyze_yara(file_path):
    """
    Scan a file against compiled YARA rules with thread safety,
    timeout protection, and string extraction.
    """
    results = {
        'matches': [],
        'total_matches': 0,
        'error': None
    }
    try:
        rules = load_yara_rules()
        
        if not rules:
            results['error'] = 'No compiled YARA rules available.'
            return results
        
        # Timeout prevents ReDoS (Regex Denial of Service)
        matches = rules.match(file_path, timeout=30)
        results['total_matches'] = len(matches)
        
        for match in matches:
            match_data = {
                'rule': match.rule,
                'tags': match.tags,
                'meta': match.meta,
                'namespace': match.namespace,
                'strings': [],
            }
            
            # Extract first 5 matched strings (truncated to 64 bytes each)
            if hasattr(match, 'strings') and match.strings:
                for string_match in match.strings[:5]:
                    try:
                        if hasattr(string_match, 'instances'):
                            # yara-python >= 4.3
                            for instance in string_match.instances[:2]:
                                match_data['strings'].append({
                                    'identifier': string_match.identifier,
                                    'offset': instance.offset,
                                    'data': instance.matched_data[:64].hex(),
                                })
                        else:
                            # Legacy format: (offset, identifier, data)
                            match_data['strings'].append({
                                'identifier': string_match[1],
                                'offset': string_match[0],
                                'data': string_match[2][:64].hex() if isinstance(string_match[2], bytes) else str(string_match[2])[:64],
                            })
                    except Exception:
                        pass  # Skip malformed string matches
            
            results['matches'].append(match_data)
        
    except yara.TimeoutError:
        results['error'] = 'YARA scan timed out (possible complex rule / large file).'
    except Exception as e:
        results['error'] = str(e)
    
    return results
