import virustotal3.core
import logging
import time

logger = logging.getLogger(__name__)

# Simple in-memory cache to avoid redundant lookups
_vt_cache = {}
_CACHE_TTL = 86400  # 24 hours


def check_file_hash(sha256_hash, api_key=None):
    """
    Query VirusTotal for a file hash (SHA-256 only).
    
    Returns:
        dict with keys: status, malicious, suspicious, undetected, total, 
                        link, scan_date, or error
    """
    if not sha256_hash or len(sha256_hash) != 64:
        return {
            'status': 'skipped',
            'error': 'Invalid or missing SHA-256 hash.',
        }
    
    # Check cache first
    cached = _vt_cache.get(sha256_hash)
    if cached and (time.time() - cached.get('_cached_at', 0)) < _CACHE_TTL:
        return cached
    
    if not api_key:
        from django.conf import settings
        api_key = getattr(settings, 'VT_API_KEY', None)
    
    if not api_key:
        return {
            'status': 'skipped',
            'error': 'VirusTotal API key not configured.',
        }

    try:
        vt = virustotal3.core.Files(api_key)
        report = vt.info_file(sha256_hash)
        
        if not isinstance(report, dict):
            return {'status': 'error', 'error': 'Unexpected response format from VirusTotal.'}
        
        stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        
        result = {
            'status': 'success',
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0),
            'total': sum(stats.values()) if stats else 0,
            'link': f"https://www.virustotal.com/gui/file/{sha256_hash}",
            'scan_date': report.get('data', {}).get('attributes', {}).get('last_analysis_date', ''),
            '_cached_at': time.time(),
        }
        
        # Cache the result
        _vt_cache[sha256_hash] = result
        logger.info(f"VT lookup for {sha256_hash[:16]}...: {result['malicious']}/{result['total']} detections")
        
        return result
        
    except Exception as e:
        error_str = str(e)
        
        # Handle "not found" gracefully (hash not in VT database)
        if 'Not Found' in error_str or '404' in error_str:
            return {
                'status': 'not_found',
                'error': 'File hash not found in VirusTotal database.',
                'link': f"https://www.virustotal.com/gui/file/{sha256_hash}",
            }
        
        logger.error(f"VirusTotal API error: {e}")
        return {
            'status': 'error',
            'error': f'VirusTotal API error: {error_str}',
        }
