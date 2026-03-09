from celery import shared_task
from .models import ScanJob, ScanResult, ThreatReport
from .engines.static_analyzer import analyze_pe
from .engines.yara_engine import analyze_yara
from .engines.vt_client import check_file_hash
import os
import logging
import magic  # python-magic for file type detection

logger = logging.getLogger(__name__)

# Add the parent directory to sys.path for AI engine imports
import sys
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.append(backend_dir)

from ai_engine.ml.classifier import MalwareClassifier
from ai_engine.llm.threat_explainer import generate_explanation


def detect_file_type(file_path):
    """Detect file type using magic bytes (not extension)."""
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        return file_type
    except Exception:
        # Fallback: check magic bytes manually
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
            if header[:2] == b'MZ':
                return 'application/x-dosexec'
            elif header[:4] == b'\x7fELF':
                return 'application/x-elf'
            elif header[:4] == b'%PDF':
                return 'application/pdf'
            elif header[:2] in (b'PK', ):
                return 'application/zip'
        except Exception:
            pass
    return 'application/octet-stream'


@shared_task(bind=True, time_limit=300, soft_time_limit=240)
def run_full_scan(self, job_id, file_path):
    """
    Industry-grade multi-engine file scan with:
    - File type detection
    - BLAKE3 + SHA-256 hashing
    - Static PE analysis (19 features)
    - YARA rule matching
    - VirusTotal hash lookup (SHA-256)
    - ML classification (ensemble model)
    - Normalized threat scoring with MEDIUM level
    - AI explanation generation
    """
    try:
        job = ScanJob.objects.get(id=job_id)
        job.status = 'SCANNING'
        job.save()

        result = ScanResult.objects.create(job=job)
        engine_results = {}

        # 0. File type detection
        file_type = detect_file_type(file_path)
        engine_results['file_type'] = file_type
        logger.info(f"Scanning {job.file_name} (type: {file_type})")

        # 1. Static Analysis (PE analysis, multi-hash, ransomware strings)
        static_res = analyze_pe(file_path)
        engine_results['static'] = static_res

        # 2. YARA Matching
        yara_res = analyze_yara(file_path)
        engine_results['yara'] = yara_res

        # 3. VirusTotal Check — ALWAYS use SHA-256
        sha256_hash = static_res.get('hashes', {}).get('sha256', '')
        if not sha256_hash:
            # Fallback: compute SHA-256 directly
            import hashlib
            with open(file_path, 'rb') as f:
                sha256_hash = hashlib.sha256(f.read()).hexdigest()
        
        vt_res = check_file_hash(sha256_hash)
        engine_results['virustotal'] = vt_res

        # 4. Machine Learning Classification
        ml_classifier = MalwareClassifier()
        ml_res = ml_classifier.predict(static_res)
        engine_results['ml_classifier'] = ml_res

        # ═══════════════════════════════════════════════
        # NORMALIZED THREAT SCORING
        # ═══════════════════════════════════════════════
        # Each signal is normalized to 0.0-1.0, then weighted
        
        # VirusTotal score (0-1 based on detection ratio)
        vt_malicious = vt_res.get('malicious', 0) if isinstance(vt_res, dict) else 0
        vt_total = vt_res.get('total', 1) if isinstance(vt_res, dict) else 1
        vt_score = min(vt_malicious / max(vt_total, 1), 1.0)
        
        # YARA score (0-1, capped at 3 matches = 1.0)
        yara_matches_count = len(yara_res.get('matches', []))
        yara_score = min(yara_matches_count / 3.0, 1.0)
        
        # Static analysis score (combined signals)
        suspicious_sections = len(static_res.get('suspicious_sections', []))
        suspicious_imports = len(static_res.get('suspicious_imports', []))
        ransom_strings = len(static_res.get('ransom_strings', []))
        timestamp_anomaly = 1 if static_res.get('compiler_timestamp_anomaly', False) else 0
        is_signed = 1 if static_res.get('signature', {}).get('has_signature', False) else 0
        
        static_score = min((
            (suspicious_sections * 0.15) +
            (min(suspicious_imports, 10) * 0.05) +
            (ransom_strings * 0.10) +
            (timestamp_anomaly * 0.10) +
            (0.0 if is_signed else 0.05)  # Unsigned = slight increase
        ), 1.0)
        
        # ML score
        ml_confidence = ml_res.get('confidence', 0.0)
        ml_is_malware = ml_res.get('is_malware', False)
        ml_score = ml_confidence if ml_is_malware else (1.0 - ml_confidence) * 0.3
        
        # Weighted combination
        detection_score = (
            vt_score * 0.30 +       # VirusTotal: 30% weight
            yara_score * 0.25 +      # YARA: 25% weight
            static_score * 0.20 +    # Static analysis: 20% weight
            ml_score * 0.25          # ML classifier: 25% weight
        )
        
        # Ransomware string bonus (strong independent signal)
        if ransom_strings >= 3:
            detection_score = min(detection_score + 0.20, 1.0)
        
        # Determine threat level with all 5 levels
        if detection_score >= 0.70:
            threat_level = 'CRITICAL'
        elif detection_score >= 0.50:
            threat_level = 'HIGH'
        elif detection_score >= 0.30:
            threat_level = 'MEDIUM'
        elif detection_score >= 0.10:
            threat_level = 'LOW'
        else:
            threat_level = 'CLEAN'

        # Update Result
        result.threat_level = threat_level
        result.detection_count = round(detection_score * 100)  # Store as percentage
        result.ml_confidence_score = ml_res.get('confidence', 0.0)
        result.engine_results = engine_results
        result.save()

        # Job Completed
        job.status = 'COMPLETED'
        job.save()
        
        logger.info(
            f"Scan complete: {job.file_name} -> {threat_level} "
            f"(score: {detection_score:.2f}, VT: {vt_score:.2f}, "
            f"YARA: {yara_score:.2f}, Static: {static_score:.2f}, ML: {ml_score:.2f})"
        )

        # Trigger AI Explanation (async)
        generate_threat_report.delay(result.id)

    except Exception as e:
        if 'job' in locals():
            job.status = 'FAILED'
            job.save()
        logger.error(f"Error in scan task: {e}", exc_info=True)

    finally:
        # Secure file handling: wipe and delete the file after analysis
        if file_path and os.path.exists(file_path):
            try:
                # Overwrite with zeros before deletion (basic secure delete)
                file_size = os.path.getsize(file_path)
                with open(file_path, 'wb') as f:
                    f.write(b'\x00' * min(file_size, 104857600))  # Cap at 100MB
                os.remove(file_path)
                logger.info(f"Securely deleted analyzed file: {file_path}")
            except Exception as e:
                logger.warning(f"Failed to securely delete {file_path}: {e}")
                try:
                    os.remove(file_path)
                except Exception:
                    pass


@shared_task
def generate_threat_report(result_id):
    """Celery task to generate the LLM explanation asynchronously."""
    try:
        result = ScanResult.objects.get(id=result_id)
        explanation = generate_explanation(result.threat_level, result.engine_results)
        
        ThreatReport.objects.create(
            result=result,
            llm_explanation=explanation
        )
        logger.info(f"AI threat report generated for result {result_id}")
    except Exception as e:
        logger.error(f"Failed to generate AI report: {e}")
