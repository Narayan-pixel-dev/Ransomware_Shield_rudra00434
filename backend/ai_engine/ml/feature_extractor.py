import logging

logger = logging.getLogger(__name__)

# Feature names for reference and model consistency
FEATURE_NAMES = [
    'entropy',
    'num_sections',
    'num_suspicious_sections',
    'num_imports',
    'num_exports',
    'num_suspicious_imports',
    'has_debug_info',
    'has_tls_callbacks',
    'has_relocations',
    'resource_entropy',
    'timestamp_anomaly',
    'section_name_anomaly_count',
    'text_section_entropy',
    'max_section_raw_size_ratio',
    'has_overlay',
    'is_pe',
    'is_signed',
    'ransom_string_count',
    'file_size_kb',
]

class FeatureExtractor:
    """
    Extract 19 numerical features from enhanced static analysis results
    for the Random Forest / Gradient Boosting malware classifier.
    """
    
    def get_feature_names(self):
        return FEATURE_NAMES
    
    def extract(self, pe_data):
        """
        Extract features from the enhanced static analyzer output.
        Returns a 2D array suitable for scikit-learn prediction.
        """
        if not pe_data:
            return [[0.0] * len(FEATURE_NAMES)]

        try:
            features = [
                # 1. Overall file entropy (0.0 - 8.0)
                float(pe_data.get('entropy', 0.0)),
                
                # 2. Number of PE sections
                int(pe_data.get('num_sections', 0)),
                
                # 3. Number of suspicious (high-entropy / packed) sections
                len(pe_data.get('suspicious_sections', [])),
                
                # 4. Total imports count
                int(pe_data.get('num_imports', 0)),
                
                # 5. Total exports count  
                int(pe_data.get('num_exports', 0)),
                
                # 6. Number of suspicious API imports detected
                len(pe_data.get('suspicious_imports', [])),
                
                # 7. Has debug information (0/1) — malware rarely ships debug symbols
                1 if pe_data.get('has_debug_info', False) else 0,
                
                # 8. Has TLS callbacks (0/1) — anti-debugging technique
                1 if pe_data.get('has_tls_callbacks', False) else 0,
                
                # 9. Has relocation table (0/1)
                1 if pe_data.get('has_relocations', False) else 0,
                
                # 10. Resource section entropy
                float(pe_data.get('resources', {}).get('resource_entropy', 0.0)),
                
                # 11. Compiler timestamp anomaly (0/1)
                1 if pe_data.get('compiler_timestamp_anomaly', False) else 0,
                
                # 12. Non-standard section name count
                int(pe_data.get('section_name_anomaly_count', 0)),
                
                # 13. .text section entropy (encrypted code = high)
                float(pe_data.get('text_section_entropy', 0.0)),
                
                # 14. Max section virtual-to-raw size ratio
                float(pe_data.get('max_section_raw_size_ratio', 0.0)),
                
                # 15. Has overlay data (0/1) — data after PE structure
                1 if pe_data.get('has_overlay', False) else 0,
                
                # 16. Is valid PE file (0/1)
                1 if pe_data.get('is_pe', False) else 0,
                
                # 17. Has digital signature (0/1) — ransomware rarely signed
                1 if pe_data.get('signature', {}).get('has_signature', False) else 0,
                
                # 18. Number of ransomware-specific strings found
                len(pe_data.get('ransom_strings', [])),
                
                # 19. File size in KB (ransomware often < 10MB)
                round(pe_data.get('file_size_bytes', 0) / 1024.0, 2),
            ]
        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            return [[0.0] * len(FEATURE_NAMES)]
        
        # Scikit-Learn expects a 2D array for predictions
        return [features]
