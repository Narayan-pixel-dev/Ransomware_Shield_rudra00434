import React, { useState, useEffect } from 'react';
import FileDropZone from '../components/scanner/FileDropZone';
import ScanProgress from '../components/scanner/ScanProgress';
import { scannerService } from '../services/scannerService';
import { AlertTriangle, Download, ShieldCheck, Brain, Shield, Bug, FileKey, Hash } from 'lucide-react';
import MarkdownRenderer from '../components/common/MarkdownRenderer';

const Scanner = () => {
    const [job, setJob] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        let interval;
        if (job && (job.status === 'PENDING' || job.status === 'SCANNING')) {
            interval = setInterval(async () => {
                try {
                    const updatedJob = await scannerService.getJobStatus(job.id);
                    setJob(updatedJob);
                    if (updatedJob.status === 'COMPLETED' || updatedJob.status === 'FAILED') {
                        clearInterval(interval);
                    }
                } catch (err) {
                    console.error("Polling error", err);
                    clearInterval(interval);
                }
            }, 2000);
        }
        return () => clearInterval(interval);
    }, [job]);

    const handleUpload = async (file) => {
        setLoading(true);
        setError(null);
        try {
            const newJob = await scannerService.uploadFile(file);
            setJob(newJob);
        } catch (err) {
            setError(err.response?.data?.error || 'Upload failed');
        } finally {
            setLoading(false);
        }
    };

    const threatColor = (level) => {
        switch (level) {
            case 'CLEAN': return 'text-threat-clean border-threat-clean bg-threat-clean/10 drop-shadow-[0_0_15px_rgba(50,173,230,0.5)]';
            case 'LOW': return 'text-threat-low border-threat-low bg-threat-low/10 drop-shadow-[0_0_15px_rgba(48,209,88,0.5)]';
            case 'MEDIUM': return 'text-threat-medium border-threat-medium bg-threat-medium/10 drop-shadow-[0_0_15px_rgba(255,214,10,0.5)]';
            case 'HIGH': return 'text-threat-high border-threat-high bg-threat-high/10 drop-shadow-[0_0_15px_rgba(255,107,53,0.5)]';
            case 'CRITICAL': return 'text-threat-critical border-threat-critical bg-threat-critical/20 shadow-[0_0_30px_rgba(255,45,85,0.6)] animate-pulse';
            default: return 'text-gray-400 border-gray-700 bg-gray-800';
        }
    };

    const result = job?.result;
    const report = job?.report;
    const engineResults = result?.engine_results || {};

    return (
        <div className="max-w-5xl mx-auto p-6 pt-12 pb-24 relative overflow-hidden">
            <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-threat-clean/5 rounded-full mix-blend-screen filter blur-[120px] pointer-events-none"></div>

            <div className="text-center mb-10 relative z-10">
                <h1 className="text-4xl font-black mb-4 tracking-tight drop-shadow-md">Deep Malware <span className="text-transparent bg-clip-text bg-gradient-to-r from-threat-clean to-purple-500">Extraction</span></h1>
                <p className="text-gray-400 max-w-2xl mx-auto text-lg">
                    Submit suspicious files for immediate parallel analysis against YARA intelligence, BLAKE3 hashing, and ML-powered detection.
                </p>
            </div>

            {error && (
                <div className="glass-panel border-threat-critical/50 text-threat-critical p-4 rounded-xl mb-6 flex items-center gap-3 relative z-10 shadow-[0_0_15px_rgba(255,45,85,0.2)]">
                    <AlertTriangle className="animate-pulse" /> <span className="font-semibold">{error}</span>
                </div>
            )}

            {/* Upload Zone */}
            {(!job || job.status === 'FAILED') && (
                <div className="relative z-10">
                    <FileDropZone onFileUpload={handleUpload} isLoading={loading} />
                </div>
            )}

            {/* Progress View */}
            {job && (job.status === 'PENDING' || job.status === 'SCANNING') && (
                <div className="relative z-10">
                    <ScanProgress status={job.status} />
                </div>
            )}

            {/* Results View */}
            {job && job.status === 'COMPLETED' && result && (
                <div className="space-y-6 mt-8 animate-in fade-in slide-in-from-bottom-8 duration-700 relative z-10">
                    <div className="flex flex-col md:flex-row gap-6">
                        {/* Threat Badge Card */}
                        <div className={`flex-1 p-10 rounded-2xl border-2 flex flex-col items-center justify-center text-center transition-all ${threatColor(result.threat_level)}`}>
                            {result.threat_level === 'CLEAN' ? (
                                <ShieldCheck className="h-24 w-24 mb-6 drop-shadow-lg" />
                            ) : (
                                <AlertTriangle className="h-24 w-24 mb-6 drop-shadow-lg" />
                            )}
                            <h2 className="text-5xl font-black tracking-widest uppercase mb-3 drop-shadow-lg">{result.threat_level}</h2>
                            <p className="font-bold opacity-90 text-lg bg-black/20 px-4 py-1 rounded-full">{job.file_name}</p>

                            {/* Hash Display */}
                            <div className="mt-6 bg-black/40 border border-white/10 px-4 py-3 rounded-lg font-mono text-sm w-full text-left space-y-2">
                                <div className="flex items-center gap-2">
                                    <Hash size={14} className="text-indigo-400 shrink-0" />
                                    <span className="text-gray-500">BLAKE3:</span>
                                    <span className="text-gray-300 break-all">{job.file_hash}</span>
                                </div>
                                {job.sha256_hash && (
                                    <div className="flex items-center gap-2">
                                        <FileKey size={14} className="text-cyan-400 shrink-0" />
                                        <span className="text-gray-500">SHA-256:</span>
                                        <span className="text-gray-300 break-all text-xs">{job.sha256_hash}</span>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Quick Stats Card */}
                        <div className="flex-1 glass-panel p-8 rounded-2xl border border-white/10 shadow-2xl hover:border-white/20 transition-colors">
                            <h3 className="text-2xl font-bold mb-6 border-b border-gray-700/50 pb-3 text-white">Analysis Breakdown</h3>
                            <div className="space-y-4">
                                <div className="flex justify-between items-center group">
                                    <span className="text-gray-400 group-hover:text-gray-300 transition-colors">YARA Pattern Matches</span>
                                    <span className="font-black text-xl bg-dark-900 px-3 py-1 rounded-lg border border-gray-800">{engineResults?.yara?.matches?.length || 0}</span>
                                </div>
                                <div className="flex justify-between items-center group">
                                    <span className="text-gray-400 group-hover:text-gray-300 transition-colors">Suspicious PE Sections</span>
                                    <span className="font-black text-xl bg-dark-900 px-3 py-1 rounded-lg border border-gray-800">{engineResults?.static?.suspicious_sections?.length || 0}</span>
                                </div>
                                <div className="flex justify-between items-center group">
                                    <span className="text-gray-400 group-hover:text-gray-300 transition-colors">Suspicious API Imports</span>
                                    <span className="font-black text-xl bg-dark-900 px-3 py-1 rounded-lg border border-gray-800">{engineResults?.static?.suspicious_imports?.length || 0}</span>
                                </div>
                                <div className="flex justify-between items-center group">
                                    <span className="text-gray-400 group-hover:text-gray-300 transition-colors">File Entropy Level</span>
                                    <span className="font-black text-xl bg-dark-900 px-3 py-1 rounded-lg border border-gray-800">
                                        {engineResults?.static?.entropy?.toFixed(2) || 'N/A'}
                                    </span>
                                </div>
                                <div className="flex justify-between items-center group">
                                    <span className="text-gray-400 group-hover:text-gray-300 transition-colors">Ransomware Strings</span>
                                    <span className={`font-black text-xl px-3 py-1 rounded-lg border ${(engineResults?.static?.ransom_strings?.length || 0) > 0
                                        ? 'bg-threat-critical/20 text-threat-critical border-threat-critical/30'
                                        : 'bg-dark-900 border-gray-800'
                                        }`}>
                                        {engineResults?.static?.ransom_strings?.length || 0}
                                    </span>
                                </div>

                                {/* VirusTotal Results */}
                                {engineResults?.virustotal?.status === 'success' && (
                                    <div className="flex justify-between items-center pt-3 border-t border-gray-700/50 group">
                                        <span className="text-gray-300 font-medium flex items-center gap-2">
                                            <Shield size={16} className="text-blue-400" />
                                            VirusTotal Detections
                                        </span>
                                        <span className={`font-black text-xl px-3 py-1 rounded-lg border ${engineResults.virustotal.malicious > 0
                                            ? 'bg-threat-critical/20 text-threat-critical border-threat-critical/30'
                                            : 'bg-threat-clean/20 text-threat-clean border-threat-clean/30'
                                            }`}>
                                            {engineResults.virustotal.malicious} / {engineResults.virustotal.total}
                                        </span>
                                    </div>
                                )}

                                <div className="flex justify-between items-center pt-3 border-t border-gray-700/50">
                                    <span className="text-gray-300 font-medium flex items-center gap-2">
                                        <Bug size={16} className="text-purple-400" />
                                        ML Confidence
                                    </span>
                                    <span className="font-black text-2xl text-transparent bg-clip-text bg-gradient-to-r from-threat-medium to-threat-critical">
                                        {(result.ml_confidence_score * 100).toFixed(1)}%
                                    </span>
                                </div>

                                {/* Digital Signature */}
                                {engineResults?.static?.signature && (
                                    <div className="flex justify-between items-center group">
                                        <span className="text-gray-400">Digital Signature</span>
                                        <span className={`font-bold text-sm px-3 py-1 rounded-lg border ${engineResults.static.signature.has_signature
                                            ? 'bg-threat-clean/20 text-threat-clean border-threat-clean/30'
                                            : 'bg-threat-high/20 text-threat-high border-threat-high/30'
                                            }`}>
                                            {engineResults.static.signature.has_signature ? '✓ Signed' : '✗ Unsigned'}
                                        </span>
                                    </div>
                                )}
                            </div>

                            <div className="mt-8 flex flex-col sm:flex-row gap-4">
                                <button
                                    onClick={() => window.open(`http://localhost:8000/api/reports/download/${result.id}/`, '_blank')}
                                    className="flex-1 flex items-center justify-center gap-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 py-4 rounded-xl transition-all duration-300 font-bold text-white shadow-[0_0_15px_rgba(79,70,229,0.4)]"
                                >
                                    <Download size={20} /> Download PDF Report
                                </button>
                                <button
                                    onClick={() => setJob(null)}
                                    className="flex-1 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-threat-clean/50 py-4 rounded-xl transition-all duration-300 font-bold text-white shadow-lg hover:shadow-[0_0_15px_rgba(50,173,230,0.3)]"
                                >
                                    Scan Another File
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* AI Threat Explanation */}
                    {report?.llm_explanation && (
                        <div className="glass-panel p-8 rounded-2xl border border-indigo-500/20 shadow-2xl">
                            <div className="flex items-center gap-3 mb-6 border-b border-gray-700/50 pb-4">
                                <div className="bg-indigo-500/20 p-2 rounded-lg border border-indigo-500/30">
                                    <Brain size={24} className="text-indigo-400" />
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold text-white">AI Threat Analysis</h3>
                                    <p className="text-sm text-gray-400">Powered by Groq • LLaMA 3.1</p>
                                </div>
                            </div>
                            <div className="max-w-none">
                                <MarkdownRenderer content={report.llm_explanation} />
                            </div>
                        </div>
                    )}

                    {/* Ransomware Strings Found */}
                    {engineResults?.static?.ransom_strings?.length > 0 && (
                        <div className="glass-panel p-6 rounded-2xl border border-threat-critical/20 shadow-xl">
                            <h3 className="text-lg font-bold text-threat-critical mb-4 flex items-center gap-2">
                                <AlertTriangle size={20} />
                                Ransomware Indicators Detected
                            </h3>
                            <div className="flex flex-wrap gap-2">
                                {engineResults.static.ransom_strings.map((str, i) => (
                                    <span key={i} className="px-3 py-1.5 bg-threat-critical/10 text-threat-critical border border-threat-critical/30 rounded-lg text-sm font-mono">
                                        {str}
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Suspicious Imports */}
                    {engineResults?.static?.suspicious_imports?.length > 0 && (
                        <div className="glass-panel p-6 rounded-2xl border border-threat-high/20 shadow-xl">
                            <h3 className="text-lg font-bold text-threat-high mb-4 flex items-center gap-2">
                                <Bug size={20} />
                                Suspicious API Imports ({engineResults.static.suspicious_imports.length})
                            </h3>
                            <div className="flex flex-wrap gap-2">
                                {engineResults.static.suspicious_imports.map((api, i) => (
                                    <span key={i} className="px-3 py-1.5 bg-threat-high/10 text-threat-high border border-threat-high/30 rounded-lg text-sm font-mono">
                                        {api}
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )
            }
        </div >
    );
};

export default Scanner;
