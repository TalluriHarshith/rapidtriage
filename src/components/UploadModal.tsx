/**
 * RapidTriage - Evidence Upload Modal
 * Section 49: Forensic Drop Zone (EVIDENCE ACQUISITION / + ADD EVIDENCE)
 * Supports full Light and Dark themes.
 */

import React, { useState, useRef } from 'react';
import {
  Upload,
  FileText,
  AlertCircle,
  CheckCircle2,
  X,
  Download,
  Info,
  ArrowRight,
  Plus,
  FileCheck,
} from 'lucide-react';
import {
  validateAndParseDataset,
  convertRecordsToStandardizedEvents,
  SAMPLE_CSV_CONTENT,
} from '../services/forensicEngine';
import { StandardizedEvent, CSVUploadPreview } from '../types/forensics';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDatasetConfirmed: (events: StandardizedEvent[], fileName: string) => void;
}

export const UploadModal: React.FC<UploadModalProps> = ({
  isOpen,
  onClose,
  onDatasetConfirmed,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<CSVUploadPreview | null>(null);
  const [showFormatExample, setShowFormatExample] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileProcess = (file: File) => {
    setError(null);
    setPreview(null);

    const validExtensions = ['.csv', '.json'];
    const isExtensionValid = validExtensions.some((ext) =>
      file.name.toLowerCase().endsWith(ext)
    );

    if (!isExtensionValid) {
      setError('Unsupported file type. Please upload a .csv or .json dataset file.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (!content || !content.trim()) {
        setError('Uploaded file is empty.');
        return;
      }

      const result = validateAndParseDataset(content, file.name);
      if (!result.success) {
        setError(result.error || 'Failed to validate dataset format.');
        return;
      }

      setPreview({
        fileName: file.name,
        fileSizeBytes: file.size,
        totalRows: result.records.length,
        headers: result.headers,
        previewRows: result.records.slice(0, 5),
        rawContent: content,
        format: file.name.toLowerCase().endsWith('.json') ? 'json' : 'csv',
      });
    };

    reader.onerror = () => {
      setError('An error occurred while reading the file.');
    };

    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileProcess(e.dataTransfer.files[0]);
    }
  };

  const handleDownloadSampleCSV = () => {
    const blob = new Blob([SAMPLE_CSV_CONTENT], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'RapidTriage_Sample_Dataset.csv';
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleConfirmAnalysis = () => {
    if (!preview) return;
    const result = validateAndParseDataset(preview.rawContent, preview.fileName);
    if (!result.success) {
      setError(result.error || 'Validation failed during final parsing.');
      return;
    }

    const events = convertRecordsToStandardizedEvents(result.records);
    onDatasetConfirmed(events, preview.fileName);
    onClose();
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-150">
      <div className="rounded-lg max-w-2xl w-full shadow-2xl flex flex-col max-h-[90vh] overflow-hidden border transition-colors bg-white border-slate-300 text-slate-900 dark:bg-[#101520] dark:border-slate-800 dark:text-slate-100">
        {/* Subtle Top Yellow Evidence Strip */}
        <div className="h-1.5 w-full evidence-tape-diagonal"></div>

        {/* Header */}
        <div className="p-4 border-b flex items-center justify-between bg-slate-50 border-slate-200 dark:bg-[#0b0f17] dark:border-slate-800">
          <div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider font-semibold">
              EVIDENCE ACQUISITION
            </span>
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
              Ingest External Evidence Package
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 space-y-4 overflow-y-auto text-xs">
          {/* Section 49: Forensic Drop Zone */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragActive(true);
            }}
            onDragLeave={() => setDragActive(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-lg p-7 text-center cursor-pointer transition-colors ${
              dragActive
                ? 'border-yellow-500 bg-yellow-50/50 dark:bg-yellow-950/20'
                : 'border-slate-300 hover:border-yellow-500 bg-slate-50 dark:border-slate-700/80 dark:bg-[#0c1017] dark:hover:border-yellow-500'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,.json"
              className="hidden"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  handleFileProcess(e.target.files[0]);
                }
              }}
            />
            <div className="inline-flex items-center justify-center w-10 h-10 rounded-full bg-yellow-100 text-yellow-800 dark:bg-yellow-950/60 dark:text-yellow-400 mb-2">
              <Plus className="w-5 h-5 stroke-[2.5]" />
            </div>
            <div className="font-bold text-sm text-slate-800 dark:text-slate-200 uppercase tracking-wider font-mono">
              + ADD EVIDENCE
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 font-sans">
              Drop CSV or JSON evidence file here or click to browse
            </p>
            <div className="text-[11px] font-mono text-slate-400 dark:text-slate-500 mt-2">
              CSV • JSON (Mandatory column: timestamp)
            </div>
          </div>

          {/* Quick Helper Actions */}
          <div className="flex items-center justify-between pt-1 font-mono">
            <button
              type="button"
              onClick={handleDownloadSampleCSV}
              className="flex items-center gap-1.5 text-xs text-yellow-700 dark:text-yellow-400 hover:underline font-bold transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Sample CSV</span>
            </button>

            <button
              type="button"
              onClick={() => setShowFormatExample(!showFormatExample)}
              className="flex items-center gap-1 text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200 text-[11px] transition-colors"
            >
              <Info className="w-3.5 h-3.5" />
              <span>{showFormatExample ? 'Hide Format Example' : 'CSV Format Example'}</span>
            </button>
          </div>

          {/* Collapsible Format Example */}
          {showFormatExample && (
            <div className="border rounded p-3 text-[11px] font-mono space-y-1.5 animate-in fade-in bg-slate-100 border-slate-200 text-slate-800 dark:bg-[#090d14] dark:border-slate-800 dark:text-slate-300">
              <div className="text-slate-500 font-semibold uppercase">Expected CSV Schema:</div>
              <div className="text-[10px] break-all text-slate-700 dark:text-slate-400">
                timestamp, artifact, event_type, process, path, user, file, url, local_address, remote_address, device, description
              </div>
              <div className="text-slate-500 text-[10px] pt-1">
                * Only <strong>timestamp</strong> is strictly mandatory.
              </div>
            </div>
          )}

          {/* Validation Error Message */}
          {error && (
            <div className="p-3.5 rounded-md border text-xs space-y-1 bg-red-50 text-red-900 border-red-300 dark:bg-red-950/40 dark:text-red-200 dark:border-red-800">
              <div className="flex items-center gap-2 font-bold text-red-800 dark:text-red-300 font-mono">
                <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0" />
                <span>UNABLE TO ANALYZE DATASET</span>
              </div>
              <p className="text-[11px] pl-6 leading-relaxed font-sans">{error}</p>
            </div>
          )}

          {/* Section 49: Validated Evidence Banner & Table Preview */}
          {preview && (
            <div className="space-y-3 pt-2 border-t border-slate-200 dark:border-slate-800">
              {/* Evidence Status Banner */}
              <div className="flex items-center justify-between p-3 rounded border font-mono bg-emerald-50 border-emerald-300 text-emerald-950 dark:bg-emerald-950/30 dark:border-emerald-800 dark:text-emerald-200">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                  <span className="font-bold">✓ {preview.fileName}</span>
                  <span className="text-slate-500 font-normal">
                    · {formatFileSize(preview.fileSizeBytes)} · SHA-256 pending
                  </span>
                </div>
                <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-emerald-200/50 dark:bg-emerald-900/60">
                  [REVIEW DATA]
                </span>
              </div>

              {/* Preview Table */}
              <div className="border rounded-md overflow-x-auto bg-white border-slate-200 dark:bg-[#0a0e16] dark:border-slate-800">
                <table className="w-full text-left text-[11px] font-mono">
                  <thead className="border-b bg-slate-100 text-slate-600 border-slate-200 dark:bg-[#121824] dark:text-slate-400 dark:border-slate-800">
                    <tr>
                      <th className="py-2 px-2.5">Timestamp</th>
                      <th className="py-2 px-2.5">Event Type</th>
                      <th className="py-2 px-2.5">Process</th>
                      <th className="py-2 px-2.5">Path</th>
                      <th className="py-2 px-2.5">User</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-slate-800 dark:text-slate-300">
                    {preview.previewRows.map((row, idx) => {
                      const lower: Record<string, string> = {};
                      Object.entries(row).forEach(([k, v]) => {
                        lower[k.toLowerCase()] = v;
                      });
                      return (
                        <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                          <td className="py-1.5 px-2.5 whitespace-nowrap font-medium text-slate-900 dark:text-slate-100">
                            {lower['timestamp'] || lower['time'] || '-'}
                          </td>
                          <td className="py-1.5 px-2.5 whitespace-nowrap">
                            {lower['event_type'] || lower['event'] || '-'}
                          </td>
                          <td className="py-1.5 px-2.5 whitespace-nowrap">
                            {lower['process'] || lower['proc'] || '-'}
                          </td>
                          <td className="py-1.5 px-2.5 max-w-xs truncate text-slate-500 dark:text-slate-400" title={lower['path'] || ''}>
                            {lower['path'] || lower['filepath'] || '-'}
                          </td>
                          <td className="py-1.5 px-2.5 whitespace-nowrap text-slate-500">
                            {lower['user'] || lower['username'] || '-'}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <p className="text-[11px] text-slate-500 font-sans">
                Click <strong>Analyze Evidence</strong> below to parse records, normalize timestamps, and correlate into the incident timeline.
              </p>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t flex items-center justify-end gap-3 bg-slate-50 border-slate-200 dark:bg-[#0b0f17] dark:border-slate-800">
          <button
            type="button"
            onClick={onClose}
            className="px-3.5 py-1.5 text-xs text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200 transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleConfirmAnalysis}
            disabled={!preview}
            className="flex items-center gap-2 px-4 py-2 font-bold text-xs rounded transition-colors disabled:opacity-40 disabled:cursor-not-allowed shadow-xs bg-yellow-500 hover:bg-yellow-400 text-slate-950 cursor-pointer"
          >
            <span>Analyze Evidence</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
