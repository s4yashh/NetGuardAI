import { useRef, useState, type DragEvent } from "react";
import { CheckCircle2, CircleAlert, FileSpreadsheet, LoaderCircle, Play, ShieldCheck, Upload, X } from "lucide-react";
import Card from "./Card";
import { formatBytes } from "../format";
import type { ApiError } from "../api";

interface UploadPanelProps {
  file: File | null;
  loading: boolean;
  error: ApiError | null;
  modelReady: boolean;
  onFileChange: (file: File | null) => void;
  onAnalyze: () => void;
}

export default function UploadPanel({ file, loading, error, modelReady, onFileChange, onAnalyze }: UploadPanelProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  function handleDrop(event: DragEvent) {
    event.preventDefault();
    setDragging(false);
    const dropped = event.dataTransfer.files[0];
    if (dropped) onFileChange(dropped);
  }

  return (
    <Card
      title="Traffic analysis"
      subtitle="Upload flow records exported in CIC-IDS2017 / CICFlowMeter CSV format. Include an optional Label column to compare predictions with ground truth."
    >
      <div className="upload-grid">
        <div
          role="button"
          tabIndex={0}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => (event.key === "Enter" || event.key === " ") && inputRef.current?.click()}
          onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          className={`dropzone ${dragging ? "dropzone-active" : ""}`}
          aria-label="Choose or drop a CSV traffic file"
        >
          <div className="dropzone-icon"><Upload size={20} /></div>
          <div className="dropzone-main"><span>Choose a CSV file</span> or drop it here</div>
          <div className="dropzone-help">CSV only · Maximum size 100 MB</div>
          <input
            ref={inputRef}
            type="file"
            accept=".csv,text/csv"
            className="hidden"
            onChange={(event) => {
              onFileChange(event.target.files?.[0] ?? null);
              event.target.value = "";
            }}
          />
        </div>
        <div className="upload-side" aria-label="Upload requirements">
          <div className="upload-side-item"><ShieldCheck size={15} /> <span>Required feature columns are validated before inference.</span></div>
          <div className="upload-side-item"><CheckCircle2 size={15} /> <span>Extra columns are ignored; label data stays optional.</span></div>
          <div className="upload-side-item"><CheckCircle2 size={15} /> <span>Every batch receives a distribution-shift check.</span></div>
        </div>
      </div>

      {file && (
        <div className="selected-file">
          <div className="selected-file-info">
            <div className="file-icon"><FileSpreadsheet size={17} /></div>
            <div className="min-w-0">
              <div className="file-name">{file.name}</div>
              <div className="file-size">{formatBytes(file.size)} · ready for analysis</div>
            </div>
          </div>
          <div className="upload-actions">
            <button type="button" onClick={() => onFileChange(null)} disabled={loading} className="btn btn-quiet">
              <X size={15} /> Clear
            </button>
            <button type="button" onClick={onAnalyze} disabled={loading || !modelReady} title={modelReady ? undefined : "Train a model first"} className="btn btn-primary">
              {loading ? <LoaderCircle size={15} className="animate-spin" /> : <Play size={15} />}
              {loading ? "Analyzing traffic" : "Analyze traffic"}
            </button>
          </div>
        </div>
      )}

      {error && <ErrorBox error={error} />}
    </Card>
  );
}

function ErrorBox({ error }: { error: ApiError }) {
  const shown = error.columns.slice(0, 12);
  const hidden = error.columns.length - shown.length;
  return (
    <div role="alert" className="input-error">
      <p><CircleAlert size={16} className="shrink-0 text-malicious" />{error.message}</p>
      {shown.length > 0 && (
        <div className="error-columns">
          {shown.map((column) => <code key={column}>{column}</code>)}
          {hidden > 0 && <span className="text-xs text-muted">and {hidden} more</span>}
        </div>
      )}
    </div>
  );
}
