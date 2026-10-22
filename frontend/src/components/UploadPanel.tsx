import { useRef, useState, type DragEvent } from "react";
import { FileSpreadsheet, LoaderCircle, Play, Upload, X, CircleAlert } from "lucide-react";
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
      title="Analyze network traffic"
      subtitle="Upload flow records in CIC-IDS2017 / CICFlowMeter CSV format. An optional Label column lets NetGuard check its predictions."
    >
      <div
        role="button"
        tabIndex={0}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className={`flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-4 py-8 text-center transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
          dragging ? "border-accent bg-accent/10" : "border-line bg-raised/40 hover:border-accent/60"
        }`}
      >
        <Upload size={24} className="text-accent-strong" />
        <p className="text-sm text-ink">
          <span className="font-medium text-accent-strong">Choose a CSV file</span> or drag it here
        </p>
        <p className="text-xs text-muted">Maximum 100 MB</p>
        <input
          ref={inputRef}
          type="file"
          accept=".csv,text/csv"
          className="hidden"
          onChange={(e) => {
            onFileChange(e.target.files?.[0] ?? null);
            e.target.value = ""; // allow re-selecting the same file
          }}
        />
      </div>

      {file && (
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-raised px-4 py-3">
          <div className="flex min-w-0 items-center gap-3">
            <FileSpreadsheet size={20} className="shrink-0 text-ink-2" />
            <div className="min-w-0">
              <p className="truncate text-sm font-medium text-ink">{file.name}</p>
              <p className="text-xs text-muted">{formatBytes(file.size)}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => onFileChange(null)}
              disabled={loading}
              className="inline-flex items-center gap-1.5 rounded-md px-3 py-2 text-sm text-ink-2 hover:bg-line/60 disabled:opacity-50"
            >
              <X size={16} /> Clear
            </button>
            <button
              type="button"
              onClick={onAnalyze}
              disabled={loading || !modelReady}
              title={modelReady ? undefined : "Train a model first"}
              className="inline-flex items-center gap-1.5 rounded-md bg-accent px-4 py-2 text-sm font-medium text-white hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? <LoaderCircle size={16} className="animate-spin" /> : <Play size={16} />}
              {loading ? "Analyzing…" : "Analyze traffic"}
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
    <div role="alert" className="mt-4 rounded-lg border border-malicious/40 bg-malicious/10 px-4 py-3">
      <p className="flex items-center gap-2 text-sm font-medium text-ink">
        <CircleAlert size={16} className="shrink-0 text-malicious" />
        {error.message}
      </p>
      {shown.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {shown.map((column) => (
            <code key={column} className="rounded bg-page px-1.5 py-0.5 text-xs text-ink-2">
              {column}
            </code>
          ))}
          {hidden > 0 && <span className="text-xs text-muted">and {hidden} more</span>}
        </div>
      )}
    </div>
  );
}
