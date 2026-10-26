import { CircleAlert, LoaderCircle } from "lucide-react";
import type { Health } from "../api";

export default function Header({ health, error }: { health: Health | null; error: string | null }) {
  return (
    <header className="topbar">
      <div className="topbar-copy">
        <h1>Network traffic analysis</h1>
        <p>Upload, inspect, and validate flow-level threat predictions</p>
      </div>
      <div className="topbar-actions">
        <a className="api-link" href="/docs" target="_blank" rel="noreferrer">API reference</a>
        <ModelStatus health={health} error={error} />
      </div>
    </header>
  );
}

function ModelStatus({ health, error }: { health: Health | null; error: string | null }) {
  if (error) {
    return (
      <span className="model-status status-problem">
        <CircleAlert size={16} className="text-malicious" /> Backend offline
      </span>
    );
  }
  if (!health) {
    return (
      <span className="model-status">
        <LoaderCircle size={16} className="animate-spin" /> Connecting…
      </span>
    );
  }
  if (!health.model_loaded) {
    return (
      <span className="model-status status-warning">
        <CircleAlert size={16} className="text-warn" /> No trained model
      </span>
    );
  }
  return (
    <span className="model-status" title={`Reliability layer: ${health.reliability_active ? "active" : "inactive"} · Shift gate: ${health.shift_gate_active ? "active" : "inactive"}`}>
      <span className="status-dot" />
      <span>Model ready · <strong>{health.model_name}</strong></span>
      <span className="text-muted">({health.feature_count} features)</span>
    </span>
  );
}
