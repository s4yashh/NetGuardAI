import { ShieldCheck, CircleAlert, LoaderCircle } from "lucide-react";
import type { Health } from "../api";

export default function Header({ health, error }: { health: Health | null; error: string | null }) {
  return (
    <header className="border-b border-line bg-card/60">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-4 sm:px-6">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent/15 text-accent-strong">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h1 className="text-lg font-semibold leading-tight text-ink">NetGuard AI</h1>
            <p className="text-sm text-muted">Malware detection using AI-based network traffic analysis</p>
          </div>
        </div>
        <ModelStatus health={health} error={error} />
      </div>
    </header>
  );
}

function ModelStatus({ health, error }: { health: Health | null; error: string | null }) {
  if (error) {
    return (
      <span className="inline-flex items-center gap-2 rounded-full border border-malicious/40 px-3 py-1 text-sm text-ink-2">
        <CircleAlert size={16} className="text-malicious" /> Backend offline
      </span>
    );
  }
  if (!health) {
    return (
      <span className="inline-flex items-center gap-2 text-sm text-muted">
        <LoaderCircle size={16} className="animate-spin" /> Connecting…
      </span>
    );
  }
  if (!health.model_loaded) {
    return (
      <span className="inline-flex items-center gap-2 rounded-full border border-warn/40 px-3 py-1 text-sm text-ink-2">
        <CircleAlert size={16} className="text-warn" /> No trained model
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-line px-3 py-1 text-sm text-ink-2">
      <span className="h-2 w-2 rounded-full bg-ok" />
      Model ready · <span className="text-ink">{health.model_name}</span>
      <span className="text-muted">({health.feature_count} features)</span>
    </span>
  );
}
