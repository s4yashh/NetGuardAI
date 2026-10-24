import { AlertTriangle, CheckCircle2, Info } from "lucide-react";
import type { ShiftReport } from "../api";
import { formatPct } from "../format";

interface ShiftWarningProps {
  shift: ShiftReport | null;
  warning: string | null;
}

/**
 * Batch-level reliability banner.
 *
 * Shown before the per-flow results, because a distribution warning changes how
 * every number below it should be read.
 */
export default function ShiftWarning({ shift, warning }: ShiftWarningProps) {
  if (!shift) return null;

  if (shift.verdict === "in_distribution") {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-line bg-card px-5 py-3 text-sm text-ink-2">
        <CheckCircle2 size={16} className="shrink-0 text-benign" />
        <span>
          Batch distribution matches the training traffic
          <span className="text-muted"> · shift score {shift.score.toFixed(2)} (limit {shift.threshold_in.toFixed(2)})</span>
        </span>
      </div>
    );
  }

  const severe = shift.verdict === "severely_shifted";
  const Icon = severe ? AlertTriangle : Info;
  const tone = severe
    ? "border-malicious/40 bg-malicious/10"
    : "border-warn/40 bg-warn/10";
  const iconTone = severe ? "text-malicious" : "text-warn";

  return (
    <div className={`rounded-xl border px-5 py-4 ${tone}`}>
      <div className="flex items-start gap-3">
        <Icon size={20} className={`mt-0.5 shrink-0 ${iconTone}`} />
        <div className="space-y-1">
          <p className="font-medium text-ink">
            {severe ? "This batch is outside the model's training distribution" : "This batch differs from the training traffic"}
          </p>
          <p className="text-sm text-ink-2">
            {warning ??
              "The shift gate detected unusual feature distributions. Treat the per-flow results below with caution."}
          </p>
          <p className="text-xs text-muted">
            Shift score {shift.score.toFixed(2)} · in-distribution limit {shift.threshold_in.toFixed(2)} ·{" "}
            severe limit {shift.threshold_severe.toFixed(2)}
            {shift.rows_compared ? ` · compared ${shift.rows_compared.toLocaleString()} flows` : ""}
          </p>
          {shift.top_shifted_features.length > 0 && (
            <p className="text-xs text-muted">
              Most affected features:{" "}
              {shift.top_shifted_features.slice(0, 4).map((f) => f.feature).join(", ")}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

/** Compact summary of the operating point, shown next to the review count. */
export function operatingPointLabel(alpha?: number, capacity?: number): string {
  if (alpha === undefined) return "default threshold";
  const budget = formatPct(alpha, 1);
  const review = capacity === undefined ? "" : ` · review capacity ${formatPct(capacity, 0)}`;
  return `false-alarm budget ${budget}${review}`;
}
