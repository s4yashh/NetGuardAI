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
      <div className="shift-banner shift-banner-ok">
        <CheckCircle2 size={18} className="mt-0.5 shrink-0 text-benign" />
        <div><p className="shift-title">Batch distribution matches the training reference</p><p className="shift-detail">Shift score {shift.score.toFixed(2)} · in-distribution limit {shift.threshold_in.toFixed(2)} · {shift.rows_compared?.toLocaleString() ?? 0} flows compared</p></div>
      </div>
    );
  }

  const severe = shift.verdict === "severely_shifted";
  const Icon = severe ? AlertTriangle : Info;
  const tone = severe ? "shift-banner-danger" : "shift-banner-warn";
  const iconTone = severe ? "text-malicious" : "text-review";

  return (
    <div className={`shift-banner ${tone}`}>
        <Icon size={19} className={`mt-0.5 shrink-0 ${iconTone}`} />
        <div>
          <p className="shift-title">
            {severe ? "This batch is outside the model's training distribution" : "This batch differs from the training traffic"}
          </p>
          <p className="shift-copy">
            {warning ??
              "The shift gate detected unusual feature distributions. Treat the per-flow results below with caution."}
          </p>
          <p className="shift-detail">
            Shift score {shift.score.toFixed(2)} · in-distribution limit {shift.threshold_in.toFixed(2)} ·{" "}
            severe limit {shift.threshold_severe.toFixed(2)}
            {shift.rows_compared ? ` · compared ${shift.rows_compared.toLocaleString()} flows` : ""}
          </p>
          {shift.top_shifted_features.length > 0 && (
            <p className="shift-detail">
              Most affected features:{" "}
              {shift.top_shifted_features.slice(0, 4).map((f) => f.feature).join(", ")}
            </p>
          )}
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
