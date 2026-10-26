import { Activity, ClipboardCheck, ShieldAlert, ShieldCheck, Target, type LucideIcon } from "lucide-react";
import type { PredictionResponse } from "../api";
import { formatInt, formatPct } from "../format";

export default function SummaryCards({ result }: { result: PredictionResponse }) {
  const { summary, evaluation } = result;
  const cards = [
    { icon: Activity, label: "Flows analyzed", value: formatInt(summary.total), note: result.filename, tone: "text-accent-strong" },
    { icon: ShieldCheck, label: "Benign", value: formatInt(summary.benign), note: `${formatPct(summary.benign_ratio)} of uploaded flows`, tone: "text-benign" },
    { icon: ShieldAlert, label: "Malicious", value: formatInt(summary.malicious), note: `${formatPct(summary.malicious_ratio)} of uploaded flows`, tone: "text-malicious" },
    ...(summary.review > 0 ? [{ icon: ClipboardCheck, label: "Needs review", value: formatInt(summary.review), note: `${formatPct(summary.review_ratio)} · abstained decision`, tone: "text-review" }] : []),
    ...(evaluation ? [{ icon: Target, label: "Label agreement", value: formatPct(evaluation.accuracy), note: `${formatInt(evaluation.correct)} of ${formatInt(summary.total)} predictions match`, tone: "text-accent-strong" }] : []),
  ];

  return (
    <section aria-label="Analysis summary">
      <div className="stat-grid">
        {cards.map((card) => <Stat key={card.label} {...card} />)}
      </div>
      <Composition benign={summary.benign} review={summary.review} malicious={summary.malicious} />
    </section>
  );
}

function Stat({ icon: Icon, label, value, note, tone }: { icon: LucideIcon; label: string; value: string; note: string; tone: string }) {
  return <article className="stat-card">
    <div className="stat-label"><Icon size={15} className={tone} /> {label}</div>
    <div className="stat-value tabular">{value}</div>
    <div className="stat-note" title={note}>{note}</div>
  </article>;
}

function Composition({ benign, review, malicious }: { benign: number; review: number; malicious: number }) {
  const total = benign + review + malicious || 1;
  const parts = [
    { label: "Benign", value: benign, color: "var(--color-benign)" },
    ...(review ? [{ label: "Review", value: review, color: "var(--color-review)" }] : []),
    { label: "Malicious", value: malicious, color: "var(--color-malicious)" },
  ];
  return <div className="composition">
    <div className="composition-header">
      <span>Traffic composition</span>
      <span className="composition-legend">
        {parts.map((part) => <span className="legend-item" key={part.label}><i className="legend-dot" style={{ background: part.color }} />{part.label} <strong className="tabular text-ink">{formatPct(part.value / total, 1)}</strong></span>)}
      </span>
    </div>
    <div className="composition-bar">
      {parts.filter((part) => part.value > 0).map((part) => <div key={part.label} style={{ flexGrow: part.value, background: part.color }} title={`${part.label}: ${formatInt(part.value)}`} />)}
    </div>
  </div>;
}
