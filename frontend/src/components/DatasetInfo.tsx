import { Database } from "lucide-react";
import Card from "./Card";
import type { Metrics } from "../api";
import { formatDate, formatInt } from "../format";

/** Facts about the data the model was trained and tested on. */
export default function DatasetInfo({ metrics }: { metrics: Metrics }) {
  const { dataset, split, features } = metrics;
  const total = split.train + split.validation + split.test;
  const items = [
    { label: "Raw flows", value: formatInt(dataset.raw_rows) },
    { label: "Duplicates removed", value: formatInt(dataset.duplicates_removed) },
    { label: "Flows used", value: formatInt(dataset.rows_used) },
    { label: "Features", value: String(features.count) },
  ];
  const parts = [
    { label: "Train", value: split.train, color: "bg-accent" },
    { label: "Validation", value: split.validation, color: "bg-ink-2" },
    { label: "Test", value: split.test, color: "bg-muted" },
  ];

  return (
    <Card title="Training data" subtitle={dataset.source}>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {items.map((item) => (
          <div key={item.label}>
            <p className="text-xs text-muted">{item.label}</p>
            <p className="mt-1 text-lg font-semibold text-ink">{item.value}</p>
          </div>
        ))}
      </div>

      <div className="mt-5">
        <p className="mb-2 text-xs text-muted">Stratified split (random_state = 42)</p>
        <div className="flex h-2.5 gap-0.5 overflow-hidden rounded">
          {parts.map((p) => (
            <div key={p.label} className={p.color} style={{ flexGrow: p.value }} />
          ))}
        </div>
        <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-sm text-ink-2">
          {parts.map((p) => (
            <span key={p.label} className="inline-flex items-center gap-1.5">
              <span className={`h-2.5 w-2.5 rounded-sm ${p.color}`} />
              {p.label} <span className="tabular text-ink">{formatInt(p.value)}</span>
              <span className="text-muted">({((p.value / total) * 100).toFixed(0)}%)</span>
            </span>
          ))}
        </div>
      </div>

      <div className="mt-5 flex items-start gap-2 rounded-lg bg-raised px-3 py-2.5 text-xs text-ink-2">
        <Database size={14} className="mt-0.5 shrink-0 text-muted" />
        <span>
          Class balance: {formatInt(dataset.class_counts.Benign)} benign / {formatInt(dataset.class_counts.Malicious)}{" "}
          malicious flows{dataset.sampled ? " (stratified sample of the cleaned dataset)" : ""}. Trained{" "}
          {formatDate(metrics.generated_at)}.
        </span>
      </div>
    </Card>
  );
}
