import { useState } from "react";
import Card from "./Card";
import type { Metrics } from "../api";
import { formatInt, formatPct } from "../format";

const CLASSES = ["Benign", "Malicious"];
const CELL_NAMES = [
  ["True negative", "False positive"],
  ["False negative", "True positive"],
];

/** 2x2 confusion matrix from the test set. Cell shade = share of that actual class. */
export default function ConfusionMatrix({ metrics }: { metrics: Metrics }) {
  const [selected, setSelected] = useState(metrics.best_model);
  const model = metrics.models.find((m) => m.name === selected) ?? metrics.models[0];
  const matrix = model.confusion_matrix;

  return (
    <Card
      title="Confusion matrix"
      subtitle="Rows = actual class, columns = predicted class (test set)"
      action={
        <select
          value={model.name}
          onChange={(e) => setSelected(e.target.value)}
          aria-label="Model"
          className="rounded-md border border-line bg-raised px-2 py-1.5 text-sm text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {metrics.models.map((m) => (
            <option key={m.name}>{m.name}</option>
          ))}
        </select>
      }
    >
      <div className="grid grid-cols-[auto_1fr_1fr] gap-0.5 text-sm">
        <div />
        {CLASSES.map((c) => (
          <div key={c} className="pb-2 text-center text-xs uppercase tracking-wide text-muted">
            Predicted {c}
          </div>
        ))}
        {matrix.map((row, i) => {
          const rowTotal = row[0] + row[1];
          return [
            <div key={`label-${i}`} className="flex items-center pr-3 text-xs uppercase tracking-wide text-muted">
              Actual {CLASSES[i]}
            </div>,
            ...row.map((count, j) => {
              const share = rowTotal ? count / rowTotal : 0;
              return (
                <div
                  key={`${i}-${j}`}
                  className={`flex flex-col items-center justify-center px-2 py-6 text-center ${
                    i === 0 && j === 0 ? "rounded-tl-lg" : ""
                  } ${i === 0 && j === 1 ? "rounded-tr-lg" : ""} ${i === 1 && j === 0 ? "rounded-bl-lg" : ""} ${
                    i === 1 && j === 1 ? "rounded-br-lg" : ""
                  }`}
                  style={{ background: `rgba(57, 135, 229, ${0.06 + share * 0.6})` }}
                  title={`${CELL_NAMES[i][j]}: ${formatInt(count)}`}
                >
                  <span className="tabular text-xl font-semibold text-ink">{formatInt(count)}</span>
                  <span className="mt-0.5 text-xs text-ink-2">
                    {CELL_NAMES[i][j]} · {formatPct(share)}
                  </span>
                </div>
              );
            }),
          ];
        })}
      </div>
    </Card>
  );
}
