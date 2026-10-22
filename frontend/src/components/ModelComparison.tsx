import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Award } from "lucide-react";
import Card from "./Card";
import type { Metrics } from "../api";
import { MODEL_COLORS, formatPct } from "../format";

const METRICS = [
  { key: "accuracy", label: "Accuracy" },
  { key: "precision", label: "Precision" },
  { key: "recall", label: "Recall" },
  { key: "f1_score", label: "F1-score" },
] as const;

/** Table + grouped bar chart comparing the three trained models on the test set. */
export default function ModelComparison({ metrics }: { metrics: Metrics }) {
  // One chart row per metric, one bar per model.
  const chartData = METRICS.map((m) => ({
    metric: m.label,
    ...Object.fromEntries(metrics.models.map((model) => [model.name, model[m.key]])),
  }));

  return (
    <Card
      title="Model comparison"
      subtitle={`Test set of ${metrics.split.test.toLocaleString()} unseen flows · positive class = Malicious`}
    >
      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full min-w-[680px] text-left text-sm">
          <thead className="bg-raised text-xs uppercase tracking-wide text-muted">
            <tr>
              <th className="px-3 py-2.5 font-medium">Model</th>
              {METRICS.map((m) => (
                <th key={m.key} className="px-3 py-2.5 text-right font-medium">
                  {m.label}
                </th>
              ))}
              <th className="px-3 py-2.5 text-right font-medium">Validation F1</th>
              <th className="px-3 py-2.5 text-right font-medium">Train time</th>
            </tr>
          </thead>
          <tbody className="tabular">
            {metrics.models.map((model) => (
              <tr key={model.name} className="border-t border-line">
                <td className="px-3 py-2.5">
                  <span className="inline-flex items-center gap-2 text-ink">
                    <span className="h-2.5 w-2.5 rounded-sm" style={{ background: MODEL_COLORS[model.name] }} />
                    {model.name}
                    {model.name === metrics.best_model && (
                      <span className="inline-flex items-center gap-1 rounded bg-accent/15 px-1.5 py-0.5 text-xs text-accent-strong">
                        <Award size={12} /> Selected
                      </span>
                    )}
                  </span>
                </td>
                {METRICS.map((m) => (
                  <td key={m.key} className="px-3 py-2.5 text-right text-ink-2">
                    {formatPct(model[m.key])}
                  </td>
                ))}
                <td className="px-3 py-2.5 text-right text-muted">{formatPct(model.validation_f1)}</td>
                <td className="px-3 py-2.5 text-right text-muted">{model.train_seconds.toFixed(1)} s</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-xs text-muted">
        Model selection: {metrics.selection_metric}. Accuracy, precision, recall and F1 come from the separate test set,
        which is never used for training or selection.
      </p>

      <div className="mt-5 h-72">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} barGap={2} barCategoryGap="25%" margin={{ top: 8, right: 8, bottom: 0, left: -8 }}>
            <CartesianGrid vertical={false} stroke="var(--color-grid)" />
            <XAxis dataKey="metric" tick={{ fill: "var(--color-ink-2)", fontSize: 12 }} axisLine={{ stroke: "var(--color-line)" }} tickLine={false} />
            <YAxis
              domain={[0, 1]}
              ticks={[0, 0.25, 0.5, 0.75, 1]}
              tickFormatter={(v: number) => `${v * 100}%`}
              tick={{ fill: "var(--color-muted)", fontSize: 12 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: "var(--color-raised)", opacity: 0.6 }}
              contentStyle={{ background: "var(--color-raised)", border: "1px solid var(--color-line)", borderRadius: 8 }}
              labelStyle={{ color: "var(--color-ink)", fontWeight: 600 }}
              itemStyle={{ color: "var(--color-ink-2)" }}
              formatter={(value) => formatPct(Number(value), 3)}
            />
            <Legend
              itemSorter={null}
              wrapperStyle={{ fontSize: 12 }}
              iconType="square"
              iconSize={10}
              formatter={(value) => <span style={{ color: "var(--color-ink-2)" }}>{value}</span>}
            />
            {metrics.models.map((model) => (
              <Bar key={model.name} dataKey={model.name} fill={MODEL_COLORS[model.name]} radius={[4, 4, 0, 0]} maxBarSize={24} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
