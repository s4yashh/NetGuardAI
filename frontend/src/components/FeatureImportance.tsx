import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Card from "./Card";
import type { Metrics } from "../api";

/** Top features used by the selected tree-based model (Gini importance). */
export default function FeatureImportance({ metrics }: { metrics: Metrics }) {
  const data = metrics.feature_importances.slice(0, 10);
  if (data.length === 0) return null;
  const labelWidth = window.innerWidth < 640 ? 140 : 200; // narrower labels on phones

  return (
    <Card title="Most important features" subtitle={`Top 10 of ${metrics.features.count} features in the ${metrics.best_model} model`}>
      <div style={{ height: data.length * 30 + 40 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 0 }}>
            <CartesianGrid horizontal={false} stroke="var(--color-grid)" />
            <XAxis
              type="number"
              tickFormatter={(v: number) => `${+(v * 100).toFixed(1)}%`}
              tick={{ fill: "var(--color-muted)", fontSize: 12 }}
              axisLine={{ stroke: "var(--color-line)" }}
              tickLine={false}
            />
            <YAxis
              type="category"
              dataKey="feature"
              width={labelWidth}
              tick={{ fill: "var(--color-ink-2)", fontSize: labelWidth < 200 ? 11 : 12 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: "var(--color-raised)", opacity: 0.6 }}
              contentStyle={{ background: "var(--color-raised)", border: "1px solid var(--color-line)", borderRadius: 8 }}
              labelStyle={{ color: "var(--color-ink)", fontWeight: 600 }}
              itemStyle={{ color: "var(--color-ink-2)" }}
              formatter={(value) => [`${(Number(value) * 100).toFixed(2)}%`, "Importance"]}
            />
            <Bar dataKey="importance" fill="var(--color-series-1)" radius={[0, 4, 4, 0]} maxBarSize={16} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
