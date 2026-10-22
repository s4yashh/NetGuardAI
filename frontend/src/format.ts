export const formatInt = (n: number) => n.toLocaleString("en-US");

export const formatPct = (ratio: number, digits = 2) => `${(ratio * 100).toFixed(digits)}%`;

/** Compact numbers for table cells: 1234567 -> 1.23M */
export function formatCompact(value: number | null): string {
  if (value === null) return "—";
  return new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 2 }).format(value);
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}

export function formatDate(iso: string): string {
  const date = new Date(iso);
  return isNaN(date.getTime()) ? iso : date.toLocaleString();
}

// Model colours follow the model (fixed order), never its rank.
export const MODEL_COLORS: Record<string, string> = {
  "Random Forest": "var(--color-series-1)",
  "Decision Tree": "var(--color-series-2)",
  "Logistic Regression": "var(--color-series-3)",
};
