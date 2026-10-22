import { useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, Download, LoaderCircle, ShieldAlert, ShieldCheck } from "lucide-react";
import Card from "./Card";
import type { ClassName, PredictionResponse, PredictionRow } from "../api";
import { formatCompact, formatInt } from "../format";

type Filter = "all" | "Benign" | "Malicious" | "wrong";
const PAGE_SIZE = 20;

interface ResultsTableProps {
  result: PredictionResponse;
  downloading: boolean;
  onDownload: () => void;
}

export default function ResultsTable({ result, downloading, onDownload }: ResultsTableProps) {
  const [filter, setFilter] = useState<Filter>("all");
  const [page, setPage] = useState(0);
  const labelled = result.evaluation !== null;

  const rows = useMemo(() => result.rows.filter((r) => matches(r, filter)), [result.rows, filter]);
  const pageCount = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const visible = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const filters: { id: Filter; label: string }[] = [
    { id: "all", label: "All" },
    { id: "Benign", label: "Benign" },
    { id: "Malicious", label: "Malicious" },
    ...(labelled ? [{ id: "wrong" as Filter, label: "Misclassified" }] : []),
  ];

  return (
    <Card
      title="Prediction results"
      subtitle={
        result.rows_truncated
          ? `Showing the first ${formatInt(result.rows.length)} of ${formatInt(result.summary.total)} flows. Download the CSV for every row.`
          : `${formatInt(result.summary.total)} flows classified by ${result.model_name}`
      }
      action={
        <button
          type="button"
          onClick={onDownload}
          disabled={downloading}
          className="inline-flex items-center gap-1.5 rounded-md border border-line px-3 py-2 text-sm text-ink hover:bg-raised disabled:opacity-50"
        >
          {downloading ? <LoaderCircle size={16} className="animate-spin" /> : <Download size={16} />}
          Download CSV
        </button>
      }
    >
      <div className="mb-3 flex flex-wrap gap-1 rounded-lg bg-page p-1 text-sm sm:w-fit">
        {filters.map((f) => (
          <button
            key={f.id}
            type="button"
            onClick={() => {
              setFilter(f.id);
              setPage(0);
            }}
            className={`rounded-md px-3 py-1.5 ${filter === f.id ? "bg-raised text-ink" : "text-muted hover:text-ink"}`}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full min-w-[720px] text-left text-sm">
          <thead className="bg-raised text-xs uppercase tracking-wide text-muted">
            <tr>
              <th className="px-3 py-2.5 font-medium">#</th>
              {result.display_columns.map((c) => (
                <th key={c} className="px-3 py-2.5 text-right font-medium">
                  {c}
                </th>
              ))}
              <th className="px-3 py-2.5 font-medium">Malicious probability</th>
              <th className="px-3 py-2.5 font-medium">Prediction</th>
              {labelled && <th className="px-3 py-2.5 font-medium">Actual</th>}
            </tr>
          </thead>
          <tbody className="tabular">
            {visible.map((r) => (
              <tr key={r.row} className="border-t border-line hover:bg-raised/50">
                <td className="px-3 py-2 text-muted">{r.row}</td>
                {result.display_columns.map((c) => (
                  <td key={c} className="px-3 py-2 text-right text-ink-2" title={String(r.values[c] ?? "")}>
                    {c === "Destination Port" ? (r.values[c] ?? "—") : formatCompact(r.values[c])}
                  </td>
                ))}
                <td className="px-3 py-2">
                  <ProbabilityBar value={r.malicious_probability} />
                </td>
                <td className="px-3 py-2">
                  <ClassBadge value={r.prediction} />
                </td>
                {labelled && (
                  <td className={`px-3 py-2 ${r.actual !== r.prediction ? "text-warn" : "text-ink-2"}`}>
                    {r.actual}
                    {r.actual !== r.prediction && <span className="ml-1 text-xs">(mismatch)</span>}
                  </td>
                )}
              </tr>
            ))}
            {visible.length === 0 && (
              <tr>
                <td colSpan={10} className="px-3 py-8 text-center text-muted">
                  No flows match this filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="mt-3 flex items-center justify-between text-sm text-muted">
        <span>
          {formatInt(rows.length)} row{rows.length === 1 ? "" : "s"}
        </span>
        <div className="flex items-center gap-2">
          <PageButton label="Previous page" disabled={page === 0} onClick={() => setPage(page - 1)}>
            <ChevronLeft size={16} />
          </PageButton>
          <span className="tabular">
            Page {page + 1} of {pageCount}
          </span>
          <PageButton label="Next page" disabled={page >= pageCount - 1} onClick={() => setPage(page + 1)}>
            <ChevronRight size={16} />
          </PageButton>
        </div>
      </div>
    </Card>
  );
}

function matches(row: PredictionRow, filter: Filter): boolean {
  if (filter === "all") return true;
  if (filter === "wrong") return row.actual !== null && row.actual !== row.prediction;
  return row.prediction === filter;
}

export function ClassBadge({ value }: { value: ClassName }) {
  const malicious = value === "Malicious";
  const Icon = malicious ? ShieldAlert : ShieldCheck;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium ${
        malicious ? "bg-malicious/15 text-ink" : "bg-benign/15 text-ink"
      }`}
    >
      <Icon size={14} className={malicious ? "text-malicious" : "text-benign"} />
      {value}
    </span>
  );
}

function ProbabilityBar({ value }: { value: number }) {
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-line">
        <div className="h-full rounded-full bg-malicious" style={{ width: `${value * 100}%` }} />
      </div>
      <span className="w-12 text-xs text-ink-2">{(value * 100).toFixed(1)}%</span>
    </div>
  );
}

function PageButton(props: { label: string; disabled: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-label={props.label}
      disabled={props.disabled}
      onClick={props.onClick}
      className="rounded-md border border-line p-1.5 text-ink-2 hover:bg-raised disabled:opacity-40"
    >
      {props.children}
    </button>
  );
}
