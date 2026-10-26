import { useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, ClipboardCheck, Download, LoaderCircle, ShieldAlert, ShieldCheck } from "lucide-react";
import Card from "./Card";
import type { ClassName, PredictionResponse, PredictionRow } from "../api";
import { formatCompact, formatInt } from "../format";

type Filter = "all" | "Benign" | "Malicious" | "Review" | "wrong";
const PAGE_SIZE = 20;

interface ResultsTableProps { result: PredictionResponse; downloading: boolean; onDownload: () => void; }

export default function ResultsTable({ result, downloading, onDownload }: ResultsTableProps) {
  const [filter, setFilter] = useState<Filter>("all");
  const [page, setPage] = useState(0);
  const labelled = result.evaluation !== null;
  const rows = useMemo(() => result.rows.filter((row) => matches(row, filter)), [result.rows, filter]);
  const pageCount = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const visible = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const first = rows.length ? page * PAGE_SIZE + 1 : 0;
  const last = Math.min((page + 1) * PAGE_SIZE, rows.length);
  const filters: { id: Filter; label: string; count: number }[] = [
    { id: "all", label: "All", count: result.rows.length },
    { id: "Benign", label: "Benign", count: result.rows.filter((row) => row.decision === "Benign").length },
    { id: "Malicious", label: "Malicious", count: result.rows.filter((row) => row.decision === "Malicious").length },
    ...(result.summary.review > 0 ? [{ id: "Review" as Filter, label: "Review", count: result.summary.review }] : []),
    ...(labelled ? [{ id: "wrong" as Filter, label: "Misclassified", count: result.rows.filter((row) => row.actual !== null && row.actual !== row.prediction).length }] : []),
  ];

  return <Card
    title="Prediction results"
    subtitle={result.rows_truncated ? `Showing the first ${formatInt(result.rows.length)} of ${formatInt(result.summary.total)} flows. Download the CSV for every record.` : `${formatInt(result.summary.total)} flows analyzed by ${result.model_name}.`}
    action={<button type="button" onClick={onDownload} disabled={downloading} className="btn btn-quiet border border-line"><>{downloading ? <LoaderCircle size={15} className="animate-spin" /> : <Download size={15} />}</>Export CSV</button>}
  >
    <div className="table-toolbar">
      <div className="filter-group" aria-label="Filter prediction results">
        {filters.map((item) => <button key={item.id} type="button" onClick={() => { setFilter(item.id); setPage(0); }} className={`filter-button ${filter === item.id ? "filter-button-active" : ""}`}>
          {item.label} <span className="tabular opacity-70">{item.count}</span>
        </button>)}
      </div>
      <div className="text-xs text-muted">Decision uses calibrated probability and review thresholds</div>
    </div>
    <div className="table-shell">
      <table className="console-table tabular">
        <thead><tr>
          <th>#</th>
          {result.display_columns.map((column) => <th key={column} className="text-right">{column}</th>)}
          <th>Malicious probability</th><th>Decision</th>{labelled && <th>Actual label</th>}
        </tr></thead>
        <tbody>
          {visible.map((row) => <tr key={row.row}>
            <td className="text-muted">{row.row}</td>
            {result.display_columns.map((column) => <td key={column} className="text-right" title={String(row.values[column] ?? "")}>{column === "Destination Port" ? (row.values[column] ?? "—") : formatCompact(row.values[column])}</td>)}
            <td><ProbabilityBar value={row.malicious_probability} /></td>
            <td><ClassBadge value={row.decision} /></td>
            {labelled && <td className={row.actual !== row.prediction ? "text-review" : "text-ink-2"}>{row.actual}{row.actual !== row.prediction && <span className="ml-1 text-[10px]">(mismatch)</span>}</td>}
          </tr>)}
          {!visible.length && <tr><td colSpan={10} className="py-10 text-center text-muted">No flows match this filter.</td></tr>}
        </tbody>
      </table>
    </div>
    <div className="table-footer">
      <span>Showing <strong className="tabular text-ink">{first}–{last}</strong> of {formatInt(rows.length)} filtered flows</span>
      <div className="pager">
        <button className="page-button" type="button" aria-label="Previous page" disabled={page === 0} onClick={() => setPage(page - 1)}><ChevronLeft size={15} /></button>
        <span className="tabular">Page {page + 1} / {pageCount}</span>
        <button className="page-button" type="button" aria-label="Next page" disabled={page >= pageCount - 1} onClick={() => setPage(page + 1)}><ChevronRight size={15} /></button>
      </div>
    </div>
  </Card>;
}

function matches(row: PredictionRow, filter: Filter): boolean {
  if (filter === "all") return true;
  if (filter === "wrong") return row.actual !== null && row.actual !== row.prediction;
  return row.decision === filter;
}

export function ClassBadge({ value }: { value: ClassName | "Review" }) {
  if (value === "Review") return <span className="decision-badge bg-review/15 text-review"><ClipboardCheck size={13} /> Review</span>;
  const malicious = value === "Malicious";
  const Icon = malicious ? ShieldAlert : ShieldCheck;
  return <span className={`decision-badge ${malicious ? "bg-malicious/15 text-malicious" : "bg-benign/15 text-benign"}`}><Icon size={13} />{value}</span>;
}

function ProbabilityBar({ value }: { value: number }) {
  return <div className="probability"><div className="probability-track"><div className="probability-fill" style={{ width: `${value * 100}%` }} /></div><span className="w-10 text-[11px]">{(value * 100).toFixed(1)}%</span></div>;
}
