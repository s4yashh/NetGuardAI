import { Activity, ShieldAlert, ShieldCheck, Target, type LucideIcon } from "lucide-react";
import type { PredictionResponse } from "../api";
import { formatInt, formatPct } from "../format";

export default function SummaryCards({ result }: { result: PredictionResponse }) {
  const { summary, evaluation } = result;
  return (
    <div className="space-y-4">
      <div className={`grid grid-cols-1 gap-4 sm:grid-cols-2 ${evaluation ? "lg:grid-cols-4" : "lg:grid-cols-3"}`}>
        <Stat icon={Activity} label="Flows analyzed" value={formatInt(summary.total)} note={result.filename} />
        <Stat
          icon={ShieldCheck}
          iconClass="text-benign"
          label="Benign"
          value={formatInt(summary.benign)}
          note={formatPct(1 - summary.malicious_ratio) + " of flows"}
        />
        <Stat
          icon={ShieldAlert}
          iconClass="text-malicious"
          label="Malicious"
          value={formatInt(summary.malicious)}
          note={formatPct(summary.malicious_ratio) + " of flows"}
        />
        {evaluation && (
          <Stat
            icon={Target}
            label="Agreement with file labels"
            value={formatPct(evaluation.accuracy)}
            note={`${formatInt(evaluation.correct)} of ${formatInt(summary.total)} correct`}
          />
        )}
      </div>
      <ProportionBar benign={summary.benign} malicious={summary.malicious} />
    </div>
  );
}

interface StatProps {
  icon: LucideIcon;
  iconClass?: string;
  label: string;
  value: string;
  note: string;
}

function Stat({ icon: Icon, iconClass = "text-ink-2", label, value, note }: StatProps) {
  return (
    <div className="rounded-xl border border-line bg-card p-5">
      <div className="flex items-center gap-2 text-sm text-ink-2">
        <Icon size={18} className={iconClass} />
        {label}
      </div>
      <p className="mt-2 text-3xl font-semibold text-ink">{value}</p>
      <p className="mt-1 truncate text-sm text-muted" title={note}>
        {note}
      </p>
    </div>
  );
}

/** One horizontal bar split into benign / malicious share, with a 2px gap between parts. */
function ProportionBar({ benign, malicious }: { benign: number; malicious: number }) {
  const total = benign + malicious;
  return (
    <div className="rounded-xl border border-line bg-card px-5 py-4">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-sm">
        <span className="text-ink-2">Traffic composition</span>
        <span className="flex gap-4 text-ink-2">
          <Legend color="bg-benign" label="Benign" value={benign / total} />
          <Legend color="bg-malicious" label="Malicious" value={malicious / total} />
        </span>
      </div>
      <div className="flex h-3 gap-0.5 overflow-hidden rounded">
        {benign > 0 && <div className="bg-benign" style={{ flexGrow: benign }} title={`Benign: ${formatInt(benign)}`} />}
        {malicious > 0 && (
          <div className="bg-malicious" style={{ flexGrow: malicious }} title={`Malicious: ${formatInt(malicious)}`} />
        )}
      </div>
    </div>
  );
}

function Legend({ color, label, value }: { color: string; label: string; value: number }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`h-2.5 w-2.5 rounded-sm ${color}`} />
      {label} <span className="tabular text-ink">{formatPct(value, 1)}</span>
    </span>
  );
}
