import { useEffect, useState } from "react";
import { BarChart3, Info, Radar } from "lucide-react";
import Header from "./components/Header";
import ConsoleSidebar from "./components/ConsoleSidebar";
import UploadPanel from "./components/UploadPanel";
import ShiftWarning from "./components/ShiftWarning";
import SummaryCards from "./components/SummaryCards";
import ResultsTable from "./components/ResultsTable";
import DatasetInfo from "./components/DatasetInfo";
import ModelComparison from "./components/ModelComparison";
import ConfusionMatrix from "./components/ConfusionMatrix";
import FeatureImportance from "./components/FeatureImportance";
import {
  ApiError,
  downloadPredictions,
  getHealth,
  getMetrics,
  predict,
  type Health,
  type Metrics,
  type PredictionResponse,
} from "./api";

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [metricsError, setMetricsError] = useState<string | null>(null);

  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<PredictionResponse | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  // Load model status and the saved evaluation report once on start-up.
  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch((e: Error) => setHealthError(e.message));
    getMetrics()
      .then(setMetrics)
      .catch((e: Error) => setMetricsError(e.message));
  }, []);

  function handleFileChange(next: File | null) {
    setFile(next);
    setResult(null);
    setError(null);
  }

  async function handleAnalyze() {
    if (!file) return;
    setAnalyzing(true);
    setError(null);
    try {
      setResult(await predict(file));
    } catch (e) {
      setResult(null);
      setError(e instanceof ApiError ? e : new ApiError(String(e)));
    } finally {
      setAnalyzing(false);
    }
  }

  async function handleDownload() {
    if (!file) return;
    setDownloading(true);
    try {
      await downloadPredictions(file);
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(String(e)));
    } finally {
      setDownloading(false);
    }
  }

  return (
    <div className="console-shell">
      <ConsoleSidebar health={health} />
      <div className="console-workspace">
        <Header health={health} error={healthError} />
        <main className="console-main">
          <section className="console-hero" id="analysis">
            <div>
              <div className="eyebrow"><Radar size={13} /> Flow intelligence</div>
              <h2>Make traffic decisions with context, not just confidence.</h2>
              <p>
                Analyze CICFlowMeter-style traffic records, inspect per-flow decisions, and verify whether the uploaded batch resembles the model’s training environment.
              </p>
            </div>
            <div className="hero-meta" aria-label="Model capabilities">
              <div className="metric-chip"><span>Classifier</span>{health?.model_name ?? "Loading"}</div>
              <div className="metric-chip"><span>Reliability</span>{health?.reliability_active ? "Calibrated" : "Standard"}</div>
              <div className="metric-chip"><span>Shift gate</span>{health?.shift_gate_active ? "Active" : "Unavailable"}</div>
            </div>
          </section>
        {health && !health.model_loaded && (
          <Notice>
            No trained model was found. Run <code className="text-ink">python -m ml.train</code> from the project folder,
            then refresh this page.
          </Notice>
        )}

        <UploadPanel
          file={file}
          loading={analyzing}
          error={error}
          modelReady={Boolean(health?.model_loaded)}
          onFileChange={handleFileChange}
          onAnalyze={handleAnalyze}
        />

        {result && (
          <>
            <ShiftWarning shift={result.shift} warning={result.warning} />
            <SummaryCards result={result} />
            <div id="results"><ResultsTable result={result} downloading={downloading} onDownload={handleDownload} /></div>
          </>
        )}

        <div className="section-heading" id="evaluation">
          <div className="heading-icon"><BarChart3 size={16} /></div>
          <div>
            <h2>Model evaluation</h2>
            <p>Held-out test performance, training data profile, and model features.</p>
          </div>
        </div>

        {metrics ? (
          <>
            <ModelComparison metrics={metrics} />
            <div className="grid gap-6 lg:grid-cols-2">
              <ConfusionMatrix metrics={metrics} />
              <DatasetInfo metrics={metrics} />
            </div>
            <FeatureImportance metrics={metrics} />
          </>
        ) : (
          <Notice>{metricsError ?? "Loading evaluation report…"}</Notice>
        )}
          <footer className="footer">
            NetGuard AI · trained on CIC-IDS2017 (Canadian Institute for Cybersecurity, UNB)
          </footer>
        </main>
      </div>
    </div>
  );
}

function Notice({ children }: { children: React.ReactNode }) {
  return (
    <div className="console-notice">
      <Info size={16} className="mt-0.5 shrink-0 text-muted" />
      <p>{children}</p>
    </div>
  );
}
