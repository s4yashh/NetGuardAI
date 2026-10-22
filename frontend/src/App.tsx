import { useEffect, useState } from "react";
import { BarChart3, Info } from "lucide-react";
import Header from "./components/Header";
import UploadPanel from "./components/UploadPanel";
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
    <div className="min-h-screen">
      <Header health={health} error={healthError} />

      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6">
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
            <SummaryCards result={result} />
            <ResultsTable result={result} downloading={downloading} onDownload={handleDownload} />
          </>
        )}

        <div className="flex items-center gap-2 pt-2">
          <BarChart3 size={18} className="text-muted" />
          <h2 className="text-sm font-semibold uppercase tracking-wide text-ink-2">Model evaluation</h2>
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
      </main>

      <footer className="mx-auto max-w-7xl px-4 pb-8 text-xs text-muted sm:px-6">
        NetGuard AI · trained on the CIC-IDS2017 dataset (Canadian Institute for Cybersecurity, UNB)
      </footer>
    </div>
  );
}

function Notice({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2 rounded-xl border border-line bg-card px-5 py-4 text-sm text-ink-2">
      <Info size={16} className="mt-0.5 shrink-0 text-muted" />
      <p>{children}</p>
    </div>
  );
}
