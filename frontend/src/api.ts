// Types and helper functions for talking to the FastAPI backend.
// All requests use relative /api URLs: Vite proxies them in development,
// and FastAPI serves the built frontend on the same origin in production.

export type ClassName = "Benign" | "Malicious";

export interface Health {
  status: string;
  model_loaded: boolean;
  model_name?: string;
  trained_at?: string;
  feature_count?: number;
  error?: string;
}

export interface PredictionRow {
  row: number;
  values: Record<string, number | null>;
  prediction: ClassName;
  malicious_probability: number;
  actual: ClassName | null;
}

export interface PredictionResponse {
  filename: string;
  model_name: string;
  summary: { total: number; benign: number; malicious: number; malicious_ratio: number };
  evaluation: {
    accuracy: number;
    correct: number;
    actual_malicious: number;
    actual_benign: number;
  } | null;
  display_columns: string[];
  rows: PredictionRow[];
  rows_truncated: boolean;
}

export interface ModelResult {
  name: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  validation_f1: number;
  train_seconds: number;
  confusion_matrix: [[number, number], [number, number]];
}

export interface Metrics {
  generated_at: string;
  best_model: string;
  selection_metric: string;
  dataset: {
    source: string;
    files: string[];
    raw_rows: number;
    duplicates_removed: number;
    rows_after_cleaning: number;
    rows_used: number;
    sampled: boolean;
    class_counts: Record<ClassName, number>;
    attack_counts: Record<string, number>;
  };
  split: { train: number; validation: number; test: number };
  features: { count: number; names: string[]; dropped_constant: string[] };
  models: ModelResult[];
  feature_importances: { feature: string; importance: number }[];
}

/** Error thrown for non-2xx responses; `columns` lists offending CSV columns. */
export class ApiError extends Error {
  columns: string[];
  constructor(message: string, columns: string[] = []) {
    super(message);
    this.columns = columns;
  }
}

async function request(url: string, init?: RequestInit): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(url, init);
  } catch {
    throw new ApiError("Cannot reach the backend. Is the FastAPI server running on port 8000?");
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    let columns: string[] = [];
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
      else if (body.detail?.message) {
        message = body.detail.message;
        columns = body.detail.columns ?? [];
      }
    } catch {
      // Not JSON: usually the Vite proxy reporting that the backend is down.
      if (response.status >= 500) message = "Backend unavailable. Start it with: uvicorn backend.app.main:app";
    }
    throw new ApiError(message, columns);
  }
  return response;
}

export async function getHealth(): Promise<Health> {
  return (await request("/api/health")).json();
}

export async function getMetrics(): Promise<Metrics> {
  return (await request("/api/metrics")).json();
}

function formData(file: File): FormData {
  const data = new FormData();
  data.append("file", file);
  return data;
}

export async function predict(file: File): Promise<PredictionResponse> {
  const response = await request("/api/predict", { method: "POST", body: formData(file) });
  return response.json();
}

/** Ask the backend for the full CSV with predictions and trigger a browser download. */
export async function downloadPredictions(file: File): Promise<void> {
  const response = await request("/api/predict/download", { method: "POST", body: formData(file) });
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = file.name.replace(/\.csv$/i, "") + "_predictions.csv";
  link.click();
  URL.revokeObjectURL(url);
}
