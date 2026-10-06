/**
 * Centralized API client communicating with the authoritative Python FastAPI backend.
 */

import { AnalyzeUrlResponse, ScanHistoryItem, BenchmarkData, HealthStatus } from "./types";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export class ApiError extends Error {
  status: number;
  data: any;

  constructor(message: string, status: number, data?: any) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

export async function analyzeUrl(url: string, inspectHtml: boolean = true): Promise<AnalyzeUrlResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
    },
    body: JSON.stringify({
      url: url.trim(),
      inspect_html: inspectHtml,
    }),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    const message = errorData?.detail?.message || errorData?.message || `API analysis failed (${response.status})`;
    throw new ApiError(message, response.status, errorData);
  }

  return response.json();
}

export async function getScanHistory(limit: number = 20): Promise<ScanHistoryItem[]> {
  const response = await fetch(`${API_BASE_URL}/api/v1/history?limit=${limit}`, {
    cache: "no-store",
    headers: { "Accept": "application/json" }
  });

  if (!response.ok) {
    throw new ApiError(`Failed to fetch scan history (${response.status})`, response.status);
  }

  return response.json();
}

export async function getBenchmarkData(): Promise<BenchmarkData> {
  const response = await fetch(`${API_BASE_URL}/api/v1/benchmark`, {
    cache: "no-store",
    headers: { "Accept": "application/json" }
  });

  if (!response.ok) {
    throw new ApiError(`Failed to fetch benchmark data (${response.status})`, response.status);
  }

  return response.json();
}

export async function getHealthStatus(): Promise<HealthStatus> {
  const response = await fetch(`${API_BASE_URL}/api/v1/health`, {
    cache: "no-store",
    headers: { "Accept": "application/json" }
  });

  if (!response.ok) {
    throw new ApiError(`Backend health check failed (${response.status})`, response.status);
  }

  return response.json();
}
