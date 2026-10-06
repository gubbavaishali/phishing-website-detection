"use client";

import { useEffect, useState } from "react";
import Navbar from "@/components/Navbar";
import { getBenchmarkData } from "@/lib/api";
import type { BenchmarkData, BenchmarkMetrics } from "@/lib/types";

function MetricBadge({ value, label }: { value: number; label: string }) {
  const pct = Math.round(value * 100);
  const color =
    pct >= 95 ? "text-emerald-400" : pct >= 80 ? "text-yellow-400" : "text-red-400";
  return (
    <div className="flex flex-col items-center bg-gray-800 rounded-xl p-4 min-w-[90px]">
      <span className={`text-2xl font-bold ${color}`}>{pct}%</span>
      <span className="text-xs text-gray-400 mt-1 text-center">{label}</span>
    </div>
  );
}

function ModelCard({ name, m, isChampion }: { name: string; m: BenchmarkMetrics; isChampion: boolean }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
      <div className="flex items-center gap-3 mb-4">
        <h3 className="text-lg font-semibold text-white">{name}</h3>
        {isChampion && (
          <span className="bg-emerald-600/20 text-emerald-400 text-xs font-medium px-2.5 py-1 rounded-full border border-emerald-500/30">
            Champion
          </span>
        )}
      </div>
      <div className="flex flex-wrap gap-3">
        <MetricBadge value={m.accuracy} label="Accuracy" />
        <MetricBadge value={m.precision} label="Precision" />
        <MetricBadge value={m.recall} label="Recall" />
        <MetricBadge value={m.f1_score} label="F1 Score" />
        <MetricBadge value={m.roc_auc} label="ROC-AUC" />
      </div>
      <div className="mt-4 grid grid-cols-2 gap-4">
        <div>
          <p className="text-xs text-gray-500 mb-2 uppercase tracking-wider">Confusion Matrix</p>
          <div className="grid grid-cols-2 text-center text-sm rounded-lg overflow-hidden border border-gray-700">
            <div className="bg-emerald-900/30 p-3">
              <div className="text-emerald-400 font-bold text-lg">{m.confusion_matrix.true_negative}</div>
              <div className="text-gray-500 text-xs">TN</div>
            </div>
            <div className="bg-red-900/30 p-3">
              <div className="text-red-400 font-bold text-lg">{m.confusion_matrix.false_positive}</div>
              <div className="text-gray-500 text-xs">FP</div>
            </div>
            <div className="bg-red-900/30 p-3">
              <div className="text-red-400 font-bold text-lg">{m.confusion_matrix.false_negative}</div>
              <div className="text-gray-500 text-xs">FN</div>
            </div>
            <div className="bg-emerald-900/30 p-3">
              <div className="text-emerald-400 font-bold text-lg">{m.confusion_matrix.true_positive}</div>
              <div className="text-gray-500 text-xs">TP</div>
            </div>
          </div>
        </div>
        <div className="flex flex-col gap-2 justify-center">
          <div className="flex items-center justify-between bg-gray-800 rounded-lg px-3 py-2">
            <span className="text-xs text-gray-400">False Negative Rate</span>
            <span className={`text-sm font-bold ${m.false_negative_rate === 0 ? "text-emerald-400" : "text-red-400"}`}>
              {(m.false_negative_rate * 100).toFixed(1)}%
            </span>
          </div>
          <div className="flex items-center justify-between bg-gray-800 rounded-lg px-3 py-2">
            <span className="text-xs text-gray-400">False Positive Rate</span>
            <span className={`text-sm font-bold ${m.false_positive_rate === 0 ? "text-emerald-400" : "text-yellow-400"}`}>
              {(m.false_positive_rate * 100).toFixed(1)}%
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function BenchmarkPage() {
  const [data, setData] = useState<BenchmarkData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getBenchmarkData()
      .then(setData)
      .catch(() => setError("Could not load benchmark data. Is the backend running?"));
  }, []);

  if (error)
    return (
      <div className="min-h-screen bg-gray-950 text-white flex flex-col">
        <Navbar />
        <div className="flex-1 flex items-center justify-center text-red-400">{error}</div>
      </div>
    );

  if (!data)
    return (
      <div className="min-h-screen bg-gray-950 text-white flex flex-col">
        <Navbar />
        <div className="flex-1 flex items-center justify-center text-gray-400 animate-pulse">
          Loading benchmark data…
        </div>
      </div>
    );

  const { dataset_summary, model_comparisons, generalization_benchmark, feature_importances } = data;
  const maxImportance = feature_importances[0]?.importance ?? 1;

  return (
    <div className="min-h-screen bg-gray-950 text-white flex flex-col">
      <Navbar />
      <main className="flex-1 max-w-6xl mx-auto px-4 py-10 space-y-12">

        {/* Header */}
        <section>
          <h1 className="text-3xl font-bold text-white mb-1">Model Benchmark Report</h1>
          <p className="text-gray-400">
            Champion model:{" "}
            <span className="text-emerald-400 font-semibold">{data.champion_model}</span>
          </p>
        </section>

        {/* Dataset Summary */}
        <section>
          <h2 className="text-xl font-semibold text-white mb-4">Dataset Summary</h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: "Total Samples", value: dataset_summary.total_samples },
              { label: "Training Set", value: dataset_summary.train_samples },
              { label: "Test Set", value: dataset_summary.test_samples },
              {
                label: "Class Balance",
                value: `${dataset_summary.class_distribution.legitimate}L / ${dataset_summary.class_distribution.phishing}P`,
              },
            ].map(({ label, value }) => (
              <div key={label} className="bg-gray-800 rounded-xl p-4 text-center">
                <div className="text-2xl font-bold text-blue-400">{value}</div>
                <div className="text-xs text-gray-400 mt-1">{label}</div>
              </div>
            ))}
          </div>
        </section>

        {/* Model Comparison */}
        <section>
          <h2 className="text-xl font-semibold text-white mb-4">Model Comparison</h2>
          <div className="space-y-6">
            {Object.entries(model_comparisons).map(([name, m]) => (
              <ModelCard key={name} name={name} m={m} isChampion={name === data.champion_model} />
            ))}
          </div>
        </section>

        {/* Generalization Benchmark */}
        <section>
          <h2 className="text-xl font-semibold text-white mb-1">Generalization Benchmark</h2>
          <p className="text-gray-500 text-sm mb-4">
            {generalization_benchmark.total_samples} unseen attack patterns not present in training data
          </p>
          <div className="flex gap-4 mb-6">
            <MetricBadge value={generalization_benchmark.accuracy} label="Accuracy" />
            <MetricBadge value={generalization_benchmark.recall} label="Recall" />
          </div>
          <div className="space-y-2">
            {generalization_benchmark.sample_evaluations.map((ev, i) => (
              <div
                key={i}
                className={`flex items-start gap-3 rounded-xl p-4 border ${
                  ev.correct
                    ? "bg-emerald-900/10 border-emerald-800/40"
                    : "bg-red-900/10 border-red-800/40"
                }`}
              >
                <span className={`mt-0.5 text-lg ${ev.correct ? "text-emerald-400" : "text-red-400"}`}>
                  {ev.correct ? "✓" : "✗"}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-gray-300 mb-1">{ev.technique}</div>
                  <code className="text-xs text-gray-500 break-all">{ev.url}</code>
                </div>
                <div className="text-right flex-shrink-0">
                  <div className={`text-sm font-semibold ${ev.predicted === "phishing" ? "text-red-400" : "text-emerald-400"}`}>
                    {ev.predicted.toUpperCase()}
                  </div>
                  <div className="text-xs text-gray-500">{Math.round(ev.risk_probability * 100)}% prob</div>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Feature Importances */}
        <section>
          <h2 className="text-xl font-semibold text-white mb-4">Feature Importances (Top 15)</h2>
          <div className="space-y-2">
            {feature_importances.slice(0, 15).map((fi) => (
              <div key={fi.feature} className="flex items-center gap-3">
                <span className="text-xs text-gray-500 w-5 text-right">{fi.rank}</span>
                <span className="text-sm text-gray-300 w-44 truncate">{fi.feature}</span>
                <div className="flex-1 bg-gray-800 rounded-full h-2">
                  <div
                    className="bg-gradient-to-r from-blue-500 to-emerald-500 h-2 rounded-full"
                    style={{ width: `${(fi.importance / maxImportance) * 100}%` }}
                  />
                </div>
                <span className="text-xs text-gray-400 w-12 text-right">
                  {(fi.importance * 100).toFixed(1)}%
                </span>
              </div>
            ))}
          </div>
        </section>

      </main>
    </div>
  );
}
