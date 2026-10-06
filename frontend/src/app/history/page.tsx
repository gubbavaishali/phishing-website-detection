"use client";

import { useEffect, useState } from "react";
import { getScanHistory } from "@/lib/api";
import { ScanHistoryItem } from "@/lib/types";
import { Database, ShieldAlert, ShieldCheck, AlertTriangle, Clock, RefreshCw, BarChart2 } from "lucide-react";

export default function HistoryPage() {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHistory = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await getScanHistory(50);
      setHistory(data);
    } catch (err: any) {
      setError("Unable to load scan history. Backend database may be offline or uninitialized.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const totalScans = history.length;
  const phishingCount = history.filter((s) => s.classification === "phishing").length;
  const suspiciousCount = history.filter((s) => s.classification === "suspicious").length;
  const legitCount = history.filter((s) => s.classification === "legitimate").length;
  const avgRisk = totalScans > 0 ? (history.reduce((acc, s) => acc + s.risk_score, 0) / totalScans).toFixed(1) : "0";

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white flex items-center gap-3">
            <Database className="w-7 h-7 text-blue-400" />
            Scan History &amp; Persistent Records
          </h1>
          <p className="text-xs sm:text-sm text-gray-400 mt-1">
            Persisted scans in Supabase PostgreSQL / Local Durable Store.
          </p>
        </div>

        <button
          onClick={fetchHistory}
          disabled={isLoading}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium border border-gray-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Aggregate Stats Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard label="Total Scans" value={totalScans} icon={BarChart2} color="text-blue-400" />
        <StatCard label="Phishing Detected" value={phishingCount} icon={ShieldAlert} color="text-red-400" />
        <StatCard label="Suspicious Cases" value={suspiciousCount} icon={AlertTriangle} color="text-amber-400" />
        <StatCard label="Verified Legitimate" value={legitCount} icon={ShieldCheck} color="text-emerald-400" />
      </div>

      {/* Table */}
      <div className="rounded-2xl bg-gray-900/60 border border-gray-800 overflow-hidden shadow-xl">
        <div className="p-4 sm:p-6 border-b border-gray-800 flex items-center justify-between">
          <span className="font-bold text-white text-sm">Recent Audit Log</span>
          <span className="text-xs text-gray-400 font-mono">Showing {history.length} records</span>
        </div>

        {isLoading ? (
          <div className="p-12 text-center text-gray-400 text-sm">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto text-blue-400 mb-2" />
            Loading scan history...
          </div>
        ) : error ? (
          <div className="p-8 text-center text-red-400 text-sm">{error}</div>
        ) : history.length === 0 ? (
          <div className="p-12 text-center text-gray-400 text-sm space-y-2">
            <p>No scans recorded yet.</p>
            <p className="text-xs text-gray-500">Run a URL scan from the home page to populate persistent records.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs sm:text-sm">
              <thead className="bg-gray-950/60 text-gray-400 font-mono text-[11px] uppercase border-b border-gray-800">
                <tr>
                  <th className="py-3 px-4">Target URL</th>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Key Signals</th>
                  <th className="py-3 px-4 text-right">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {history.map((item) => (
                  <tr key={item.id} className="hover:bg-gray-800/40 transition font-sans">
                    <td className="py-3.5 px-4 max-w-xs truncate font-mono text-xs text-gray-200" title={item.normalized_url}>
                      {item.normalized_url}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span
                        className={`px-2.5 py-1 rounded-full text-[11px] font-semibold uppercase tracking-wider border ${
                          item.classification === "phishing"
                            ? "bg-red-500/10 text-red-400 border-red-500/30"
                            : item.classification === "suspicious"
                            ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                            : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                        }`}
                      >
                        {item.classification}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2 font-mono">
                        <span className="font-bold text-white">{item.risk_score}</span>
                        <div className="w-16 h-1.5 rounded-full bg-gray-800 overflow-hidden">
                          <div
                            className={`h-full ${
                              item.risk_score >= 80
                                ? "bg-red-500"
                                : item.risk_score >= 60
                                ? "bg-orange-500"
                                : item.risk_score >= 30
                                ? "bg-amber-500"
                                : "bg-emerald-500"
                            }`}
                            style={{ width: `${item.risk_score}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-xs text-gray-400 max-w-sm truncate">
                      {item.reasons && item.reasons.length > 0 ? item.reasons.join(", ") : "Standard profile"}
                    </td>
                    <td className="py-3.5 px-4 text-right font-mono text-[11px] text-gray-400 whitespace-nowrap">
                      {new Date(item.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, icon: Icon, color }: { label: string; value: any; icon: any; color: string }) {
  return (
    <div className="p-4 rounded-2xl bg-gray-900/60 border border-gray-800 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-400 font-medium">{label}</span>
        <Icon className={`w-4 h-4 ${color}`} />
      </div>
      <div className="text-2xl font-bold font-mono text-white">{value}</div>
    </div>
  );
}
