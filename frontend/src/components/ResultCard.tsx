"use client";

import { useState } from "react";
import { AnalyzeUrlResponse } from "@/lib/types";
import RiskGauge from "./RiskGauge";
import FeatureBreakdown from "./FeatureBreakdown";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Info,
  CheckCircle2,
  Clock,
  Layers,
  Sparkles,
} from "lucide-react";

interface ResultCardProps {
  data: AnalyzeUrlResponse;
}

export default function ResultCard({ data }: ResultCardProps) {
  const [showDetailedReasons, setShowDetailedReasons] = useState(false);

  const isPhishing = data.classification === "phishing";
  const isSuspicious = data.classification === "suspicious";

  const getStatusTheme = () => {
    if (isPhishing) {
      return {
        bg: "from-red-950/40 via-gray-900 to-gray-900",
        border: "border-red-500/30",
        accent: "text-red-400",
        badgeBg: "bg-red-500/10 text-red-400 border-red-500/30",
        icon: ShieldAlert,
      };
    }
    if (isSuspicious) {
      return {
        bg: "from-amber-950/40 via-gray-900 to-gray-900",
        border: "border-amber-500/30",
        accent: "text-amber-400",
        badgeBg: "bg-amber-500/10 text-amber-400 border-amber-500/30",
        icon: AlertTriangle,
      };
    }
    return {
      bg: "from-emerald-950/40 via-gray-900 to-gray-900",
      border: "border-emerald-500/30",
      accent: "text-emerald-400",
      badgeBg: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
      icon: ShieldCheck,
    };
  };

  const theme = getStatusTheme();
  const StatusIcon = theme.icon;

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Top Banner Card */}
      <div
        className={`rounded-3xl bg-gradient-to-b ${theme.bg} border ${theme.border} p-6 sm:p-8 shadow-2xl backdrop-blur-xl relative overflow-hidden`}
      >
        {/* Subtle background glow */}
        <div
          className={`absolute -top-24 -right-24 w-72 h-72 rounded-full blur-3xl opacity-20 pointer-events-none ${
            isPhishing ? "bg-red-500" : isSuspicious ? "bg-amber-500" : "bg-emerald-500"
          }`}
        />

        <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
          {/* Left Column: Classification & Highlights */}
          <div className="md:col-span-8 space-y-4">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${theme.badgeBg}`}>
                {data.classification_label}
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-gray-800/80 text-gray-300 border border-gray-700/60">
                Confidence: <strong className="text-white">{data.confidence_level}</strong> ({(data.confidence * 100).toFixed(0)}%)
              </span>
            </div>

            {/* Target URL */}
            <div className="space-y-1">
              <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider block">
                Analyzed URL
              </span>
              <p className="text-sm sm:text-base font-mono font-medium text-white break-all flex items-center gap-2">
                <span className="truncate">{data.normalized_url}</span>
              </p>
            </div>

            {/* Summary Reasons */}
            <div className="space-y-2 pt-2">
              <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-blue-400" />
                Primary Detection Factors
              </span>
              <ul className="space-y-1.5">
                {data.reasons.map((reason, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-xs sm:text-sm text-gray-200">
                    <span className={`mt-0.5 font-bold ${theme.accent}`}>•</span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Right Column: Risk Gauge Dial */}
          <div className="md:col-span-4 flex flex-col items-center justify-center border-t md:border-t-0 md:border-l border-gray-800/80 pt-4 md:pt-0">
            <RiskGauge score={data.risk_score} severity={data.severity_tier} />
          </div>
        </div>

        {/* Brand Alert Banner (if brand deception detected) */}
        {data.brand_analysis.is_suspicious_brand_use && (
          <div className="mt-6 p-4 rounded-2xl bg-red-950/40 border border-red-500/30 flex items-start gap-3">
            <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div className="text-xs sm:text-sm space-y-1">
              <span className="font-bold text-red-300 block">
                Deceptive Brand Impersonation Detected ({data.brand_analysis.matched_brand})
              </span>
              <p className="text-gray-300">{data.brand_analysis.details}</p>
            </div>
          </div>
        )}
      </div>

      {/* Detailed Analysis Breakdown Tabs */}
      <FeatureBreakdown data={data} />

      {/* Detailed Explanation Accordion */}
      <div className="rounded-2xl bg-gray-900/60 border border-gray-800 overflow-hidden">
        <button
          onClick={() => setShowDetailedReasons(!showDetailedReasons)}
          className="w-full px-6 py-4 flex items-center justify-between text-left text-sm font-semibold text-gray-300 hover:text-white hover:bg-gray-800/30 transition"
        >
          <span className="flex items-center gap-2">
            <Info className="w-4 h-4 text-blue-400" />
            <span>Comprehensive Forensic Findings ({data.detailed_reasons.length} Signals)</span>
          </span>
          {showDetailedReasons ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>

        {showDetailedReasons && (
          <div className="p-6 border-t border-gray-800 space-y-3">
            {data.detailed_reasons.map((r, i) => (
              <div
                key={i}
                className="p-3.5 rounded-xl bg-gray-950/60 border border-gray-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                        r.severity === "CRITICAL"
                          ? "bg-red-500/20 text-red-400 border border-red-500/30"
                          : r.severity === "HIGH"
                          ? "bg-orange-500/20 text-orange-400 border border-orange-500/30"
                          : r.severity === "MEDIUM"
                          ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                          : r.severity === "POSITIVE"
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                          : "bg-gray-800 text-gray-300"
                      }`}
                    >
                      {r.severity}
                    </span>
                    <span className="font-semibold text-white">{r.title}</span>
                  </div>
                  <p className="text-gray-300">{r.description}</p>
                </div>
                <span className="text-[11px] font-mono text-gray-400 shrink-0 bg-gray-900/80 px-2.5 py-1 rounded-lg border border-gray-800">
                  {r.impact}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Footer Metadata & Disclaimer */}
      <div className="p-4 rounded-2xl bg-gray-950/40 border border-gray-800/60 text-[11px] text-gray-400 space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
          <span>Scan ID: <strong className="text-gray-300">{data.scan_id.slice(0, 8)}</strong></span>
          <span>Model Version: <strong className="text-gray-300">v{data.model_version}</strong></span>
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3 text-gray-500" />
            {new Date(data.scanned_at).toLocaleString()}
          </span>
        </div>
        <p className="text-gray-500 italic pt-1 border-t border-gray-800/40">
          * {data.disclaimer}
        </p>
      </div>
    </div>
  );
}
