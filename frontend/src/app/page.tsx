"use client";

import { useState } from "react";
import UrlInputForm from "@/components/UrlInputForm";
import ResultCard from "@/components/ResultCard";
import { analyzeUrl, ApiError } from "@/lib/api";
import { AnalyzeUrlResponse } from "@/lib/types";
import { Shield, Cpu, Lock, CheckCircle2, AlertCircle, RefreshCw } from "lucide-react";

export default function Home() {
  const [result, setResult] = useState<AnalyzeUrlResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadingStep, setLoadingStep] = useState<string>("");

  const handleAnalyze = async (url: string, inspectHtml: boolean) => {
    setIsLoading(true);
    setError(null);
    setLoadingStep("Validating URL syntax & sanitizing parameters...");

    try {
      const stepTimer1 = setTimeout(() => {
        setLoadingStep("Extracting 37 multi-signal features (Lexical, Domain, TLD)...");
      }, 500);

      const stepTimer2 = setTimeout(() => {
        setLoadingStep("Running Random Forest inference & cross-referencing threat feeds...");
      }, 1100);

      const data = await analyzeUrl(url, inspectHtml);
      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);

      setResult(data);
    } catch (err: any) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Unable to reach detection backend. Please ensure the Python API server is running on port 8000.");
      }
      setResult(null);
    } finally {
      setIsLoading(false);
      setLoadingStep("");
    }
  };

  return (
    <div className="space-y-10 py-4">
      {/* Hero Header */}
      <div className="text-center max-w-3xl mx-auto space-y-4">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold">
          <Shield className="w-3.5 h-3.5" />
          Multi-Signal Cybersecurity Phishing Defense
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight leading-tight">
          Explainable Phishing Website Detection
        </h1>
        <p className="text-sm sm:text-base text-gray-300 leading-relaxed">
          Combines URL lexical syntax, domain infrastructure, safe HTML metadata, and brand typosquatting detection with an explainable Random Forest classifier.
        </p>
      </div>

      {/* URL Input Form */}
      <UrlInputForm onAnalyze={handleAnalyze} isLoading={isLoading} />

      {/* Progressive Loading Indicator */}
      {isLoading && (
        <div className="w-full max-w-md mx-auto p-6 rounded-2xl bg-gray-900/80 border border-gray-800 text-center space-y-3 shadow-xl backdrop-blur-md animate-pulse">
          <RefreshCw className="w-8 h-8 text-blue-400 animate-spin mx-auto" />
          <div className="space-y-1">
            <span className="font-semibold text-sm text-white">Analyzing Target URL</span>
            <p className="text-xs text-gray-400 font-mono">{loadingStep}</p>
          </div>
        </div>
      )}

      {/* Error Card */}
      {error && !isLoading && (
        <div className="w-full max-w-2xl mx-auto p-4 rounded-2xl bg-red-950/40 border border-red-500/30 flex items-start gap-3 text-sm text-red-300">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold block">Analysis Failed</span>
            <p className="text-xs text-gray-300">{error}</p>
          </div>
        </div>
      )}

      {/* Result Presentation */}
      {result && !isLoading && <ResultCard data={result} />}

      {/* Initial Explanatory Architecture Cards (visible when no result yet) */}
      {!result && !isLoading && !error && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-5xl mx-auto pt-8 border-t border-gray-800/60">
          <FeatureCard
            icon={Cpu}
            title="Explainable Machine Learning"
            description="Trained on 37 deterministic multi-signal features with full feature attribution and probability estimation."
          />
          <FeatureCard
            icon={Lock}
            title="Brand & Typosquatting Defense"
            description="Homoglyph-aware Levenshtein analysis detecting combosquatting and deceptive subdomains targeting major institutions."
          />
          <FeatureCard
            icon={Shield}
            title="SSRF-Protected HTML Inspection"
            description="Strictly enforces network isolation, blocking loopback, private RFC 1918, and cloud metadata targets during webpage retrieval."
          />
        </div>
      )}
    </div>
  );
}

function FeatureCard({
  icon: Icon,
  title,
  description,
}: {
  icon: any;
  title: string;
  description: string;
}) {
  return (
    <div className="p-6 rounded-2xl bg-gray-900/40 border border-gray-800/80 space-y-3 hover:border-gray-700 transition">
      <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
        <Icon className="w-5 h-5" />
      </div>
      <h3 className="font-bold text-white text-base">{title}</h3>
      <p className="text-xs text-gray-300 leading-relaxed">{description}</p>
    </div>
  );
}
