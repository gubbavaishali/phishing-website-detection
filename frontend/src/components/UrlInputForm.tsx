"use client";

import { useState } from "react";
import { Search, Globe, ShieldAlert, CheckCircle2, ArrowRight, Loader2, Sparkles } from "lucide-react";

interface UrlInputFormProps {
  onAnalyze: (url: string, inspectHtml: boolean) => Promise<void>;
  isLoading: boolean;
}

const PRESET_SAMPLES = [
  {
    label: "PayPal Combosquat",
    url: "https://paypal-account-verification-alert.com/webscr",
    category: "Combosquatting",
  },
  {
    label: "IP Host Phishing",
    url: "http://192.168.1.105/bank/signin",
    category: "IP-in-URL",
  },
  {
    label: "Subdomain Deception",
    url: "http://netflix.com.profile-update.buzz/signin",
    category: "Subdomain Mimicry",
  },
  {
    label: "Legitimate (MDN)",
    url: "https://developer.mozilla.org/en-US/",
    category: "Benign",
  },
];

export default function UrlInputForm({ onAnalyze, isLoading }: UrlInputFormProps) {
  const [url, setUrl] = useState("");
  const [inspectHtml, setInspectHtml] = useState(true);
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      setValidationError("Please enter a website URL to analyze.");
      return;
    }
    if (trimmed.length < 3) {
      setValidationError("URL is too short.");
      return;
    }
    setValidationError(null);
    await onAnalyze(trimmed, inspectHtml);
  };

  const handleSelectPreset = (sampleUrl: string) => {
    setUrl(sampleUrl);
    setValidationError(null);
  };

  return (
    <div className="w-full max-w-4xl mx-auto">
      <form onSubmit={handleSubmit} className="relative">
        <div className="flex flex-col sm:flex-row items-stretch gap-2 p-2 rounded-2xl bg-gray-900/90 border border-gray-800 shadow-2xl backdrop-blur-xl focus-within:border-blue-500/50 transition">
          <div className="relative flex-1 flex items-center">
            <Globe className="absolute left-4 w-5 h-5 text-gray-400 pointer-events-none" />
            <input
              type="text"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (validationError) setValidationError(null);
              }}
              placeholder="Enter website URL to analyze (e.g., https://example.com/login)..."
              disabled={isLoading}
              className="w-full pl-12 pr-4 py-3.5 bg-transparent text-white placeholder-gray-500 focus:outline-none text-base rounded-xl font-mono text-sm"
              autoComplete="off"
              spellCheck="false"
            />
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-medium shadow-lg shadow-blue-600/20 disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <span>Analyze URL</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>

        {/* Validation error display */}
        {validationError && (
          <p className="mt-2 text-sm text-red-400 flex items-center gap-1.5 px-3">
            <ShieldAlert className="w-4 h-4" />
            {validationError}
          </p>
        )}

        {/* Options and preset buttons */}
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-xs text-gray-400 px-1">
          {/* Preset Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold text-gray-500 uppercase tracking-wider text-[10px] flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-blue-400" /> Test Presets:
            </span>
            {PRESET_SAMPLES.map((sample) => (
              <button
                key={sample.label}
                type="button"
                onClick={() => handleSelectPreset(sample.url)}
                className="px-2.5 py-1 rounded-lg bg-gray-800/80 hover:bg-gray-700/80 text-gray-300 hover:text-white border border-gray-700/50 transition font-sans"
              >
                {sample.label}
              </button>
            ))}
          </div>

          {/* HTML inspection toggle */}
          <label className="flex items-center gap-2 cursor-pointer select-none ml-auto text-gray-400 hover:text-gray-300">
            <input
              type="checkbox"
              checked={inspectHtml}
              onChange={(e) => setInspectHtml(e.target.checked)}
              className="w-3.5 h-3.5 rounded border-gray-700 bg-gray-800 text-blue-600 focus:ring-0 cursor-pointer"
            />
            <span>Safe HTML Metadata Inspection (SSRF-Protected)</span>
          </label>
        </div>
      </form>
    </div>
  );
}
