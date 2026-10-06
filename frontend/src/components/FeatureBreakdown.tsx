"use client";

import { useState } from "react";
import { AnalyzeUrlResponse } from "@/lib/types";
import { Globe, Layers, AlertCircle, FileCode, Shield, CheckCircle2, XCircle } from "lucide-react";

interface FeatureBreakdownProps {
  data: AnalyzeUrlResponse;
}

export default function FeatureBreakdown({ data }: FeatureBreakdownProps) {
  const [activeTab, setActiveTab] = useState<"lexical" | "domain" | "brand" | "html" | "threat" | "ml">("lexical");

  const tabs = [
    { id: "lexical", label: "URL & Lexical", icon: Globe },
    { id: "domain", label: "Domain & DNS", icon: Layers },
    { id: "brand", label: "Brand Similarity", icon: AlertCircle },
    { id: "html", label: "HTML Metadata", icon: FileCode },
    { id: "threat", label: "Threat Feeds", icon: Shield },
    { id: "ml", label: "ML Attributions", icon: CheckCircle2 },
  ] as const;

  return (
    <div className="rounded-2xl bg-gray-900/60 border border-gray-800 overflow-hidden">
      {/* Tabs Header */}
      <div className="flex border-b border-gray-800 overflow-x-auto bg-gray-950/40">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-3.5 text-xs sm:text-sm font-medium whitespace-nowrap transition border-b-2 ${
                isActive
                  ? "border-blue-500 text-blue-400 bg-blue-500/5"
                  : "border-transparent text-gray-400 hover:text-gray-200 hover:bg-gray-800/30"
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab Contents */}
      <div className="p-6">
        {/* 1. Lexical Tab */}
        {activeTab === "lexical" && (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4">
            <MetricBox label="URL Length" value={data.features.url_length} unit="chars" />
            <MetricBox label="Host Length" value={data.features.hostname_length} unit="chars" />
            <MetricBox label="Path Length" value={data.features.path_length} unit="chars" />
            <MetricBox label="Dots Count" value={data.features.count_dots} />
            <MetricBox label="Hyphens Count" value={data.features.count_hyphens} />
            <MetricBox label="Digit Ratio" value={`${(data.features.digit_ratio * 100).toFixed(1)}%`} />
            <MetricBox label="IP as Host" value={data.features.has_ip === 1 ? "Yes" : "No"} alert={data.features.has_ip === 1} />
            <MetricBox label="HTTPS Enabled" value={data.features.is_https === 1 ? "Yes" : "No"} success={data.features.is_https === 1} />
            <MetricBox label="URL Shortener" value={data.features.is_shortened === 1 ? "Yes" : "No"} alert={data.features.is_shortened === 1} />
            <MetricBox label="Punycode / IDN" value={data.features.has_punycode === 1 ? "Detected" : "None"} alert={data.features.has_punycode === 1} />
            <MetricBox label="Keywords Found" value={data.features.suspicious_keyword_count} alert={data.features.suspicious_keyword_count > 0} />
            <MetricBox label="Double Slash in Path" value={data.features.double_slash_in_path === 1 ? "Yes" : "No"} alert={data.features.double_slash_in_path === 1} />
          </div>
        )}

        {/* 2. Domain & DNS Tab */}
        {activeTab === "domain" && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4">
              <MetricBox label="Registered Domain" value={data.domain_analysis.registered_domain || "N/A"} highlight />
              <MetricBox label="TLD (.suffix)" value={`.${data.domain_analysis.tld}` || "N/A"} alert={data.domain_analysis.tld_is_risky === 1} />
              <MetricBox label="Subdomain Levels" value={data.domain_analysis.subdomain_count} alert={data.domain_analysis.subdomain_count >= 3} />
              <MetricBox label="Domain Entropy" value={data.domain_analysis.domain_entropy} unit="bits" alert={data.domain_analysis.domain_entropy > 3.6} />
              <MetricBox label="Hyphen in Domain" value={data.domain_analysis.has_hyphen_in_domain === 1 ? "Present" : "None"} alert={data.domain_analysis.has_hyphen_in_domain === 1} />
              <MetricBox label="DNS Active" value={data.domain_analysis.dns_resolves ? "Resolves" : "Unresolved"} success={data.domain_analysis.dns_resolves} />
            </div>

            {data.domain_analysis.tld_is_risky === 1 && (
              <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>The top-level domain (.{data.domain_analysis.tld}) has a statistically elevated malicious registration index in cybersecurity reputation databases.</span>
              </div>
            )}
          </div>
        )}

        {/* 3. Brand Similarity Tab */}
        {activeTab === "brand" && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <MetricBox
                label="Target Institution"
                value={data.brand_analysis.matched_brand || "None Detected"}
                highlight={!!data.brand_analysis.matched_brand}
              />
              <MetricBox
                label="Similarity Ratio"
                value={`${(data.brand_analysis.similarity_score * 100).toFixed(0)}%`}
                alert={data.brand_analysis.similarity_score >= 0.75}
              />
              <MetricBox
                label="Technique"
                value={data.brand_analysis.technique}
                unit=""
                alert={data.brand_analysis.is_suspicious_brand_use}
              />
            </div>

            <div className="p-4 rounded-xl bg-gray-950/60 border border-gray-800 text-sm">
              <span className="text-gray-400 font-mono text-xs block mb-1">ANALYSIS DETAILS</span>
              <p className="text-gray-200">{data.brand_analysis.details}</p>
            </div>
          </div>
        )}

        {/* 4. HTML Metadata Tab */}
        {activeTab === "html" && (
          <div className="space-y-4">
            {!data.html_analysis.html_retrieved ? (
              <div className="p-4 rounded-xl bg-gray-950/60 border border-gray-800 text-sm text-gray-400 text-center">
                HTML metadata was not retrieved (remote host unreachable, SSRF-restricted destination, or HTML inspection disabled). The model evaluated URL lexical and domain features.
              </div>
            ) : (
              <>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <MetricBox
                    label="Password Input"
                    value={data.html_analysis.has_password_input === 1 ? "Present" : "None"}
                    alert={data.html_analysis.has_password_input === 1}
                  />
                  <MetricBox
                    label="Login Form"
                    value={data.html_analysis.has_login_form === 1 ? "Detected" : "None"}
                    alert={data.html_analysis.has_login_form === 1}
                  />
                  <MetricBox
                    label="Foreign Form Action"
                    value={data.html_analysis.external_form_action === 1 ? "Cross-Domain" : "Same-Domain"}
                    alert={data.html_analysis.external_form_action === 1}
                  />
                  <MetricBox
                    label="Hidden Iframes"
                    value={data.html_analysis.has_hidden_iframe === 1 ? "Detected" : "None"}
                    alert={data.html_analysis.has_hidden_iframe === 1}
                  />
                  <MetricBox label="Script Tags" value={data.html_analysis.script_count} />
                  <MetricBox
                    label="External Asset Ratio"
                    value={`${(data.html_analysis.external_resources_ratio * 100).toFixed(0)}%`}
                    alert={data.html_analysis.external_resources_ratio > 0.70}
                  />
                </div>

                {data.html_analysis.suspicious_html_indicators.length > 0 && (
                  <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/20 text-red-300 text-xs space-y-1">
                    <span className="font-semibold block">Suspicious HTML Indicators:</span>
                    {data.html_analysis.suspicious_html_indicators.map((ind, i) => (
                      <div key={i} className="flex items-center gap-1.5">
                        <AlertCircle className="w-3.5 h-3.5 shrink-0" />
                        <span>{ind}</span>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* 5. Threat Feeds Tab */}
        {activeTab === "threat" && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <MetricBox
                label="Threat Feed Status"
                value={data.threat_intelligence.threat_detected ? "MALICIOUS LISTING" : "CLEAN"}
                alert={data.threat_intelligence.threat_detected}
                success={!data.threat_intelligence.threat_detected}
              />
              <MetricBox
                label="Reputation Score"
                value={data.threat_intelligence.reputation_score.toFixed(2)}
                alert={data.threat_intelligence.reputation_score > 0}
              />
            </div>

            <div className="space-y-2">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block">Feed Cross-Check Sources:</span>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {Object.entries(data.threat_intelligence.sources).map(([key, src]) => (
                  <div key={key} className="p-3 rounded-xl bg-gray-950/60 border border-gray-800 text-xs">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-gray-300 capitalize">{key.replace(/_/g, " ")}</span>
                      {src.status === "flagged" ? (
                        <span className="text-red-400 font-semibold flex items-center gap-1">
                          <XCircle className="w-3.5 h-3.5" /> Flagged
                        </span>
                      ) : src.status === "clean" ? (
                        <span className="text-emerald-400 font-semibold flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Clean
                        </span>
                      ) : (
                        <span className="text-gray-500">Unconfigured</span>
                      )}
                    </div>
                    <p className="text-gray-400 text-[11px]">{src.details}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* 6. ML Attributions Tab */}
        {activeTab === "ml" && (
          <div className="space-y-3">
            <p className="text-xs text-gray-400">
              SHAP-inspired feature attribution: shows how each prominent feature influenced the model decision towards phishing or legitimate for this URL.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-500">
                    <th className="py-2 px-3">Feature Name</th>
                    <th className="py-2 px-3">Observed Value</th>
                    <th className="py-2 px-3">Global Weight</th>
                    <th className="py-2 px-3 text-right">Directional Influence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60">
                  {data.feature_contributions.map((feat, idx) => (
                    <tr key={idx} className="hover:bg-gray-800/30">
                      <td className="py-2 px-3 font-semibold text-gray-300">{feat.feature}</td>
                      <td className="py-2 px-3 text-gray-400">{feat.value}</td>
                      <td className="py-2 px-3 text-blue-400">{(feat.importance_weight * 100).toFixed(1)}%</td>
                      <td className="py-2 px-3 text-right">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-sans font-medium ${
                            feat.directional_effect === "Elevates Risk"
                              ? "bg-red-500/10 text-red-400 border border-red-500/20"
                              : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          }`}
                        >
                          {feat.directional_effect}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function MetricBox({
  label,
  value,
  unit,
  alert,
  success,
  highlight,
}: {
  label: string;
  value: any;
  unit?: string;
  alert?: boolean;
  success?: boolean;
  highlight?: boolean;
}) {
  return (
    <div
      className={`p-3 rounded-xl border text-xs ${
        alert
          ? "bg-red-500/5 border-red-500/30"
          : success
          ? "bg-emerald-500/5 border-emerald-500/30"
          : highlight
          ? "bg-blue-500/5 border-blue-500/30"
          : "bg-gray-950/40 border-gray-800/80"
      }`}
    >
      <span className="text-gray-400 block mb-1 text-[11px] truncate">{label}</span>
      <div className="flex items-baseline gap-1 font-mono">
        <span
          className={`text-sm font-bold truncate ${
            alert ? "text-red-400" : success ? "text-emerald-400" : highlight ? "text-blue-400" : "text-gray-200"
          }`}
        >
          {String(value)}
        </span>
        {unit && <span className="text-[10px] text-gray-500">{unit}</span>}
      </div>
    </div>
  );
}
