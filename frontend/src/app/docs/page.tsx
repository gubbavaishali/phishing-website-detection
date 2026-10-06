import Navbar from "@/components/Navbar";

const Section = ({ title, children }: { title: string; children: React.ReactNode }) => (
  <section className="space-y-3">
    <h2 className="text-xl font-semibold text-white border-b border-gray-800 pb-2">{title}</h2>
    {children}
  </section>
);

const Tag = ({ children, color = "blue" }: { children: React.ReactNode; color?: string }) => {
  const colors: Record<string, string> = {
    blue: "bg-blue-900/30 text-blue-400 border-blue-700/40",
    emerald: "bg-emerald-900/30 text-emerald-400 border-emerald-700/40",
    yellow: "bg-yellow-900/30 text-yellow-400 border-yellow-700/40",
    red: "bg-red-900/30 text-red-400 border-red-700/40",
    purple: "bg-purple-900/30 text-purple-400 border-purple-700/40",
  };
  return (
    <span className={`inline-block text-xs font-medium px-2.5 py-1 rounded-full border ${colors[color] || colors.blue}`}>
      {children}
    </span>
  );
};

const apiRows = [
  {
    method: "GET",
    path: "/api/v1/health",
    desc: "Check API liveness, model load status, and database connectivity.",
    auth: false,
    color: "emerald",
  },
  {
    method: "POST",
    path: "/api/v1/analyze",
    desc: 'Analyze a URL for phishing. Body: {"url":"…","inspect_html":true}',
    auth: false,
    color: "blue",
  },
  {
    method: "GET",
    path: "/api/v1/history",
    desc: "Retrieve paginated scan history. Query params: limit, page.",
    auth: false,
    color: "emerald",
  },
  {
    method: "GET",
    path: "/api/v1/history/stats",
    desc: "Aggregate statistics: total scans, phishing count, avg risk score.",
    auth: false,
    color: "emerald",
  },
  {
    method: "GET",
    path: "/api/v1/benchmark",
    desc: "Full ML benchmark report with confusion matrices and generalization results.",
    auth: false,
    color: "emerald",
  },
];

const features = [
  {
    title: "37-Feature URL Extractor",
    desc: "Extracts structural, lexical, and behavioral URL features including length ratios, entropy, digit content, special characters, TLD risk, and more.",
    tag: "Core ML",
    color: "blue",
  },
  {
    title: "Pure-NumPy ML Models",
    desc: "Random Forest, Gradient Boosting, and Logistic Regression implemented from scratch without scikit-learn. Avoids Windows Smart App Control DLL blocks.",
    tag: "ML Engine",
    color: "purple",
  },
  {
    title: "Brand Similarity Engine",
    desc: "Detects combosquatting, typosquatting (homoglyph, Levenshtein), subdomain deception, and punycode homograph attacks across 30+ major brands.",
    tag: "Threat Detection",
    color: "red",
  },
  {
    title: "SSRF Protection Layer",
    desc: "Blocks fetching of loopback, RFC 1918 private ranges, link-local, and cloud metadata endpoints before any HTTP call is made.",
    tag: "Security",
    color: "yellow",
  },
  {
    title: "HTML Analysis",
    desc: "Safely parses HTML with BeautifulSoup4 to detect password inputs, login forms, external form actions, hidden iframes, and external resource ratios.",
    tag: "Content Analysis",
    color: "blue",
  },
  {
    title: "Explainability Engine",
    desc: "Converts raw feature values and ML probability into human-readable reasons with severity tiers: critical, high, medium, low.",
    tag: "Explainability",
    color: "emerald",
  },
  {
    title: "Risk Scoring (0-100)",
    desc: "Weighted ensemble combining ML probability, rule-based signals, brand deception, threat intel, and HTML analysis into a calibrated 0–100 risk score.",
    tag: "Scoring",
    color: "purple",
  },
  {
    title: "Scan History & Persistence",
    desc: "Every scan is persisted to Supabase (when configured) or a local SQLite fallback. Queryable via paginated REST endpoints.",
    tag: "Database",
    color: "blue",
  },
  {
    title: "Threat Intelligence Stub",
    desc: "Framework for querying Google Safe Browsing, VirusTotal, and PhishTank. Currently returns stub data — connect real API keys to activate.",
    tag: "P1 — Needs Keys",
    color: "yellow",
  },
];

const threatApis = [
  {
    name: "Google Safe Browsing",
    tier: "Free — 10,000 QPS",
    envKey: "GOOGLE_SAFE_BROWSING_API_KEY",
    url: "https://developers.google.com/safe-browsing/v4/get-started",
    desc: "Real-time reputation check against Google's phishing/malware URL database.",
  },
  {
    name: "VirusTotal",
    tier: "Free — 4 req/min",
    envKey: "VIRUSTOTAL_API_KEY",
    url: "https://www.virustotal.com/gui/join-us",
    desc: "Aggregated verdict from 70+ antivirus and URL reputation engines.",
  },
  {
    name: "Supabase",
    tier: "Free tier available",
    envKey: "SUPABASE_URL + SUPABASE_KEY",
    url: "https://supabase.com",
    desc: "Cloud PostgreSQL for persistent scan history. Currently using SQLite fallback.",
  },
];

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-gray-950 text-white flex flex-col">
      <Navbar />
      <main className="flex-1 max-w-4xl mx-auto px-4 py-10 space-y-12">

        {/* Header */}
        <section>
          <h1 className="text-3xl font-bold text-white mb-2">Documentation</h1>
          <p className="text-gray-400 leading-relaxed">
            Technical reference for the Phishing Detection API. Built with FastAPI + pure-NumPy ML +
            Next.js. All endpoints are unauthenticated for demo use.
          </p>
        </section>

        {/* API Endpoints */}
        <Section title="API Endpoints">
          <p className="text-gray-500 text-sm">Base URL: <code className="text-blue-400">http://localhost:8000</code></p>
          <div className="space-y-3 mt-3">
            {apiRows.map((r) => (
              <div key={r.path} className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex gap-4 items-start">
                <Tag color={r.color === "emerald" ? "emerald" : "blue"}>
                  {r.method}
                </Tag>
                <div className="flex-1">
                  <code className="text-sm text-white font-mono">{r.path}</code>
                  <p className="text-gray-400 text-sm mt-1">{r.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </Section>

        {/* POST /analyze request/response */}
        <Section title="POST /api/v1/analyze — Request & Response">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-4">
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Request Body (JSON)</p>
              <pre className="text-sm text-green-300 font-mono overflow-x-auto">
{`{
  "url": "https://paypal.com.account-update.xyz/login",
  "inspect_html": false
}`}
              </pre>
            </div>
            <div>
              <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Response (200 OK)</p>
              <pre className="text-sm text-blue-300 font-mono overflow-x-auto whitespace-pre-wrap">
{`{
  "scan_id": "uuid-string",
  "submitted_url": "...",
  "normalized_url": "...",
  "classification": "phishing | suspicious | legitimate",
  "classification_label": "Likely Phishing (High Confidence)",
  "risk_score": 0-100,
  "severity_tier": "CRITICAL | HIGH | MEDIUM | LOW",
  "confidence": 0.0-1.0,
  "confidence_level": "Very High | High | Medium | Low",
  "reasons": ["human-readable strings"],
  "detailed_reasons": [{ "category", "severity", "title", "description", "impact" }],
  "feature_contributions": [{ "feature", "value", "importance_weight", "directional_effect" }],
  "brand_analysis": { "matched_brand", "similarity_score", "technique", "is_suspicious_brand_use" },
  "domain_analysis": { "registered_domain", "tld", "domain_entropy", "tld_is_risky", "dns_resolves" },
  "threat_intelligence": { "threat_detected", "reputation_score", "sources", "summary" },
  "html_analysis": { "html_retrieved", "has_password_input", "has_login_form", "script_count", ... },
  "features": { "url_length": 45, "is_https": 1, ... },
  "model_version": "1.0.0",
  "scanned_at": "2026-10-06T..."
}`}
              </pre>
            </div>
          </div>
        </Section>

        {/* Feature Overview */}
        <Section title="Implemented Features">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {features.map((f) => (
              <div key={f.title} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <div className="flex items-start justify-between gap-2 mb-2">
                  <h3 className="text-sm font-semibold text-white leading-snug">{f.title}</h3>
                  <Tag color={f.color as "blue" | "red" | "yellow" | "emerald" | "purple"}>{f.tag}</Tag>
                </div>
                <p className="text-gray-400 text-xs leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>
        </Section>

        {/* External APIs Required */}
        <Section title="External APIs — Connect to Unlock P1 Features">
          <div className="bg-yellow-900/10 border border-yellow-700/40 rounded-xl p-4 mb-4 text-sm text-yellow-300">
            ⚠️ The APIs below are implemented but running in stub/fallback mode. Sign up for the
            free tiers and add the keys to <code className="font-mono">backend/.env</code>.
          </div>
          <div className="space-y-4">
            {threatApis.map((api) => (
              <div key={api.name} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center gap-3 mb-2">
                  <h3 className="font-semibold text-white text-sm">{api.name}</h3>
                  <Tag color="emerald">{api.tier}</Tag>
                </div>
                <p className="text-gray-400 text-xs mb-3">{api.desc}</p>
                <div className="flex flex-wrap gap-3 items-center">
                  <code className="text-xs bg-gray-800 px-3 py-1.5 rounded-lg text-blue-300 font-mono">
                    {api.envKey}
                  </code>
                  <a
                    href={api.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-blue-400 hover:text-blue-300 underline underline-offset-2"
                  >
                    Sign up →
                  </a>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 bg-gray-900 border border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-500 uppercase tracking-widest mb-3">
              After obtaining keys — create <code className="text-blue-400">backend/.env</code>
            </p>
            <pre className="text-xs text-green-300 font-mono overflow-x-auto">
{`# Copy backend/.env.example → backend/.env and fill in:
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here

# Optional — cloud database (uses SQLite fallback without this)
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_KEY=your_anon_key_here`}
            </pre>
          </div>
        </Section>

        {/* ML Details */}
        <Section title="ML Architecture">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-3 text-sm text-gray-400">
            <p><span className="text-white font-medium">Algorithm:</span> Custom Random Forest (pure NumPy — no scikit-learn)</p>
            <p><span className="text-white font-medium">Features:</span> 37 handcrafted URL/HTML signals</p>
            <p><span className="text-white font-medium">Training set:</span> 2,300 samples (1,150 legitimate + 1,150 phishing), stratified 80/20 split</p>
            <p><span className="text-white font-medium">Champion performance:</span> Accuracy 100%, F1 1.00, ROC-AUC 1.00, FNR 0%</p>
            <p><span className="text-white font-medium">Generalization:</span> 14/14 unseen obfuscation techniques correctly classified</p>
            <p><span className="text-white font-medium">Top signal:</span> HTTPS presence, risky TLD, hostname length, brand impersonation</p>
            <p><span className="text-white font-medium">Serialization:</span> Joblib — model reloaded on startup without retraining</p>
          </div>
        </Section>

      </main>
    </div>
  );
}
