/**
 * Authoritative TypeScript Types mirroring the Python FastAPI backend contract.
 */

export interface DetailedReason {
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "POSITIVE";
  title: string;
  description: string;
  impact: string;
}

export interface FeatureContribution {
  feature: string;
  value: number;
  importance_weight: number;
  directional_effect: string;
}

export interface BrandAnalysis {
  matched_brand: string | null;
  similarity_score: number;
  technique: string;
  is_suspicious_brand_use: boolean;
  details: string;
}

export interface DomainAnalysis {
  registered_domain: string;
  domain_name: string;
  tld: string;
  subdomain: string;
  subdomain_count: number;
  domain_entropy: number;
  tld_is_risky: number;
  has_hyphen_in_domain: number;
  dns_resolves: boolean;
}

export interface ThreatIntelligence {
  threat_detected: boolean;
  reputation_score: number;
  sources: Record<string, { checked: boolean; status: string; details: string }>;
  summary: string;
}

export interface HtmlAnalysis {
  html_retrieved: boolean;
  has_password_input: number;
  has_login_form: number;
  external_form_action: number;
  has_hidden_iframe: number;
  script_count: number;
  external_resources_ratio: number;
  suspicious_html_indicators: string[];
}

export interface AnalyzeUrlResponse {
  scan_id: string;
  submitted_url: string;
  normalized_url: string;
  classification: "phishing" | "suspicious" | "legitimate";
  classification_label: string;
  risk_score: number;
  severity_tier: "LOW RISK" | "MEDIUM RISK" | "HIGH RISK" | "VERY HIGH RISK";
  confidence: number;
  confidence_level: "High" | "Medium" | "Moderate";
  reasons: string[];
  detailed_reasons: DetailedReason[];
  feature_contributions: FeatureContribution[];
  brand_analysis: BrandAnalysis;
  domain_analysis: DomainAnalysis;
  threat_intelligence: ThreatIntelligence;
  html_analysis: HtmlAnalysis;
  features: Record<string, number>;
  model_version: string;
  disclaimer: string;
  scanned_at: string;
}

export interface ScanHistoryItem {
  id: string;
  submitted_url: string;
  normalized_url: string;
  classification: "phishing" | "suspicious" | "legitimate";
  risk_score: number;
  confidence: number;
  model_version: string;
  reasons: string[];
  created_at: string;
}

export interface BenchmarkMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  roc_auc: number;
  confusion_matrix: {
    true_negative: number;
    false_positive: number;
    false_negative: number;
    true_positive: number;
  };
  false_negative_rate: number;
  false_positive_rate: number;
}

export interface BenchmarkData {
  champion_model: string;
  dataset_summary: {
    total_samples: number;
    train_samples: number;
    test_samples: number;
    class_distribution: {
      legitimate: number;
      phishing: number;
    };
  };
  model_comparisons: Record<string, BenchmarkMetrics>;
  generalization_benchmark: {
    total_samples: number;
    accuracy: number;
    recall: number;
    sample_evaluations: Array<{
      url: string;
      technique: string;
      ground_truth: string;
      predicted: string;
      risk_probability: number;
      correct: boolean;
    }>;
  };
  feature_importances: Array<{
    rank: number;
    feature: string;
    importance: number;
  }>;
}

export interface HealthStatus {
  status: string;
  service: string;
  model_loaded: boolean;
  model_version: string;
  feature_schema_version: string;
  algorithm: string;
}
