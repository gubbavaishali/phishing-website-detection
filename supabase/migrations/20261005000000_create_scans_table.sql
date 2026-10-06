-- Migration: 20261005000000_create_scans_table.sql
-- Description: Create persistent scans and scan_features tables with RLS and indexes.

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Scans Table
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    submitted_url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    classification VARCHAR(32) NOT NULL CHECK (classification IN ('legitimate', 'suspicious', 'phishing')),
    risk_score SMALLINT NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence NUMERIC(4, 2) NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    model_version VARCHAR(32) NOT NULL,
    features_json JSONB,
    reasons_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_classification ON public.scans (classification);
CREATE INDEX IF NOT EXISTS idx_scans_risk_score ON public.scans (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_scans_normalized_url ON public.scans (normalized_url);

-- 2. Scan Features Table (Optional deep feature persistence)
CREATE TABLE IF NOT EXISTS public.scan_features (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    url_length INTEGER NOT NULL,
    has_ip SMALLINT NOT NULL DEFAULT 0,
    is_https SMALLINT NOT NULL DEFAULT 0,
    has_suspicious_keyword SMALLINT NOT NULL DEFAULT 0,
    brand_similarity_score NUMERIC(4, 3) NOT NULL DEFAULT 0.0,
    is_suspicious_brand_use SMALLINT NOT NULL DEFAULT 0,
    has_password_input SMALLINT NOT NULL DEFAULT 0,
    external_form_action SMALLINT NOT NULL DEFAULT 0,
    tld_is_risky SMALLINT NOT NULL DEFAULT 0,
    threat_feed_score NUMERIC(4, 3) NOT NULL DEFAULT 0.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_scan_features_scan_id ON public.scan_features (scan_id);

-- 3. Row Level Security (RLS)
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_features ENABLE ROW LEVEL SECURITY;

-- Allow public read access to scan history (read-only)
CREATE POLICY "Allow public read access to scans"
    ON public.scans
    FOR SELECT
    TO anon, authenticated
    USING (true);

-- Allow public insert through backend API
CREATE POLICY "Allow backend insert access to scans"
    ON public.scans
    FOR INSERT
    TO anon, authenticated
    WITH CHECK (true);

-- Repeat for scan_features
CREATE POLICY "Allow public read access to scan_features"
    ON public.scan_features
    FOR SELECT
    TO anon, authenticated
    USING (true);

CREATE POLICY "Allow backend insert access to scan_features"
    ON public.scan_features
    FOR INSERT
    TO anon, authenticated
    WITH CHECK (true);
