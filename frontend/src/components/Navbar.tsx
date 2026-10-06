"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useEffect } from "react";
import { Shield, Activity, Database, BookOpen, BarChart3 } from "lucide-react";
import { getHealthStatus } from "@/lib/api";

export default function Navbar() {
  const pathname = usePathname();
  const [isBackendHealthy, setIsBackendHealthy] = useState<boolean | null>(null);

  useEffect(() => {
    let mounted = true;
    getHealthStatus()
      .then(() => {
        if (mounted) setIsBackendHealthy(true);
      })
      .catch(() => {
        if (mounted) setIsBackendHealthy(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const navLinks = [
    { href: "/", label: "Scanner", icon: Shield },
    { href: "/history", label: "Scan History", icon: Database },
    { href: "/benchmark", label: "Model Benchmarks", icon: BarChart3 },
    { href: "/docs", label: "Documentation", icon: BookOpen },
  ];

  return (
    <header className="sticky top-0 z-50 bg-[#0b0f19]/90 backdrop-blur-md border-b border-gray-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-3 group">
          <div className="p-2 rounded-xl bg-blue-600/10 border border-blue-500/20 text-blue-400 group-hover:border-blue-500/40 transition">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="font-bold text-lg text-white flex items-center gap-2">
              PhishGuard <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/30">v1.0</span>
            </div>
            <p className="text-[11px] text-gray-400 hidden sm:block">Explainable Hybrid Phishing Detection</p>
          </div>
        </Link>

        {/* Navigation links */}
        <nav className="flex items-center gap-1 sm:gap-2">
          {navLinks.map((link) => {
            const Icon = link.icon;
            const isActive = pathname === link.href;
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition ${
                  isActive
                    ? "bg-blue-600/20 text-blue-400 border border-blue-500/30"
                    : "text-gray-300 hover:text-white hover:bg-gray-800/60"
                }`}
              >
                <Icon className="w-4 h-4" />
                <span className="hidden md:inline">{link.label}</span>
              </Link>
            );
          })}

          {/* Backend Status indicator */}
          <div
            className="ml-2 pl-3 border-l border-gray-800 flex items-center gap-2 text-xs font-mono"
            title={
              isBackendHealthy === null
                ? "Connecting to backend..."
                : isBackendHealthy
                ? "FastAPI ML Backend Online"
                : "Backend Offline (Port 8000)"
            }
          >
            <span
              className={`w-2 h-2 rounded-full ${
                isBackendHealthy === null
                  ? "bg-yellow-400 animate-pulse"
                  : isBackendHealthy
                  ? "bg-emerald-400 ring-2 ring-emerald-500/20"
                  : "bg-red-500 ring-2 ring-red-500/20"
              }`}
            />
            <span className="text-gray-400 hidden lg:inline">
              {isBackendHealthy ? "Engine Active" : "Backend"}
            </span>
          </div>
        </nav>
      </div>
    </header>
  );
}
