import type { Metadata } from "next";
import Navbar from "@/components/Navbar";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishGuard | Explainable Hybrid Phishing Detection",
  description:
    "Cybersecurity application utilizing URL lexical analysis, domain infrastructure, safe HTML inspection, and explainable machine learning to detect phishing websites.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#090d16] text-gray-100 flex flex-col min-h-screen">
        <Navbar />
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </main>
        <footer className="border-t border-gray-800 py-6 text-center text-xs text-gray-400">
          <p>
            PhishGuard &bull; Explainable Hybrid Phishing Website Detection Engine &bull; College &amp; Research Engineering Baseline
          </p>
        </footer>
      </body>
    </html>
  );
}
