"use client";

interface RiskGaugeProps {
  score: number;
  severity: string;
}

export default function RiskGauge({ score, severity }: RiskGaugeProps) {
  const radius = 70;
  const stroke = 12;
  const normalizedRadius = radius - stroke / 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  // Semicircle arc (180 degrees)
  const strokeDashoffset = circumference - (score / 100) * (circumference * 0.75);

  const getColor = (s: number) => {
    if (s >= 80) return { stroke: "#ef4444", text: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30" };
    if (s >= 60) return { stroke: "#f97316", text: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" };
    if (s >= 30) return { stroke: "#f59e0b", text: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/30" };
    return { stroke: "#10b981", text: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30" };
  };

  const theme = getColor(score);

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <div className="relative flex items-center justify-center">
        <svg height={radius * 2} width={radius * 2} className="transform -rotate-90">
          {/* Background circle track */}
          <circle
            stroke="#1f2937"
            fill="transparent"
            strokeWidth={stroke}
            r={normalizedRadius}
            cx={radius}
            cy={radius}
            strokeDasharray={`${circumference * 0.75} ${circumference}`}
            strokeLinecap="round"
          />
          {/* Active progress arc */}
          <circle
            stroke={theme.stroke}
            fill="transparent"
            strokeWidth={stroke}
            strokeDasharray={`${circumference * 0.75} ${circumference}`}
            style={{ strokeDashoffset, transition: "stroke-dashoffset 0.8s ease-in-out" }}
            r={normalizedRadius}
            cx={radius}
            cy={radius}
            strokeLinecap="round"
          />
        </svg>

        {/* Center score */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className={`text-4xl font-extrabold font-mono tracking-tight ${theme.text}`}>
            {score}
          </span>
          <span className="text-[11px] font-semibold tracking-wider text-gray-400 uppercase mt-0.5">
            / 100
          </span>
        </div>
      </div>

      <div className={`mt-3 px-3 py-1 rounded-full text-xs font-semibold uppercase tracking-wider border ${theme.bg} ${theme.text} ${theme.border}`}>
        {severity}
      </div>
    </div>
  );
}
