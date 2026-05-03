export default function HealthScore({ score }) {
  const circumference = 2 * Math.PI * 45;
  const offset = circumference - (score.score / 100) * circumference;

  return (
    <div className="bg-slate-800/40 backdrop-blur-md border
    border-white/5 rounded-2xl p-6 shadow-lg">
      <div className="flex items-center justify-between flex-wrap gap-6">

        {/* Score Circle */}
        <div className="flex items-center gap-6">
          <div className="relative w-28 h-28 flex-shrink-0">
            <svg className="w-28 h-28 -rotate-90" viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="45"
                fill="none" stroke="#1e293b" strokeWidth="8"/>
              <circle cx="50" cy="50" r="45"
                fill="none"
                stroke={score.score >= 80
                  ? '#4ade80'
                  : score.score >= 60
                  ? '#facc15'
                  : '#f87171'}
                strokeWidth="8"
                strokeLinecap="round"
                strokeDasharray={circumference}
                strokeDashoffset={offset}
                className="transition-all duration-1000"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col
            items-center justify-center">
              <span className={`text-2xl font-bold ${score.color}`}>
                {score.grade}
              </span>
              <span className="text-slate-400 text-xs">
                {score.score}/100
              </span>
            </div>
          </div>

          <div>
            <h3 className="text-white font-semibold text-lg">
              Network Health Score
            </h3>
            <p className={`text-sm font-medium ${score.color}`}>
              {score.summary}
            </p>
            {score.issues.length > 0 && (
              <div className="mt-2 space-y-1">
                {score.issues.slice(0, 3).map((issue, i) => (
                  <p key={i} className="text-slate-400 text-xs
                  flex items-center gap-1">
                    <span>⚠️</span> {issue}
                  </p>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Recommendations */}
        <div className="flex-1 min-w-[200px]">
          <p className="text-slate-400 text-xs font-medium
          uppercase tracking-wide mb-2">
            Recommendations
          </p>
          <div className="space-y-2">
            {score.recommendations.slice(0, 3).map((rec, i) => (
              <div key={i} className="flex items-start gap-2
              bg-slate-900/50 rounded-xl p-3">
                <span className="text-cyan-400 text-xs
                flex-shrink-0 mt-0.5">→</span>
                <p className="text-slate-300 text-xs">{rec}</p>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}
