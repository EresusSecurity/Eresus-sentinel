import { SeverityBadge } from './SeverityBadge'
import type { Finding } from '../types'

export function FindingCard({ finding, delay = 0 }: { finding: Finding; delay?: number }) {
  return (
    <div
      className="bg-sentinel-bg border-l-2 border-sentinel-border p-3 animate-slide-in"
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="flex items-center gap-2 mb-1">
        <SeverityBadge severity={finding.severity} />
        <code className="text-[10px] text-gray-500">{finding.rule_id}</code>
        {finding.confidence > 0 && (
          <span className="text-[10px] text-gray-700 ml-auto">
            {Math.round(finding.confidence * 100)}%
          </span>
        )}
      </div>
      <p className="text-[11px] text-gray-300">{finding.title}</p>
      {finding.description && (
        <p className="text-[10px] text-gray-600 mt-1">{finding.description}</p>
      )}
      {finding.evidence && (
        <div className="mt-1.5 px-2 py-1.5 bg-black/40 border border-sentinel-border">
          <code className="text-[10px] text-red-400/80 break-all leading-relaxed">
            {finding.evidence.slice(0, 300)}
          </code>
        </div>
      )}
    </div>
  )
}
