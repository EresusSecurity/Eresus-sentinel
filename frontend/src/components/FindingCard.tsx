import { useState } from 'react'
import { SeverityBadge } from './SeverityBadge'
import type { Finding } from '../types'
import { ChevronDown, ChevronRight, Wrench, ExternalLink } from 'lucide-react'
import { clsx } from 'clsx'

const sevBorderColors: Record<string, string> = {
  CRITICAL: 'border-l-red-500',
  HIGH: 'border-l-orange-500',
  MEDIUM: 'border-l-amber-500',
  LOW: 'border-l-green-500',
  INFO: 'border-l-blue-500',
}

export function FindingCard({ finding, delay = 0 }: { finding: Finding; delay?: number }) {
  const [expanded, setExpanded] = useState(false)
  const hasDetails = finding.evidence || finding.remediation || (finding.cwe_ids && finding.cwe_ids.length > 0)

  return (
    <div
      className={clsx(
        'bg-sentinel-bg border-l-2 border border-sentinel-border animate-slide-in transition-colors hover:bg-sentinel-card/50',
        sevBorderColors[finding.severity] || 'border-l-gray-500'
      )}
      style={{ animationDelay: `${delay}ms` }}
    >
      <button
        onClick={() => hasDetails && setExpanded(!expanded)}
        className="w-full text-left p-3"
        disabled={!hasDetails}
      >
        <div className="flex items-center gap-2">
          {hasDetails && (
            expanded
              ? <ChevronDown className="w-3 h-3 text-gray-600 flex-shrink-0" />
              : <ChevronRight className="w-3 h-3 text-gray-600 flex-shrink-0" />
          )}
          <SeverityBadge severity={finding.severity} />
          <code className="text-[10px] text-gray-500">{finding.rule_id}</code>
          <span className="text-[11px] text-gray-300 flex-1 truncate">{finding.title}</span>
          {finding.confidence > 0 && (
            <span className="text-[10px] text-gray-700 tabular-nums flex-shrink-0">
              {Math.round(finding.confidence * 100)}%
            </span>
          )}
        </div>
        {finding.description && (
          <p className="text-[10px] text-gray-600 mt-1 pl-5 line-clamp-2">{finding.description}</p>
        )}
      </button>

      {expanded && (
        <div className="px-3 pb-3 space-y-2 border-t border-sentinel-border pt-2 ml-5">
          {finding.evidence && (
            <div className="px-2 py-1.5 bg-black/40 border border-sentinel-border">
              <p className="text-[9px] text-gray-700 uppercase tracking-wider mb-1">Evidence</p>
              <code className="text-[10px] text-red-400/80 break-all leading-relaxed block whitespace-pre-wrap">
                {finding.evidence.slice(0, 500)}
              </code>
            </div>
          )}

          {finding.remediation && (
            <div className="px-2 py-1.5 bg-green-500/5 border border-green-500/10">
              <p className="text-[9px] text-green-600 uppercase tracking-wider mb-1 flex items-center gap-1">
                <Wrench className="w-3 h-3" /> Remediation
              </p>
              <p className="text-[10px] text-green-400/80 leading-relaxed">
                {finding.remediation}
              </p>
            </div>
          )}

          {finding.cwe_ids && finding.cwe_ids.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {finding.cwe_ids.map((cwe) => {
                // Sanitize CWE ID: only allow numeric part (e.g. "CWE-89" → "89")
                const cweNum = cwe.replace(/^CWE-/i, '').replace(/\D/g, '')
                if (!cweNum) return null
                return (
                  <a
                    key={cwe}
                    href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-[9px] text-blue-400/70 hover:text-blue-400 bg-blue-500/5 border border-blue-500/10 px-1.5 py-0.5 transition-colors"
                  >
                    CWE-{cweNum} <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                )
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
