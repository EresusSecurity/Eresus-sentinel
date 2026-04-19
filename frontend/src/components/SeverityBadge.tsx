import { clsx } from 'clsx'
import type { Severity } from '../types'

const sevColors: Record<Severity, string> = {
  CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/20',
  HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  MEDIUM: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  LOW: 'bg-green-500/10 text-green-400 border-green-500/20',
  INFO: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={clsx('text-[9px] px-1.5 py-0.5 border font-bold tracking-wider', sevColors[severity])}>
      {severity}
    </span>
  )
}
