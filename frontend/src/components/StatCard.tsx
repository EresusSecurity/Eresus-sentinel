import { clsx } from 'clsx'
import type { ReactNode } from 'react'

interface Props {
  title: string
  value: string | number
  subtitle?: string
  icon: ReactNode
  iconBg: string
  delay?: number
  highlight?: boolean
}

export function StatCard({ title, value, subtitle, icon, iconBg, delay = 0, highlight }: Props) {
  return (
    <div
      className="stat-card bg-sentinel-card border border-sentinel-border rounded-xl p-5 animate-fade-in-up"
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-gray-500 uppercase tracking-wider">{title}</span>
        <div className={clsx('w-7 h-7 flex items-center justify-center', iconBg)}>
          {icon}
        </div>
      </div>
      <p className={clsx(
        'text-2xl font-bold tracking-tight',
        highlight ? 'text-amber-500' : 'text-white'
      )}>
        {value}
      </p>
      {subtitle && <p className="text-xs text-gray-600 mt-1">{subtitle}</p>}
    </div>
  )
}
