import { useQuery } from '@tanstack/react-query'
import { fetchHistory } from '../api/client'
import { clsx } from 'clsx'
import { SeverityBadge } from '../components/SeverityBadge'
import { Clock, Search, Filter } from 'lucide-react'
import { useState, useMemo } from 'react'
import type { ScanEntry, ArtifactEntry, Severity } from '../types'

type HistoryItem =
  | (Omit<ScanEntry, 'type'> & { type: 'firewall'; scan_type: ScanEntry['type'] })
  | (ArtifactEntry & { type: 'artifact' })

export default function HistoryPage() {
  const { data, isLoading } = useQuery({ queryKey: ['history'], queryFn: fetchHistory, refetchInterval: 5000 })
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<'all' | 'firewall' | 'artifact'>('all')

  const items: HistoryItem[] = useMemo(() => {
    const scans = (data?.scans ?? []).map((s) => ({ ...s, type: 'firewall' as const, scan_type: s.type }))
    const artifacts = (data?.artifacts ?? []).map((a) => ({ ...a, type: 'artifact' as const }))
    return [...scans, ...artifacts].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  }, [data])

  const filtered = useMemo(() => {
    let list = items
    if (typeFilter !== 'all') list = list.filter((i) => i.type === typeFilter)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter((i) => {
        if (i.type === 'firewall') return i.prompt.toLowerCase().includes(q)
        return i.filename.toLowerCase().includes(q)
      })
    }
    return list
  }, [items, typeFilter, search])

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-80">
        <div className="w-4 h-4 border border-red-500/30 border-t-red-500 animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-4 animate-fade-in-up">
      {/* Header */}
      <div className="flex items-center gap-2 text-[10px] text-gray-600 uppercase tracking-[0.2em]">
        <Clock className="w-3 h-3" />
        <span>scan history</span>
        <div className="flex-1 border-t border-sentinel-border ml-2" />
        <span className="text-gray-700">{filtered.length} entries</span>
      </div>

      {/* Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-700" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search prompts, filenames..."
            className="w-full bg-sentinel-card border border-sentinel-border pl-8 pr-3 py-2 text-[11px] text-gray-300 placeholder-gray-700"
          />
        </div>
        <div className="flex items-center gap-1">
          <Filter className="w-3 h-3 text-gray-700 mr-1" />
          {(['all', 'firewall', 'artifact'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={clsx(
                'text-[9px] px-2 py-1.5 border uppercase tracking-wider transition-colors',
                typeFilter === t
                  ? 'bg-red-500/5 border-red-500/20 text-red-400'
                  : 'border-sentinel-border text-gray-600 hover:text-gray-400'
              )}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Counts */}
      <div className="flex items-center gap-3 text-[9px] text-gray-700">
        <span>{items.filter((i) => i.type === 'firewall').length} firewall</span>
        <span>·</span>
        <span>{items.filter((i) => i.type === 'artifact').length} artifact</span>
      </div>

      {/* Table */}
      <div className="bg-sentinel-card border border-sentinel-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-sentinel-border bg-black/20">
                <th className="px-3 py-2 text-[9px] text-gray-600 uppercase tracking-wider">TYPE</th>
                <th className="px-3 py-2 text-[9px] text-gray-600 uppercase tracking-wider">TARGET</th>
                <th className="px-3 py-2 text-[9px] text-gray-600 uppercase tracking-wider">SEV</th>
                <th className="px-3 py-2 text-[9px] text-gray-600 uppercase tracking-wider">RESULT</th>
                <th className="px-3 py-2 text-[9px] text-gray-600 uppercase tracking-wider">FIND</th>
                <th className="px-3 py-2 text-[9px] text-gray-600 uppercase tracking-wider">LATENCY</th>
                <th className="px-3 py-2 text-[9px] text-gray-600 uppercase tracking-wider">TIME</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sentinel-border">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-3 py-10 text-center text-gray-700 text-[11px]">
                    {search ? 'No matches' : 'No history yet'}
                  </td>
                </tr>
              ) : (
                filtered.map((item) => {
                  const maxSev = item.findings.length > 0
                    ? item.findings.reduce((max, f) => {
                        const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
                        return order.indexOf(f.severity) < order.indexOf(max) ? f.severity : max
                      }, item.findings[0].severity)
                    : null

                  return (
                    <tr key={`${item.type}-${item.id}`} className="hover:bg-sentinel-hover transition-colors">
                      <td className="px-3 py-2">
                        <span className={clsx(
                          'text-[9px] px-1.5 py-0.5 border',
                          item.type === 'firewall' ? 'border-blue-500/20 text-blue-400' : 'border-purple-500/20 text-purple-400'
                        )}>
                          {item.type === 'firewall' ? 'FW' : 'ART'}
                        </span>
                      </td>
                      <td className="px-3 py-2 max-w-xs">
                        <code className="text-[10px] text-gray-400 truncate block">
                          {item.type === 'firewall' ? item.prompt.slice(0, 80) : item.filename}
                        </code>
                      </td>
                      <td className="px-3 py-2">
                        {maxSev ? <SeverityBadge severity={maxSev as Severity} /> : <span className="text-[9px] text-gray-700">—</span>}
                      </td>
                      <td className="px-3 py-2">
                        {item.type === 'firewall' ? (
                          <span className={clsx(
                            'text-[10px] font-bold',
                            item.action === 'block' ? 'text-red-400' : item.finding_count > 0 ? 'text-amber-400' : 'text-green-400'
                          )}>
                            {item.action === 'block' ? 'BLOCK' : item.finding_count > 0 ? 'WARN' : 'CLEAN'}
                          </span>
                        ) : (
                          <span className={clsx(
                            'text-[10px] font-bold',
                            item.status === 'CRITICAL' ? 'text-red-400' : item.status === 'WARNING' ? 'text-amber-400' : 'text-green-400'
                          )}>
                            {item.status}
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-[10px] text-gray-500">{item.finding_count}</td>
                      <td className="px-3 py-2 text-[10px] text-gray-500">{item.latency_ms}ms</td>
                      <td className="px-3 py-2 text-[9px] text-gray-600">
                        {new Date(item.timestamp).toLocaleTimeString()}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
