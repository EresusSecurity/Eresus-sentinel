import { useState, useCallback } from 'react'
import { PathScanPage } from '../components/PathScanPage'
import { scanDiff } from '../api/client'
import { GitBranch } from 'lucide-react'

const quickTargets = [
  { label: '--staged', desc: 'Staged changes' },
  { label: 'HEAD~1', desc: 'Last commit' },
  { label: 'HEAD~5', desc: 'Last 5 commits' },
  { label: 'main..HEAD', desc: 'Branch diff' },
]

export default function DiffPage() {
  const [target, setTarget] = useState('--staged')

  const scanFn = useCallback(
    (_input: string) => scanDiff(_input || target),
    [target]
  )

  return (
    <PathScanPage
      title="Diff Scanner"
      description="Git diff ML anti-pattern detection · staged changes · PR review · commit analysis"
      placeholder="--staged"
      scanFn={scanFn}
      inputLabel="DIFF TARGET"
      icon={<GitBranch className="w-4 h-4" />}
      extraOptions={
        <div className="flex items-center gap-1.5 mt-2 pt-2 border-t border-sentinel-border">
          <span className="text-[9px] text-gray-700 mr-1">Quick:</span>
          {quickTargets.map((qt) => (
            <button
              key={qt.label}
              type="button"
              onClick={() => setTarget(qt.label)}
              className="text-[9px] px-2 py-1 bg-black/30 border border-sentinel-border text-gray-600 hover:text-gray-300 hover:border-sentinel-hover transition-colors font-mono"
              title={qt.desc}
            >
              {qt.label}
            </button>
          ))}
        </div>
      }
    />
  )
}
