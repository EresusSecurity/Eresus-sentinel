import { useState, useCallback } from 'react'
import { PathScanPage } from '../components/PathScanPage'
import { scanSecrets } from '../api/client'
import { KeyRound } from 'lucide-react'

export default function SecretsPage() {
  const [entropy, setEntropy] = useState(true)
  const [gitHistory, setGitHistory] = useState(false)

  const scanFn = useCallback(
    (path: string) => scanSecrets(path, { enable_entropy: entropy, git_history: gitHistory }),
    [entropy, gitHistory]
  )

  return (
    <PathScanPage
      title="Secrets Scanner"
      description="120+ patterns · entropy detection · AWS/GCP/Azure keys · git history · config files"
      placeholder="/path/to/scan"
      scanFn={scanFn}
      inputLabel="SCAN PATH"
      icon={<KeyRound className="w-4 h-4" />}
      extraOptions={
        <div className="flex items-center gap-4 mt-2 pt-2 border-t border-sentinel-border">
          <label className="flex items-center gap-1.5 text-[10px] text-gray-500 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={entropy}
              onChange={(e) => setEntropy(e.target.checked)}
              className="w-3 h-3 accent-red-500 bg-black border-sentinel-border"
            />
            Entropy detection
          </label>
          <label className="flex items-center gap-1.5 text-[10px] text-gray-500 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={gitHistory}
              onChange={(e) => setGitHistory(e.target.checked)}
              className="w-3 h-3 accent-red-500 bg-black border-sentinel-border"
            />
            Scan git history
          </label>
        </div>
      }
    />
  )
}
