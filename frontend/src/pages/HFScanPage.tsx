import { useState, useCallback } from 'react'
import { PathScanPage } from '../components/PathScanPage'
import { scanHF } from '../api/client'
import { Database } from 'lucide-react'

export default function HFScanPage() {
  const [deep, setDeep] = useState(false)

  const scanFn = useCallback(
    (repo: string) => scanHF(repo, deep),
    [deep]
  )

  return (
    <PathScanPage
      title="HuggingFace Scanner"
      description="Remote model repo scan · pickle detection · safetensors validation · card analysis"
      placeholder="org/model-name"
      scanFn={scanFn}
      inputLabel="HUGGINGFACE REPO"
      icon={<Database className="w-4 h-4" />}
      extraOptions={
        <div className="flex items-center gap-4 mt-2 pt-2 border-t border-sentinel-border">
          <label className="flex items-center gap-1.5 text-[10px] text-gray-500 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={deep}
              onChange={(e) => setDeep(e.target.checked)}
              className="w-3 h-3 accent-red-500 bg-black border-sentinel-border"
            />
            Deep scan (download & analyze files)
          </label>
          <span className="text-[9px] text-gray-700">Requires HF_TOKEN env var</span>
        </div>
      }
    />
  )
}
