import { PathScanPage } from '../components/PathScanPage'
import { scanSast } from '../api/client'
import { Code } from 'lucide-react'

export default function SastPage() {
  return (
    <PathScanPage
      title="SAST — Static Analysis"
      description="70+ YAML rules · eval/exec detection · hardcoded credentials · insecure patterns · taint tracking"
      placeholder="/path/to/source/code"
      scanFn={scanSast}
      inputLabel="SOURCE PATH"
      icon={<Code className="w-4 h-4" />}
    />
  )
}
