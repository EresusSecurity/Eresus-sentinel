import { PathScanPage } from '../components/PathScanPage'
import { scanSast } from '../api/client'

export default function SastPage() {
  return (
    <PathScanPage
      title="SAST — Static Analysis"
      description="Secrets detection · code patterns · entropy analysis · taint tracking"
      placeholder="/path/to/source/code"
      scanFn={scanSast}
      inputLabel="SOURCE PATH"
    />
  )
}
