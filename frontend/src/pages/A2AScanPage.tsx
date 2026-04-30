import { PathScanPage } from '../components/PathScanPage'
import { scanA2A } from '../api/client'
import { Users } from 'lucide-react'

export default function A2AScanPage() {
  return (
    <PathScanPage
      title="A2A Agent Card Scanner"
      description="Agent-to-Agent card validation · capability analysis · trust boundary checks"
      placeholder="/path/to/agent-card.json"
      scanFn={scanA2A}
      inputLabel="AGENT CARD PATH"
      icon={<Users className="w-4 h-4" />}
    />
  )
}
