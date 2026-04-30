import { PathScanPage } from '../components/PathScanPage'
import { scanAgent } from '../api/client'
import { Bot } from 'lucide-react'

export default function AgentPage() {
  return (
    <PathScanPage
      title="Agent / MCP Validator"
      description="Trust maps · permissions · MCP schema validation · A2A agent cards · behavioral analysis"
      placeholder="/path/to/agent/config"
      scanFn={scanAgent}
      inputLabel="AGENT CONFIG PATH"
      icon={<Bot className="w-4 h-4" />}
    />
  )
}
