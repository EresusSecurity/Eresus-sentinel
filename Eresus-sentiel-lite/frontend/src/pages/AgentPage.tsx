import { PathScanPage } from '../components/PathScanPage'
import { scanAgent } from '../api/client'

export default function AgentPage() {
  return (
    <PathScanPage
      title="Agent / MCP Validator"
      description="Trust maps · permissions · MCP schema validation · behavioral analysis · YARA"
      placeholder="/path/to/agent/config"
      scanFn={scanAgent}
      inputLabel="AGENT CONFIG PATH"
    />
  )
}
