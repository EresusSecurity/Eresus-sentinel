import { PathScanPage } from '../components/PathScanPage'
import { scanMCP } from '../api/client'
import { Plug } from 'lucide-react'

export default function MCPScanPage() {
  return (
    <PathScanPage
      title="MCP Scanner"
      description="MCP manifest validation · schema checks · permission analysis · live endpoint probing"
      placeholder="/path/to/mcp-manifest.json"
      scanFn={(target) => scanMCP(target)}
      inputLabel="MANIFEST PATH OR URL"
      icon={<Plug className="w-4 h-4" />}
    />
  )
}
