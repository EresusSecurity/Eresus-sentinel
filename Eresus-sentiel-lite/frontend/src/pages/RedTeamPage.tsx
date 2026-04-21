import { PathScanPage } from '../components/PathScanPage'
import { scanRedTeam } from '../api/client'

export default function RedTeamPage() {
  return (
    <PathScanPage
      title="Red Team"
      description="48 probes · 13 detectors · 14 generators · YAML playbook engine"
      placeholder="http://localhost:8000/v1/chat"
      scanFn={scanRedTeam}
      inputLabel="TARGET ENDPOINT"
    />
  )
}
