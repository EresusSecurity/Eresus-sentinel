import { PathScanPage } from '../components/PathScanPage'
import { scanSupplyChain } from '../api/client'

export default function SupplyChainPage() {
  return (
    <PathScanPage
      title="Supply Chain Audit"
      description="Dependency scanning · typosquatting · OSV.dev · provenance · hubness detection"
      placeholder="/path/to/project"
      scanFn={scanSupplyChain}
      inputLabel="PROJECT PATH"
    />
  )
}
