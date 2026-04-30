import { PathScanPage } from '../components/PathScanPage'
import { scanSupplyChain } from '../api/client'
import { Package } from 'lucide-react'

export default function SupplyChainPage() {
  return (
    <PathScanPage
      title="Supply Chain Audit"
      description="Dependency scanning · typosquatting · OSV.dev · provenance · hubness detection"
      placeholder="/path/to/project"
      scanFn={scanSupplyChain}
      inputLabel="PROJECT PATH"
      icon={<Package className="w-4 h-4" />}
    />
  )
}
