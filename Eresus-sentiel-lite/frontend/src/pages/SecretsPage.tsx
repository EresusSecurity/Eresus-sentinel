import { PathScanPage } from '../components/PathScanPage'
import { scanSecrets } from '../api/client'

export default function SecretsPage() {
  return (
    <PathScanPage
      title="Secrets Scanner"
      description="120+ patterns · entropy detection · git history · config files"
      placeholder="/path/to/scan"
      scanFn={(path) => scanSecrets(path, { enable_entropy: true })}
      inputLabel="SCAN PATH"
    />
  )
}
