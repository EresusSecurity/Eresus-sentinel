import { PathScanPage } from '../components/PathScanPage'
import { scanDiff } from '../api/client'

export default function DiffPage() {
  return (
    <PathScanPage
      title="Diff Scanner"
      description="Git diff ML anti-pattern detection · staged changes · PR review"
      placeholder="--staged"
      scanFn={scanDiff}
      inputLabel="DIFF TARGET"
    />
  )
}
