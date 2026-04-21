import { PathScanPage } from '../components/PathScanPage'
import { scanNotebook } from '../api/client'

export default function NotebookPage() {
  return (
    <PathScanPage
      title="Notebook Scanner"
      description="14 plugins — requirements · outputs · metadata · dangerous code · CVEs · PII · secrets"
      placeholder="/path/to/notebook.ipynb"
      scanFn={scanNotebook}
      inputLabel="NOTEBOOK PATH"
    />
  )
}
