import { PathScanPage } from '../components/PathScanPage'
import { scanNotebook } from '../api/client'
import { FileCode } from 'lucide-react'

export default function NotebookPage() {
  return (
    <PathScanPage
      title="Notebook Scanner"
      description="14 plugins — requirements · outputs · metadata · dangerous code · CVEs · PII · secrets"
      placeholder="/path/to/notebook.ipynb"
      scanFn={scanNotebook}
      inputLabel="NOTEBOOK PATH"
      icon={<FileCode className="w-4 h-4" />}
    />
  )
}
