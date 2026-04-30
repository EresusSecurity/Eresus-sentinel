import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, RotateCcw } from 'lucide-react'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack)
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null })
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-[60vh] p-8 text-center">
          <AlertTriangle className="w-12 h-12 text-red-500 mb-4" />
          <h2 className="text-[14px] font-bold text-white mb-2">Something went wrong</h2>
          <p className="text-[11px] text-gray-500 mb-1 max-w-md">
            An unexpected error occurred in the dashboard. This has been logged.
          </p>
          <code className="text-[10px] text-red-400/60 bg-red-500/5 border border-red-500/10 px-3 py-1.5 mt-2 mb-4 max-w-lg truncate block">
            {this.state.error?.message || 'Unknown error'}
          </code>
          <button
            onClick={this.handleReset}
            className="flex items-center gap-2 px-4 py-2 text-[10px] font-bold tracking-wider uppercase border border-sentinel-border text-gray-400 hover:text-white hover:border-sentinel-hover transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Try Again
          </button>
        </div>
      )
    }

    return this.props.children
  }
}
