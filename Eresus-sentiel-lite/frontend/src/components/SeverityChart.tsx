import { useRef, useEffect } from 'react'
import * as echarts from 'echarts'

interface Props {
  data: Record<string, number>
}

const colorMap: Record<string, string> = {
  CRITICAL: '#DC2626',
  HIGH: '#EA580C',
  MEDIUM: '#D97706',
  LOW: '#16A34A',
  INFO: '#2563EB',
}

export function SeverityChart({ data }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  const chartRef = useRef<echarts.ECharts | null>(null)

  useEffect(() => {
    if (!ref.current) return
    chartRef.current = echarts.init(ref.current, undefined, { renderer: 'canvas' })

    const items = Object.entries(data)
      .filter(([, v]) => v > 0)
      .map(([name, value]) => ({
        value,
        name,
        itemStyle: { color: colorMap[name] || '#374151' },
      }))

    chartRef.current.setOption({
      tooltip: {
        trigger: 'item',
        backgroundColor: '#111114',
        borderColor: '#1C1C22',
        textStyle: { color: '#D1D5DB', fontSize: 10, fontFamily: 'JetBrains Mono, monospace' },
      },
      series: [
        {
          type: 'pie',
          radius: ['55%', '80%'],
          center: ['50%', '50%'],
          avoidLabelOverlap: false,
          padAngle: 1,
          itemStyle: { borderRadius: 0, borderWidth: 1, borderColor: '#09090B' },
          label: { show: false },
          emphasis: {
            label: {
              show: true,
              fontSize: 10,
              fontWeight: 'bold',
              color: '#E5E7EB',
              fontFamily: 'JetBrains Mono, monospace',
            },
            scaleSize: 4,
          },
          data: items.length > 0 ? items : [{ value: 1, name: 'No data', itemStyle: { color: '#1C1C22' } }],
        },
      ],
    })

    if (items.length === 0) {
      chartRef.current.setOption({
        graphic: {
          type: 'text',
          left: 'center',
          top: 'center',
          style: {
            text: '∅',
            fill: '#374151',
            fontSize: 16,
            fontFamily: 'JetBrains Mono, monospace',
          },
        },
      })
    }

    const onResize = () => chartRef.current?.resize()
    window.addEventListener('resize', onResize)
    return () => {
      window.removeEventListener('resize', onResize)
      chartRef.current?.dispose()
    }
  }, [data])

  return <div ref={ref} className="h-48 w-full" />
}
