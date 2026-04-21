import { useRef, useEffect } from 'react'
import * as echarts from 'echarts'

interface TimelinePoint {
  ts: string
  findings: number
  latency: number
}

export function TimelineChart({ data }: { data: TimelinePoint[] }) {
  const ref = useRef<HTMLDivElement>(null)
  const chartRef = useRef<echarts.ECharts | null>(null)

  useEffect(() => {
    if (!ref.current) return
    chartRef.current = echarts.init(ref.current, undefined, { renderer: 'canvas' })

    chartRef.current.setOption({
      tooltip: {
        trigger: 'axis',
        backgroundColor: '#111114',
        borderColor: '#1C1C22',
        textStyle: { color: '#D1D5DB', fontSize: 10, fontFamily: 'JetBrains Mono, monospace' },
      },
      grid: { left: 40, right: 40, top: 10, bottom: 25 },
      xAxis: {
        type: 'category',
        data: data.map((t) => t.ts),
        axisLine: { lineStyle: { color: '#1C1C22' } },
        axisLabel: { color: '#4B5563', fontSize: 9, fontFamily: 'JetBrains Mono, monospace' },
        axisTick: { show: false },
      },
      yAxis: [
        {
          type: 'value',
          name: 'findings',
          nameTextStyle: { color: '#4B5563', fontSize: 9, fontFamily: 'JetBrains Mono, monospace' },
          axisLine: { show: false },
          splitLine: { lineStyle: { color: '#111114' } },
          axisLabel: { color: '#4B5563', fontSize: 9, fontFamily: 'JetBrains Mono, monospace' },
        },
        {
          type: 'value',
          name: 'ms',
          nameTextStyle: { color: '#4B5563', fontSize: 9, fontFamily: 'JetBrains Mono, monospace' },
          axisLine: { show: false },
          splitLine: { show: false },
          axisLabel: { color: '#4B5563', fontSize: 9, fontFamily: 'JetBrains Mono, monospace' },
        },
      ],
      series: [
        {
          name: 'Findings',
          type: 'bar',
          data: data.map((t) => t.findings),
          itemStyle: { color: '#DC2626', borderRadius: 0 },
          barWidth: '50%',
        },
        {
          name: 'Latency',
          type: 'line',
          yAxisIndex: 1,
          data: data.map((t) => t.latency),
          smooth: false,
          lineStyle: { color: '#2563EB', width: 1 },
          itemStyle: { color: '#2563EB' },
          showSymbol: false,
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: 'rgba(37,99,235,0.08)' },
              { offset: 1, color: 'rgba(37,99,235,0)' },
            ]),
          },
        },
      ],
    })

    if (data.length === 0) {
      chartRef.current.setOption({
        graphic: {
          type: 'text',
          left: 'center',
          top: 'center',
          style: {
            text: 'awaiting data...',
            fill: '#374151',
            fontSize: 11,
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
