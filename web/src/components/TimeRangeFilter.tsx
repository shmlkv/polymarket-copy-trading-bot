'use client';

export type TimeRange = '7d' | '30d' | '90d' | 'all';

interface TimeRangeFilterProps {
  value: TimeRange;
  onChange: (value: TimeRange) => void;
}

const options: { value: TimeRange; label: string }[] = [
  { value: '7d', label: '7D' },
  { value: '30d', label: '30D' },
  { value: '90d', label: '90D' },
  { value: 'all', label: 'All' },
];

export function TimeRangeFilter({ value, onChange }: TimeRangeFilterProps) {
  return (
    <div className="inline-flex bg-card border rounded-lg p-1 gap-1">
      {options.map((option) => (
        <button
          key={option.value}
          onClick={() => onChange(option.value)}
          className={`px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
            value === option.value
              ? 'bg-primary text-primary-foreground'
              : 'text-muted-foreground hover:text-foreground hover:bg-muted'
          }`}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

// Helper function to filter data by time range
export function filterByTimeRange<T extends { date?: string; month?: string }>(
  data: T[],
  timeRange: TimeRange,
  dateField: 'date' | 'month' = 'date'
): T[] {
  if (timeRange === 'all') return data;

  const now = new Date();
  const daysBack = timeRange === '7d' ? 7 : timeRange === '30d' ? 30 : 90;
  const cutoffDate = new Date(now.getTime() - daysBack * 24 * 60 * 60 * 1000);

  return data.filter((item) => {
    const dateStr = dateField === 'date' ? item.date : item.month;
    if (!dateStr) return false;
    const itemDate = new Date(dateStr);
    return itemDate >= cutoffDate;
  });
}
