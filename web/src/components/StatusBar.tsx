'use client';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';

interface StatusBarProps {
  lastUpdated?: string;
  cached?: boolean;
  cacheDate?: string;
  totalItems?: number;
  itemLabel?: string;
  refreshing: boolean;
  onRefresh: () => void;
}

export function StatusBar({
  lastUpdated,
  cached,
  cacheDate,
  totalItems,
  itemLabel = 'items',
  refreshing,
  onRefresh,
}: StatusBarProps) {
  return (
    <Card className="mb-6 p-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-4">
          {/* Status indicator with pulsing dot */}
          <div className="flex items-center gap-2">
            <span className="relative flex h-3 w-3">
              <span
                className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                  cached ? 'bg-yellow-400' : 'bg-green-400'
                }`}
              ></span>
              <span
                className={`relative inline-flex rounded-full h-3 w-3 ${
                  cached ? 'bg-yellow-500' : 'bg-green-500'
                }`}
              ></span>
            </span>
            <span className={`text-sm font-medium ${cached ? 'text-yellow-500' : 'text-green-500'}`}>
              {cached ? 'Cached' : 'Live'}
            </span>
          </div>

          {/* Date info */}
          <div className="text-sm text-muted-foreground">
            {cached && cacheDate ? (
              <span>Updated: {cacheDate.split('T')[0]}</span>
            ) : lastUpdated ? (
              <span>Updated: {lastUpdated.split('T')[0]}</span>
            ) : null}
          </div>

          {/* Item count */}
          {totalItems !== undefined && (
            <div className="text-sm text-muted-foreground">
              {totalItems} {itemLabel}
            </div>
          )}
        </div>

        {/* Refresh button */}
        <Button
          variant="outline"
          size="sm"
          onClick={onRefresh}
          disabled={refreshing}
          className="min-w-[140px] transition-all duration-200 hover:border-green-500/50 hover:bg-green-500/10"
        >
          {refreshing ? (
            <div className="flex items-center gap-2">
              <svg
                className="animate-spin h-4 w-4"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                ></circle>
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                ></path>
              </svg>
              <span>Refreshing...</span>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <svg
                className="h-4 w-4"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth="2"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                />
              </svg>
              <span>Refresh Data</span>
            </div>
          )}
        </Button>
      </div>
    </Card>
  );
}
