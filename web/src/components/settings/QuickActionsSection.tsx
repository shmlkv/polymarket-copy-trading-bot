'use client';

import { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert';
import { ActionType, ActionResponse, HealthCheckResult } from '@/types/settings';

interface QuickActionsSectionProps {
  healthCheck: HealthCheckResult | null;
  onRefreshHealth: () => void;
}

interface ActionState {
  loading: boolean;
  result: ActionResponse | null;
}

export function QuickActionsSection({ healthCheck, onRefreshHealth }: QuickActionsSectionProps) {
  const [actionStates, setActionStates] = useState<Record<string, ActionState>>({});
  const [manualSellKeyword, setManualSellKeyword] = useState('');

  const executeAction = async (action: ActionType, params?: { keyword?: string }) => {
    setActionStates(prev => ({
      ...prev,
      [action]: { loading: true, result: null },
    }));

    try {
      const response = await fetch('/api/actions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, params }),
      });

      const result: ActionResponse = await response.json();

      setActionStates(prev => ({
        ...prev,
        [action]: { loading: false, result },
      }));
    } catch (error) {
      setActionStates(prev => ({
        ...prev,
        [action]: {
          loading: false,
          result: {
            success: false,
            action,
            output: '',
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        },
      }));
    }
  };

  const getActionState = (action: ActionType): ActionState => {
    return actionStates[action] || { loading: false, result: null };
  };

  const actions: { action: ActionType; label: string; description: string; variant?: 'default' | 'destructive' | 'outline' }[] = [
    { action: 'health-check', label: 'Health Check', description: 'Verify system status' },
    { action: 'check-stats', label: 'Check Stats', description: 'View positions and P&L' },
    { action: 'close-resolved', label: 'Close Resolved', description: 'Sell positions in resolved markets', variant: 'outline' },
    { action: 'redeem-resolved', label: 'Redeem Resolved', description: 'Redeem winning positions', variant: 'outline' },
    { action: 'close-stale', label: 'Close Stale', description: 'Close old inactive positions', variant: 'outline' },
  ];

  return (
    <div className="space-y-6">
      {/* Health Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-3">
            System Health
            {healthCheck && (
              <Badge variant={healthCheck.healthy ? 'success' : 'destructive'}>
                {healthCheck.healthy ? 'Healthy' : 'Issues Detected'}
              </Badge>
            )}
          </CardTitle>
          <CardDescription>
            Current system status and connectivity
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {healthCheck ? (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {Object.entries(healthCheck.checks).map(([key, check]) => (
                <div
                  key={key}
                  className={`p-3 rounded-lg border ${
                    check.status === 'ok' ? 'border-green-500/30 bg-green-500/5' :
                    check.status === 'warning' ? 'border-yellow-500/30 bg-yellow-500/5' :
                    'border-red-500/30 bg-red-500/5'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`w-2 h-2 rounded-full ${
                      check.status === 'ok' ? 'bg-green-500' :
                      check.status === 'warning' ? 'bg-yellow-500' :
                      'bg-red-500'
                    }`} />
                    <span className="text-sm font-medium capitalize">{key}</span>
                  </div>
                  {check.message && (
                    <p className="text-xs text-muted-foreground">{check.message}</p>
                  )}
                  {'value' in check && check.value !== undefined && (
                    <p className="text-sm font-mono">${check.value.toFixed(2)}</p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">Loading health status...</p>
          )}

          <Button variant="outline" size="sm" onClick={onRefreshHealth}>
            Refresh Health Status
          </Button>
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
          <CardDescription>
            Execute common operations without using the terminal
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {actions.map(({ action, label, description, variant }) => {
              const state = getActionState(action);
              return (
                <Button
                  key={action}
                  variant={variant || 'default'}
                  className="h-auto py-3 flex flex-col items-start text-left"
                  onClick={() => executeAction(action)}
                  disabled={state.loading}
                >
                  <span className="font-medium">
                    {state.loading ? 'Running...' : label}
                  </span>
                  <span className="text-xs opacity-70 font-normal">{description}</span>
                </Button>
              );
            })}
          </div>

          {/* Manual Sell */}
          <div className="p-4 border rounded-lg space-y-3">
            <h4 className="font-medium text-sm">Manual Sell</h4>
            <p className="text-xs text-muted-foreground">
              Sell positions matching a keyword (e.g., market name)
            </p>
            <div className="flex gap-2">
              <Input
                placeholder="Enter keyword to match..."
                value={manualSellKeyword}
                onChange={(e) => setManualSellKeyword(e.target.value)}
                className="flex-1"
              />
              <Button
                variant="destructive"
                onClick={() => {
                  if (manualSellKeyword.trim()) {
                    executeAction('manual-sell', { keyword: manualSellKeyword.trim() });
                  }
                }}
                disabled={!manualSellKeyword.trim() || getActionState('manual-sell').loading}
              >
                {getActionState('manual-sell').loading ? 'Selling...' : 'Sell'}
              </Button>
            </div>
          </div>

          {/* Action Results */}
          {Object.entries(actionStates).map(([action, state]) => {
            if (!state.result) return null;

            return (
              <Alert
                key={action}
                variant={state.result.success ? 'success' : 'destructive'}
              >
                <AlertTitle>
                  {action}: {state.result.success ? 'Success' : 'Failed'}
                </AlertTitle>
                <AlertDescription>
                  <pre className="text-xs whitespace-pre-wrap max-h-40 overflow-auto mt-2 p-2 bg-black/20 rounded">
                    {state.result.output || state.result.error}
                  </pre>
                </AlertDescription>
              </Alert>
            );
          })}
        </CardContent>
      </Card>
    </div>
  );
}
