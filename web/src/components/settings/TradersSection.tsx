'use client';

import { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';

interface TradersSectionProps {
  traders: string[];
  traderLabels: Record<string, string>;
  onChange: (traders: string[]) => void;
}

export function TradersSection({ traders, traderLabels, onChange }: TradersSectionProps) {
  const [newTrader, setNewTrader] = useState('');
  const [error, setError] = useState('');

  const isValidAddress = (address: string): boolean => {
    return /^0x[a-fA-F0-9]{40}$/.test(address);
  };

  const handleAdd = () => {
    const address = newTrader.trim().toLowerCase();

    if (!address) {
      setError('Enter an address');
      return;
    }

    if (!isValidAddress(address)) {
      setError('Invalid Ethereum address format');
      return;
    }

    if (traders.some(t => t.toLowerCase() === address)) {
      setError('Trader already in list');
      return;
    }

    onChange([...traders, address]);
    setNewTrader('');
    setError('');
  };

  const handleRemove = (address: string) => {
    onChange(traders.filter(t => t.toLowerCase() !== address.toLowerCase()));
  };

  const getLabel = (address: string): string | null => {
    const label = traderLabels[address.toLowerCase()];
    return label || null;
  };

  const truncateAddress = (address: string): string => {
    return `${address.slice(0, 8)}...${address.slice(-6)}`;
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Traders to Copy</CardTitle>
        <CardDescription>
          Manage the list of traders whose trades will be copied
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Current traders list */}
        <div className="space-y-2">
          {traders.length === 0 ? (
            <p className="text-sm text-muted-foreground">No traders configured</p>
          ) : (
            traders.map((address) => {
              const label = getLabel(address);
              return (
                <div
                  key={address}
                  className="flex items-center justify-between p-3 bg-muted/50 rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <code className="text-sm font-mono">{truncateAddress(address)}</code>
                    {label && (
                      <Badge variant="secondary">{label}</Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <a
                      href={`https://polymarket.com/profile/${address}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-blue-500 hover:underline"
                    >
                      View
                    </a>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleRemove(address)}
                      className="text-red-500 hover:text-red-600 hover:bg-red-500/10"
                    >
                      Remove
                    </Button>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Add new trader */}
        <div className="flex gap-2">
          <div className="flex-1">
            <Input
              placeholder="0x... (Ethereum address)"
              value={newTrader}
              onChange={(e) => {
                setNewTrader(e.target.value);
                setError('');
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  handleAdd();
                }
              }}
              error={error}
            />
          </div>
          <Button onClick={handleAdd}>
            Add Trader
          </Button>
        </div>

        <p className="text-xs text-muted-foreground">
          {traders.length} trader{traders.length !== 1 ? 's' : ''} configured
        </p>
      </CardContent>
    </Card>
  );
}
