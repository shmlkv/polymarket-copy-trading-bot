'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

interface Tier {
  id: string;
  min: string;
  max: string; // empty = infinity
  multiplier: string;
}

interface TieredMultipliersEditorProps {
  value: string | null;
  onChange: (value: string | null) => void;
}

// Parse tiered multipliers string to tiers array
function parseTiers(value: string | null): Tier[] {
  if (!value || value.trim() === '') return [];

  const tiers: Tier[] = [];
  const parts = value.split(',').map(p => p.trim()).filter(Boolean);

  for (const part of parts) {
    const [range, multiplier] = part.split(':');
    if (!range || !multiplier) continue;

    if (range.endsWith('+')) {
      // Infinite upper bound
      tiers.push({
        id: Math.random().toString(36).slice(2),
        min: range.slice(0, -1),
        max: '',
        multiplier,
      });
    } else if (range.includes('-')) {
      const [min, max] = range.split('-');
      tiers.push({
        id: Math.random().toString(36).slice(2),
        min,
        max,
        multiplier,
      });
    }
  }

  return tiers;
}

// Convert tiers array to string format
function tiersToString(tiers: Tier[]): string | null {
  if (tiers.length === 0) return null;

  const parts = tiers.map(tier => {
    const range = tier.max === '' ? `${tier.min}+` : `${tier.min}-${tier.max}`;
    return `${range}:${tier.multiplier}`;
  });

  return parts.join(',');
}

export function TieredMultipliersEditor({ value, onChange }: TieredMultipliersEditorProps) {
  const [tiers, setTiers] = useState<Tier[]>(() => parseTiers(value));
  const [errors, setErrors] = useState<Record<string, string>>({});

  // Sync with external value changes
  useEffect(() => {
    setTiers(parseTiers(value));
  }, [value]);

  const validateTiers = (newTiers: Tier[]): boolean => {
    const newErrors: Record<string, string> = {};
    let isValid = true;

    for (let i = 0; i < newTiers.length; i++) {
      const tier = newTiers[i];
      const min = parseFloat(tier.min);
      const max = tier.max === '' ? Infinity : parseFloat(tier.max);
      const mult = parseFloat(tier.multiplier);

      if (isNaN(min) || min < 0) {
        newErrors[`${tier.id}-min`] = 'Invalid min';
        isValid = false;
      }

      if (tier.max !== '' && (isNaN(max) || max <= min)) {
        newErrors[`${tier.id}-max`] = 'Invalid max';
        isValid = false;
      }

      if (isNaN(mult) || mult < 0) {
        newErrors[`${tier.id}-mult`] = 'Invalid';
        isValid = false;
      }

      // Check for overlaps (except last tier with infinity)
      if (i < newTiers.length - 1 && tier.max === '') {
        newErrors[`${tier.id}-max`] = 'Must be last';
        isValid = false;
      }
    }

    setErrors(newErrors);
    return isValid;
  };

  const updateTiers = (newTiers: Tier[]) => {
    setTiers(newTiers);
    if (validateTiers(newTiers)) {
      onChange(tiersToString(newTiers));
    }
  };

  const addTier = () => {
    const lastTier = tiers[tiers.length - 1];
    const newMin = lastTier ? (lastTier.max || lastTier.min) : '0';

    const newTier: Tier = {
      id: Math.random().toString(36).slice(2),
      min: newMin,
      max: '',
      multiplier: '1.0',
    };

    updateTiers([...tiers, newTier]);
  };

  const removeTier = (id: string) => {
    updateTiers(tiers.filter(t => t.id !== id));
  };

  const updateTier = (id: string, field: keyof Tier, value: string) => {
    updateTiers(tiers.map(t => t.id === id ? { ...t, [field]: value } : t));
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Apply different multipliers based on trader&apos;s order size
        </p>
        <Button variant="outline" size="sm" onClick={addTier}>
          Add Tier
        </Button>
      </div>

      {tiers.length === 0 ? (
        <p className="text-sm text-muted-foreground py-4 text-center border border-dashed rounded-lg">
          No tiered multipliers configured. Using single multiplier.
        </p>
      ) : (
        <div className="space-y-2">
          <div className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2 text-xs text-muted-foreground px-1">
            <span>Min ($)</span>
            <span>Max ($)</span>
            <span>Multiplier</span>
            <span></span>
          </div>

          {tiers.map((tier, index) => (
            <div key={tier.id} className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2 items-start">
              <Input
                type="number"
                value={tier.min}
                onChange={(e) => updateTier(tier.id, 'min', e.target.value)}
                placeholder="0"
                error={errors[`${tier.id}-min`]}
                className="text-sm"
              />
              <Input
                type="number"
                value={tier.max}
                onChange={(e) => updateTier(tier.id, 'max', e.target.value)}
                placeholder={index === tiers.length - 1 ? '∞' : ''}
                error={errors[`${tier.id}-max`]}
                className="text-sm"
              />
              <Input
                type="number"
                step="0.01"
                value={tier.multiplier}
                onChange={(e) => updateTier(tier.id, 'multiplier', e.target.value)}
                placeholder="1.0"
                error={errors[`${tier.id}-mult`]}
                className="text-sm"
              />
              <Button
                variant="ghost"
                size="sm"
                onClick={() => removeTier(tier.id)}
                className="text-red-500 hover:text-red-600 px-2"
              >
                ×
              </Button>
            </div>
          ))}
        </div>
      )}

      {tiers.length > 0 && (
        <div className="text-xs text-muted-foreground bg-muted/50 p-3 rounded-lg space-y-1">
          <p className="font-medium">Preview:</p>
          {tiers.map((tier) => {
            const mult = parseFloat(tier.multiplier) || 0;
            const min = parseFloat(tier.min) || 0;
            const example = min + 10;
            const result = example * mult;
            const range = tier.max === '' ? `$${min}+` : `$${min}-$${tier.max}`;

            return (
              <p key={tier.id}>
                {range}: ${example.toFixed(0)} × {mult}x = ${result.toFixed(2)}
              </p>
            );
          })}
        </div>
      )}
    </div>
  );
}
