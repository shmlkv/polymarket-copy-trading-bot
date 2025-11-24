import { calculateOrderSize, CopyStrategy, validateCopyStrategyConfig } from '../copyStrategy';
import type { CopyStrategyConfig } from '../copyStrategy';

describe('calculateOrderSize', () => {
    const baseConfig: CopyStrategyConfig = {
        strategy: CopyStrategy.PERCENTAGE,
        copySize: 10.0,
        maxOrderSizeUSD: 100.0,
        minOrderSizeUSD: 1.0,
    };

    describe('PERCENTAGE strategy', () => {
        it('should calculate correct percentage of trader order', () => {
            const result = calculateOrderSize(baseConfig, 100, 1000, 0);
            expect(result.finalAmount).toBe(10);
            expect(result.strategy).toBe(CopyStrategy.PERCENTAGE);
            expect(result.belowMinimum).toBe(false);
        });

        it('should cap at maxOrderSizeUSD', () => {
            const result = calculateOrderSize(baseConfig, 2000, 10000, 0);
            expect(result.finalAmount).toBe(100); // Capped at max
            expect(result.cappedByMax).toBe(true);
        });

        it('should return 0 if below minimum', () => {
            const result = calculateOrderSize(baseConfig, 5, 1000, 0);
            expect(result.finalAmount).toBe(0);
            expect(result.belowMinimum).toBe(true);
        });

        it('should reduce to fit available balance', () => {
            const result = calculateOrderSize(baseConfig, 100, 5, 0);
            expect(result.finalAmount).toBeLessThanOrEqual(5 * 0.99);
            expect(result.reducedByBalance).toBe(true);
        });
    });

    describe('FIXED strategy', () => {
        const fixedConfig: CopyStrategyConfig = {
            strategy: CopyStrategy.FIXED,
            copySize: 50.0,
            maxOrderSizeUSD: 100.0,
            minOrderSizeUSD: 1.0,
        };

        it('should use fixed amount', () => {
            const result = calculateOrderSize(fixedConfig, 1000, 10000, 0);
            expect(result.finalAmount).toBe(50);
            expect(result.strategy).toBe(CopyStrategy.FIXED);
        });

        it('should cap at maxOrderSizeUSD', () => {
            const fixedConfigLarge: CopyStrategyConfig = {
                ...fixedConfig,
                copySize: 200.0,
            };
            const result = calculateOrderSize(fixedConfigLarge, 1000, 10000, 0);
            expect(result.finalAmount).toBe(100);
            expect(result.cappedByMax).toBe(true);
        });
    });

    describe('Position limits', () => {
        it('should respect maxPositionSizeUSD', () => {
            const configWithLimit: CopyStrategyConfig = {
                ...baseConfig,
                maxPositionSizeUSD: 50.0,
            };
            const result = calculateOrderSize(configWithLimit, 100, 1000, 40);
            expect(result.finalAmount).toBe(10); // 40 + 10 = 50, within limit
        });

        it('should reduce order if it would exceed maxPositionSizeUSD', () => {
            const configWithLimit: CopyStrategyConfig = {
                ...baseConfig,
                maxPositionSizeUSD: 50.0,
            };
            const result = calculateOrderSize(configWithLimit, 100, 1000, 45);
            expect(result.finalAmount).toBeLessThanOrEqual(5);
        });
    });
});

describe('validateCopyStrategyConfig', () => {
    it('should validate correct config', () => {
        const config: CopyStrategyConfig = {
            strategy: CopyStrategy.PERCENTAGE,
            copySize: 10.0,
            maxOrderSizeUSD: 100.0,
            minOrderSizeUSD: 1.0,
        };
        const errors = validateCopyStrategyConfig(config);
        expect(errors).toHaveLength(0);
    });

    it('should detect invalid copySize', () => {
        const config: CopyStrategyConfig = {
            strategy: CopyStrategy.PERCENTAGE,
            copySize: -5.0,
            maxOrderSizeUSD: 100.0,
            minOrderSizeUSD: 1.0,
        };
        const errors = validateCopyStrategyConfig(config);
        expect(errors.length).toBeGreaterThan(0);
    });

    it('should detect copySize > 100 for PERCENTAGE', () => {
        const config: CopyStrategyConfig = {
            strategy: CopyStrategy.PERCENTAGE,
            copySize: 150.0,
            maxOrderSizeUSD: 100.0,
            minOrderSizeUSD: 1.0,
        };
        const errors = validateCopyStrategyConfig(config);
        expect(errors.some((e) => e.includes('copySize'))).toBe(true);
    });

    it('should detect minOrderSizeUSD > maxOrderSizeUSD', () => {
        const config: CopyStrategyConfig = {
            strategy: CopyStrategy.PERCENTAGE,
            copySize: 10.0,
            maxOrderSizeUSD: 10.0,
            minOrderSizeUSD: 20.0,
        };
        const errors = validateCopyStrategyConfig(config);
        expect(errors.some((e) => e.includes('minOrderSizeUSD'))).toBe(true);
    });
});
