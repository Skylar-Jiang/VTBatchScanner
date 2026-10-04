import { expect, it } from 'vitest';
import { providerStatusLabel, riskLabel } from './workspace';

it('distinguishes missing reports and no detections', () => {
  expect(providerStatusLabel.not_found).toBe('未收录');
  expect(riskLabel.undetected).toBe('未检出');
});
