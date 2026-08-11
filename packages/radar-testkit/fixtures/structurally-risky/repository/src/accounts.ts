import { calculateBalance } from './billing.js';

export const accountSummary = (id: string): string =>
  `${id}:${calculateBalance(id)}`;
