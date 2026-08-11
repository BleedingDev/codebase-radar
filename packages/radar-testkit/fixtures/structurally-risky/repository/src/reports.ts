import { accountSummary } from './accounts.js';

export const renderReport = (id: string): string => accountSummary(id);
