import { renderReport } from './reports.js';

export const calculateBalance = (id: string): number =>
  renderReport(id).length;
