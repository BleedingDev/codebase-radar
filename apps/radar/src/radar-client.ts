import { makeEffectHttpApiClient } from '@modern-js/plugin-bff/effect-client';
import { RadarApi } from '../shared/api';

export const RadarClient = makeEffectHttpApiClient(RadarApi, { baseUrl: '/api' });
