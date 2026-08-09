import { Audience, type Finding } from './domain';

export const audienceLabel = {
  technical: 'CTO / Tech lead',
  executive: 'CEO / Product owner',
  security: 'CISO / Risk owner',
} satisfies Record<typeof Audience.Type, string>;

export const audienceCopy = (
  finding: Finding,
  audience: typeof Audience.Type,
) => {
  if (audience === 'technical') {
    return {
      summary: finding.technicalSummary,
      recommendation: finding.recommendation,
    };
  }
  if (audience === 'security') {
    return {
      summary:
        finding.category === 'security'
          ? finding.summary
          : `${finding.summary} This is engineering exposure, not a verified security incident.`,
      recommendation: `Ask the engineering owner to ${finding.recommendation.replace(/^./u, value => value.toLowerCase())}`,
    };
  }
  return {
    summary: finding.summary,
    recommendation:
      finding.action === 'fix now'
        ? `Fund and schedule this before the next release: ${finding.recommendation}`
        : `Have the technical owner validate this before committing delivery time: ${finding.recommendation}`,
  };
};
