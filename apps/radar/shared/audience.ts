import { Audience, type Finding } from './domain';

export const audienceLabel = {
  technical: 'Engineering',
  executive: 'Leadership',
  security: 'Security',
} satisfies Record<typeof Audience.Type, string>;

export const decisionHeadline = (
  fixNow: number,
  investigate: number,
  monitor: number,
) => {
  if (fixNow > 0) {
    return `${fixNow} ${fixNow === 1 ? 'issue needs' : 'issues need'} attention now.`;
  }
  if (investigate > 0) {
    return `Nothing urgent. Start with ${investigate} ${investigate === 1 ? 'check' : 'checks'}.`;
  }
  if (monitor > 0) {
    return `Nothing urgent. Keep an eye on ${monitor} ${monitor === 1 ? 'item' : 'items'}.`;
  }
  return 'Nothing needs attention now.';
};

export const audienceCopy = (
  finding: Finding,
  audience: typeof Audience.Type,
) => {
  if (audience === 'technical') {
    return {
      summary: finding.summary,
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
