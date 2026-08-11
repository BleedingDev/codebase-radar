type LabelProperties = Readonly<{ label: string }>;

function TypeScriptLabel({ label }: LabelProperties) {
  return <span>{label}</span>;
}

export function TypeScriptCard(properties: LabelProperties) {
  return <TypeScriptLabel {...properties} />;
}
