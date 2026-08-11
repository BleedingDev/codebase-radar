type Counter = Readonly<{ value: number }>;

function typescriptLeaf(counter: Counter) {
  return counter.value + 1;
}

export function typescriptRoot(counter: Counter) {
  return typescriptLeaf(counter);
}
