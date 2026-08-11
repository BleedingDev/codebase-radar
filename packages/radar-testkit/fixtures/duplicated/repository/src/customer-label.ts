export function formatCustomerLabel(input: string): string {
  const normalized = input.trim().toLowerCase();
  const words = normalized.split(/\s+/u);
  const visibleWords = words.filter(word => word.length > 0);
  const capitalizedWords = visibleWords.map(
    word => `${word.slice(0, 1).toUpperCase()}${word.slice(1)}`,
  );
  return capitalizedWords.join(' ');
}
