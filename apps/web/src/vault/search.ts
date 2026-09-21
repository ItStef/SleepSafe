import type { VaultEntry } from './store';

// Mala slova bez dijakritika (c, s, z umesto č, š, ž), da "cesir" nadje "Češir".
function fold(text: string): string {
  return text.normalize('NFKD').replace(/\p{M}/gu, '').replace(/đ/gi, 'd').toLowerCase();
}

// Svaka rec iz upita mora da se nadje negde u naslovu, korisnickom imenu, adresi ili beleskama.
// Lozinka se nikad ne pretrazuje.
export function filterEntries(
  entries: readonly VaultEntry[],
  query: string,
): readonly VaultEntry[] {
  const terms = fold(query).split(/\s+/).filter(Boolean);
  if (terms.length === 0) {
    return entries;
  }
  return entries.filter(({ data }) => {
    const haystack = fold([data.title, data.username, data.url, data.notes].join('\n'));
    return terms.every((term) => haystack.includes(term));
  });
}
