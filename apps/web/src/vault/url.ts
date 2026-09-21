// Adresa iz stavke postaje link samo ako je bezbedna. Stavke su korisnikov unos (a uvoz i
// sinhronizacija mogu doneti tudje), pa "javascript:", "data:" i slicne sheme se nikad ne otvaraju.
export function toSafeUrl(raw: string): string | null {
  const value = raw.trim();
  if (value === '') {
    return null;
  }
  // "localhost:3000" nije shema, ali "javascript:alert(1)" i "mailto:x" jesu.
  const hasScheme = /^[a-z][a-z0-9+.-]*:(?!\d)/i.test(value);
  const candidate = hasScheme ? value : `https://${value}`;
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return null;
  }
  if (url.hostname === '') {
    return null;
  }
  // "https://google.com@lazan.example" izgleda kao google.com, a vodi na drugi sajt.
  if (url.username !== '' || url.password !== '') {
    return null;
  }
  return url.href;
}
