export function describeUserAgent(userAgent: string | null): string {
  if (userAgent === null || userAgent.trim() === '') {
    return 'Nepoznat uređaj';
  }
  const browser = /Edg\//.test(userAgent)
    ? 'Edge'
    : /OPR\/|Opera/.test(userAgent)
      ? 'Opera'
      : /Firefox\//.test(userAgent)
        ? 'Firefox'
        : /Chrome\/|CriOS\//.test(userAgent)
          ? 'Chrome'
          : /Safari\//.test(userAgent)
            ? 'Safari'
            : 'Pregledač';
  const system = /Android/.test(userAgent)
    ? 'Android'
    : /iPhone|iPad|iPod/.test(userAgent)
      ? 'iOS'
      : /Windows/.test(userAgent)
        ? 'Windows'
        : /Macintosh|Mac OS X/.test(userAgent)
          ? 'macOS'
          : /Linux|X11/.test(userAgent)
            ? 'Linux'
            : null;
  return system === null ? browser : `${browser} na ${system}`;
}
