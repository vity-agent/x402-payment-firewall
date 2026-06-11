export function canonicalizeUrl(input: string): string {
  const url = new URL(input);
  url.hash = "";
  url.hostname = url.hostname.toLowerCase();

  if ((url.protocol === "https:" && url.port === "443") ||
      (url.protocol === "http:" && url.port === "80")) {
    url.port = "";
  }

  const sorted = [...url.searchParams.entries()].sort(([aKey, aValue], [bKey, bValue]) => {
    const keyOrder = aKey.localeCompare(bKey);
    return keyOrder !== 0 ? keyOrder : aValue.localeCompare(bValue);
  });
  url.search = "";
  for (const [key, value] of sorted) {
    url.searchParams.append(key, value);
  }

  return url.toString();
}

export function normalizedHostname(input: string): string {
  return new URL(input).hostname.toLowerCase().replace(/\.$/, "");
}

export function domainMatches(hostname: string, allowedDomain: string): boolean {
  const allowed = allowedDomain.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  return hostname === allowed || hostname.endsWith(`.${allowed}`);
}
