// The analysis API publishes filenames with MACs masked. Also protect the display
// when an older API returns a raw label. Local upload failures use a file number.
const mac = /(?<![0-9a-z])(?:(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}|[0-9a-f]{12})(?![0-9a-z])/gi;
const macLabel = /(?:^|[^0-9a-z])(?:mac(?:[-_ ]?addr(?:ess)?)?|bssid|eui[-_ ]?48)[ ._:=-]*$/i;

function isTimestamp(token: string): boolean {
  if (!/^\d{12}$/.test(token)) return false;
  const iso = `${token.slice(0, 4)}-${token.slice(4, 6)}-${token.slice(6, 8)}T${token.slice(8, 10)}:${token.slice(10)}:00.000Z`;
  const date = new Date(iso);
  return Number.isFinite(date.getTime()) && date.toISOString() === iso && !token.startsWith("0000");
}

export function publicFilename(name: string): string {
  return name.replace(mac, (token: string, offset: number) => {
    if (token.includes(":") && (name[offset - 1] === ":" || name[offset + token.length] === ":")) {
      // Six groups can be part of a longer IPv6 address. Let the URL parser verify it.
      const before = name.slice(0, offset).match(/(?<![0-9a-z])[0-9a-f:]*$/i)?.[0] ?? "";
      const after = name.slice(offset + token.length).match(/^[0-9a-f:]*/i)?.[0] ?? "";
      try {
        new URL(`http://[${before}${token}${after}]/`);
        return token;
      } catch {
        // Punctuation next to a MAC is not a valid IPv6 address.
      }
    }
    if (isTimestamp(token) && !macLabel.test(name.slice(0, offset))) return token;
    const oui = token.replace(/[:.-]/g, "").slice(0, 6).toUpperCase();
    return `${oui.slice(0, 2)}:${oui.slice(2, 4)}:${oui.slice(4)}:xx:xx:xx`;
  });
}
