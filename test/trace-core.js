// @ts-nocheck
/** Classification and lookups. No DOM. */

export const REDIRECT_API = "https://www.redirectcheck.org/api/check";
const DOH = "https://cloudflare-dns.com/dns-query";
const RIPE = "https://stat.ripe.net/data";
const SOURCE_APP = "whispr-trace";

const DNS_TYPES = {
  1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
  28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS", 257: "CAA",
};
const DNS_STATUS = { 0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED" };

const MULTI_TLD = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz",
  "com.br", "co.jp", "co.za", "com.mx", "co.in", "com.sg", "com.tr", "co.kr",
]);

export function ipv4ToInt(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    n = ((n << 8) | value) >>> 0;
  }
  return n;
}

export function intToIpv4(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

export function isIPv4(value) {
  return ipv4ToInt(value) != null;
}

export function expandIPv6(ip) {
  let text = String(ip).trim().toLowerCase().split("%")[0];
  if (!text) return null;
  const mapped = text.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped && isIPv4(mapped[1])) {
    const n = ipv4ToInt(mapped[1]);
    text = `::ffff:${((n >>> 16) & 0xffff).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  if (text.includes(".")) return null;
  const halves = text.split("::");
  if (halves.length > 2) return null;
  let groups;
  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves[1] ? halves[1].split(":") : [];
    if (left.length + right.length > 8) return null;
    groups = [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
  } else {
    groups = text.split(":");
    if (groups.length !== 8) return null;
  }
  if (groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
  return groups.map((group) => group.padStart(4, "0"));
}

export function isIPv6(value) {
  return expandIPv6(value) != null;
}

function inCidrV4(ip, cidr) {
  const [base, bitsText] = cidr.split("/");
  const bits = Number(bitsText);
  const ipN = ipv4ToInt(ip);
  const baseN = ipv4ToInt(base);
  if (ipN == null || baseN == null || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (~0 << (32 - bits)) >>> 0;
  return (ipN & mask) === (baseN & mask);
}

function v4Mapped(groups) {
  if (!groups || !groups.slice(0, 5).every((group) => group === "0000") || groups[5] !== "ffff") return null;
  return intToIpv4(((parseInt(groups[6], 16) << 16) | parseInt(groups[7], 16)) >>> 0);
}

export function describeIp(ip) {
  if (isIPv4(ip)) {
    const n = ipv4ToInt(ip);
    const rules = [
      ["255.255.255.255/32", "Limited broadcast", "Heard only on the local link."],
      ["0.0.0.0/8", "This network", "Not a public destination. 0.0.0.0 means this host, on the machine itself."],
      ["10.0.0.0/8", "Private", "RFC 1918. Used inside a network and not routed on the public Internet."],
      ["100.64.0.0/10", "Shared address space", "RFC 6598. Carrier-grade NAT, between a subscriber and the public Internet."],
      ["127.0.0.0/8", "Loopback", "Stays on this machine. The host is talking to itself."],
      ["169.254.0.0/16", "Link-local", "RFC 3927. Used when DHCP fails. 169.254.169.254 is the cloud metadata address."],
      ["172.16.0.0/12", "Private", "RFC 1918. A local network, not a public route."],
      ["192.0.0.0/24", "Protocol assignment", "Reserved for IETF protocol use, not ordinary hosting."],
      ["192.0.2.0/24", "Documentation", "TEST-NET-1, RFC 5737. For examples, not a live network."],
      ["192.168.0.0/16", "Private", "RFC 1918. A typical home or office LAN."],
      ["198.18.0.0/15", "Benchmarking", "RFC 2544. For device tests, not production traffic."],
      ["198.51.100.0/24", "Documentation", "TEST-NET-2, RFC 5737."],
      ["203.0.113.0/24", "Documentation", "TEST-NET-3, RFC 5737."],
      ["224.0.0.0/4", "Multicast", "One packet, many listeners. Not a single host to open in a browser."],
      ["240.0.0.0/4", "Reserved", "Held for future use, not public unicast."],
    ];
    let special = null;
    for (const [cidr, title, detail] of rules) {
      if (inCidrV4(ip, cidr)) {
        special = { title, detail };
        break;
      }
    }
    const leadingZero = String(ip).split(".").some((part) => part.length > 1 && part.startsWith("0"));
    return {
      version: 4,
      title: special ? special.title : "Public unicast",
      detail: special ? special.detail : leadingZero ? "Leading zeros were read as decimal, not octal." : "An ordinary public IPv4 address.",
      send: !special,
      expanded: intToIpv4(n),
      hex: `0x${n.toString(16).padStart(8, "0")}`,
      int: n,
      mapped: null,
    };
  }
  const groups = expandIPv6(ip);
  if (!groups) return null;
  const mapped = v4Mapped(groups);
  if (mapped) {
    const inner = describeIp(mapped);
    return {
      ...inner,
      version: 6,
      title: `IPv4-mapped (${inner.title})`,
      detail: `This is ::ffff:${mapped}. ${inner.detail}`,
      send: inner.send,
      expanded: groups.join(":"),
      hex: null,
      mapped,
    };
  }
  const allZero = groups.every((group) => group === "0000");
  const loopback = groups.slice(0, 7).every((group) => group === "0000") && groups[7] === "0001";
  const first = parseInt(groups[0], 16);
  let special = null;
  if (allZero) special = ["Unspecified", "The empty address. It means no address, not a destination."];
  else if (loopback) special = ["Loopback", "The IPv6 loopback. It never leaves this machine."];
  else if ((first & 0xfe00) === 0xfc00) special = ["Unique local", "fc00::/7. Private IPv6, the equivalent of RFC 1918."];
  else if ((first & 0xffc0) === 0xfe80) special = ["Link-local", "fe80::/10. Valid only on one link."];
  else if ((first & 0xff00) === 0xff00) special = ["Multicast", "ff00::/8. Not a single host."];
  else if (groups[0] === "2001" && groups[1] === "0db8") special = ["Documentation", "2001:db8::/32. For examples, not a live network."];
  else if (groups[0] === "0100" && groups.slice(1, 4).every((group) => group === "0000"))
    special = ["Discard", "0100::/64. Traffic here is thrown away."];
  else if (groups[0] === "0064" && groups[1] === "ff9b" && groups.slice(2, 6).every((group) => group === "0000"))
    special = ["NAT64", "64:ff9b::/96. A well-known prefix that translates IPv4 into IPv6."];
  const note6to4 = groups[0] === "2002" ? " 2002::/16 is 6to4: the next 32 bits are an embedded IPv4 address." : "";
  return {
    version: 6,
    title: special ? special[0] : "Public unicast",
    detail: (special ? special[1] : "An ordinary public IPv6 address.") + note6to4,
    send: !special,
    expanded: groups.join(":"),
    hex: null,
    int: null,
    mapped: null,
  };
}

export function isSpecialIp(ip) {
  const info = describeIp(ip);
  return !info || info.send === false;
}

function apexOf(host) {
  const labels = String(host).split(".").filter(Boolean);
  if (labels.length <= 2) return host;
  const last2 = labels.slice(-2).join(".");
  if (MULTI_TLD.has(last2) && labels.length >= 3) return labels.slice(-3).join(".");
  return labels.slice(-2).join(".");
}

function toPuny(host) {
  const trimmed = String(host).trim().replace(/\.$/, "");
  if (!trimmed || trimmed.length > 253 || /[\s/]/.test(trimmed)) return null;
  try {
    const url = new URL(`http://${trimmed}`);
    if (url.username || url.password || url.port || url.pathname !== "/" || url.search || url.hash) return null;
    if (!url.hostname || url.hostname.includes(":")) return null;
    return url.hostname;
  } catch {
    return null;
  }
}

function nameClass(host) {
  const name = String(host).toLowerCase().replace(/\.$/, "");
  if (
    name === "localhost" || name.endsWith(".localhost") || name.endsWith(".local") ||
    name.endsWith(".internal") || name.endsWith(".home.arpa") || name.endsWith(".intranet") ||
    name.endsWith(".lan") || !name.includes(".")
  ) return "local";
  return "public";
}

function asnNote(n) {
  if (n === 0) return "AS0 is reserved. It is not a network you can reach.";
  if (n === 23456) return "AS23456 is AS_TRANS, a stand-in used when a 16-bit BGP session refers to a 32-bit ASN.";
  if (n === 65535 || n === 4294967295) return "This number is reserved, not a public network.";
  if (n >= 64496 && n <= 64511) return "A documentation ASN from the 16-bit example range.";
  if (n >= 64512 && n <= 65534) return "A private 16-bit ASN. Used inside one network, not on the public Internet.";
  if (n >= 65536 && n <= 65551) return "A documentation ASN from the 32-bit example range.";
  if (n >= 4200000000 && n <= 4294967294) return "A private 32-bit ASN.";
  return null;
}

function blankPlan(kind, summary) {
  return {
    kind, summary, blocked: false, blockReason: null, httpUrls: [], httpNote: null,
    dnsName: null, ptrIp: null, ripePrefix: null, ripeAsn: null, apex: null,
    parsed: null, address: null, alt: null, email: null, displayHost: null, assumedScheme: false,
  };
}

function unknown(summary) {
  const plan = blankPlan(
    "unknown",
    summary || "Could not tell what that is. Use a URL, a domain, an IP, a prefix such as 1.1.1.0/24, or an ASN such as AS13335.",
  );
  plan.blocked = true;
  return plan;
}

function localPlan(name) {
  const plan = blankPlan("local", `${name} is a local name. It is not sent out. Public resolvers and checkers are the wrong place for it.`);
  plan.blocked = true;
  plan.blockReason = `${name} is a single-label name or a local suffix (.local, .localhost, .internal, .home.arpa, .lan). The local network resolves it. This page does not send it anywhere.`;
  plan.displayHost = name;
  return plan;
}

function asnPlan(numText) {
  const n = Number(numText);
  if (!Number.isInteger(n) || n < 0 || n > 4294967295) return unknown();
  const note = asnNote(n);
  const plan = blankPlan("asn", note ? `Read as AS${n}. ${note}` : `Read as AS${n}. An autonomous system is the network that announces addresses. It is not a URL.`);
  plan.ripeAsn = String(n);
  return plan;
}

function ipPlan(ip) {
  const info = describeIp(ip);
  if (!info) return unknown();
  const shown = info.mapped || info.expanded || ip;
  const plan = blankPlan(
    "ip",
    info.send
      ? `Read as a public IPv${info.version} address. Reverse DNS first, then the prefix and the network that announces it.`
      : `Read as an IPv${info.version} address. ${info.title}. ${info.detail}`,
  );
  plan.blocked = !info.send;
  plan.blockReason = info.send ? null : `${shown} is ${info.title.toLowerCase()}. ${info.detail} It is not sent to a public lookup.`;
  plan.ptrIp = info.send ? info.mapped || (info.version === 4 ? info.expanded : ip) : null;
  plan.address = info;
  return plan;
}

function prefixPlan(address, bits) {
  const info = describeIp(address);
  if (!info) return unknown();
  const text = `${info.version === 4 ? info.expanded : address}/${bits}`;
  const plan = blankPlan(
    "prefix",
    info.send
      ? `Read as the prefix ${text}. A prefix is a route, not one web server, so there is no redirect chain.`
      : `Read as ${text}. ${info.title}. ${info.detail}`,
  );
  plan.blocked = !info.send;
  plan.blockReason = info.send ? null : `${text} sits in ${info.title.toLowerCase()} space. ${info.detail}`;
  plan.ripePrefix = info.send ? text : null;
  plan.address = info;
  return plan;
}

function domainPlan(puny, typed) {
  if (nameClass(puny) === "local") return localPlan(typed || puny);
  const plan = blankPlan("domain", "Read as a domain. DNS first, then the https and http sites, so the upgrade hop shows up.");
  plan.httpUrls = [`https://${puny}/`, `http://${puny}/`];
  plan.httpNote = "Both schemes. A bare domain often answers on port 80 only long enough to send you to https.";
  plan.dnsName = puny;
  plan.apex = apexOf(puny);
  plan.displayHost = typed && typed !== puny ? typed : puny;
  return plan;
}

function applyIpHost(plan, host) {
  const info = describeIp(host);
  if (!info) return plan;
  plan.address = info;
  if (!info.send) {
    plan.blocked = true;
    plan.httpUrls = [];
    plan.ptrIp = null;
    plan.dnsName = null;
    plan.blockReason = `${host} is ${info.title.toLowerCase()}. ${info.detail} The address is not sent to a public lookup.`;
    plan.summary = `Read as a URL aimed at ${info.title.toLowerCase()} space. ${info.detail}`;
    return plan;
  }
  plan.ptrIp = info.mapped || (info.version === 4 ? info.expanded : host);
  plan.dnsName = null;
  return plan;
}

function classifyUrl(text, assumed) {
  let url;
  try { url = new URL(text); } catch { return unknown(); }
  const scheme = url.protocol.replace(":", "").toLowerCase();
  if (scheme === "javascript" || scheme === "data" || scheme === "file" || scheme === "blob") {
    return unknown("That scheme never leaves the browser. Paste an http, https, domain, IP, prefix, or ASN.");
  }
  const fragment = url.hash.replace(/^#/, "");
  const hadUser = Boolean(url.username || url.password);
  url.username = "";
  url.password = "";
  url.hash = "";
  const host = url.hostname;
  const plan = blankPlan("url", "");
  plan.assumedScheme = Boolean(assumed);
  const isIp = isIPv4(host) || isIPv6(host);
  const local = !isIp && nameClass(host) === "local";
  const defaultPort = scheme === "http" || scheme === "ws" ? "80" : scheme === "https" || scheme === "wss" ? "443" : scheme === "ftp" ? "21" : null;
  plan.parsed = {
    href: url.href, scheme, host, port: url.port || defaultPort, portExplicit: Boolean(url.port),
    path: url.pathname || "/", query: url.search.replace(/^\?/, ""), fragment, hadUser,
  };
  plan.displayHost = host;
  if (local) {
    plan.kind = "local";
    plan.blocked = true;
    plan.blockReason = `${host} is a local name. It is not sent to a public checker or resolver.`;
    plan.summary = `Read as a ${scheme} URL on a local name. Nothing was sent out.`;
    return plan;
  }
  if (isIp) applyIpHost(plan, host);
  else {
    plan.dnsName = host;
    plan.apex = apexOf(host);
  }
  if (!plan.blocked && (scheme === "http" || scheme === "https")) {
    plan.httpUrls = [url.href];
    plan.summary = assumed
      ? `Read as ${url.href}. No scheme was written, so this one was assumed.`
      : "Read as a URL. The redirect chain is for this exact address, then the name and the route.";
  } else if (!plan.blocked) {
    plan.summary = `Read as a ${scheme} URL. Hop-by-hop redirects are followed for http and https only. The name and the route are still looked up.`;
  }
  if (hadUser) plan.summary += " A username or password in the address was removed before any lookup.";
  return plan;
}

function classifyEmail(addr) {
  const domain = String(addr).split("@")[1] || "";
  const plan = classify(domain);
  if (plan.kind !== "domain" && plan.kind !== "local") return unknown("That does not look like a usable mailbox.");
  plan.email = addr;
  if (plan.kind === "domain") {
    plan.kind = "email";
    plan.summary = `Read as a mailbox at ${plan.dnsName}. Mail (MX) and the website are different routes, so both are traced.`;
  }
  return plan;
}

function classifyHostish(text) {
  let work = text;
  let fragment = "";
  const hash = work.indexOf("#");
  if (hash >= 0) { fragment = work.slice(hash + 1); work = work.slice(0, hash); }
  let query = "";
  const qMark = work.indexOf("?");
  if (qMark >= 0) { query = work.slice(qMark + 1); work = work.slice(0, qMark); }
  let path = "";
  const slash = work.indexOf("/");
  if (slash >= 0) { path = work.slice(slash); work = work.slice(0, slash); }
  if (!work || work.includes(" ")) return null;
  let host = work;
  let port = "";
  const bracket = work.match(/^\[([^\]]+)\](?::(\d{1,5}))?$/);
  if (bracket) {
    if (!isIPv6(bracket[1])) return null;
    host = bracket[1];
    port = bracket[2] || "";
  } else if (!isIPv6(work)) {
    const portMatch = work.match(/^(.*):(\d{1,5})$/);
    if (portMatch && toPuny(portMatch[1])) { host = portMatch[1]; port = portMatch[2]; }
  }
  if (port && (Number(port) < 1 || Number(port) > 65535)) return null;
  const hasExtra = Boolean((path && path !== "/") || query || port);
  if (isIPv4(host) || isIPv6(host)) {
    if (!hasExtra) return ipPlan(host);
    const scheme = port === "80" || port === "8080" ? "http" : "https";
    const hostPart = isIPv6(host) ? `[${host}]` : host;
    const plan = classifyUrl(`${scheme}://${hostPart}${port ? `:${port}` : ""}${path || "/"}${query ? `?${query}` : ""}`, true);
    if (fragment && plan.parsed) plan.parsed.fragment = fragment;
    return plan;
  }
  const puny = toPuny(host);
  if (!puny) return null;
  if (!hasExtra) return domainPlan(puny, host);
  const scheme = port === "80" || port === "8080" ? "http" : "https";
  const plan = classifyUrl(`${scheme}://${puny}${port ? `:${port}` : ""}${path || "/"}${query ? `?${query}` : ""}`, true);
  if (fragment && plan.parsed) plan.parsed.fragment = fragment;
  return plan;
}

export function classify(raw) {
  let text = String(raw ?? "").trim();
  if (!text) return blankPlan("empty", "");
  if (/[\r\n]/.test(text)) {
    text = text.split(/\r?\n/).map((line) => line.trim()).find(Boolean) || "";
    if (!text) return blankPlan("empty", "");
  }
  text = text.replace(/^["'<]+|[>"']+$/g, "").trim();
  if (text.startsWith("//")) text = `https:${text}`;
  if (/^mailto:/i.test(text)) return classifyEmail(text.slice(7).split("?")[0]);
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text) && !text.includes("://") && !text.includes("/")) return classifyEmail(text);
  const forcedIp = text.match(/^ip:\s*(.+)$/i);
  if (forcedIp) {
    const body = forcedIp[1].trim();
    if (/^\d{1,10}$/.test(body) && Number(body) <= 4294967295) return ipPlan(intToIpv4(Number(body)));
    if (isIPv4(body) || isIPv6(body)) return ipPlan(body);
    return unknown();
  }
  const forcedAs = text.match(/^(?:AS|asn:|as:)\s*(\d{1,10})$/i);
  if (forcedAs) return asnPlan(forcedAs[1]);
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) return classifyUrl(text, false);
  const cidr = text.match(/^([^\s/]+)\/(\d{1,3})$/);
  if (cidr) {
    const bits = Number(cidr[2]);
    if (isIPv4(cidr[1]) && bits <= 32) return prefixPlan(cidr[1], bits);
    if (isIPv6(cidr[1]) && bits <= 128) return prefixPlan(cidr[1], bits);
  }
  const range = text.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (range && isIPv4(range[1]) && isIPv4(range[2])) {
    const plan = blankPlan("range", `Read as the inclusive range ${range[1]}–${range[2]}. Registration is looked up across that span. There is no single site to follow.`);
    plan.ripePrefix = `${range[1]}-${range[2]}`;
    const left = describeIp(range[1]);
    if (left && !left.send) {
      plan.blocked = true;
      plan.ripePrefix = null;
      plan.blockReason = `${range[1]} is ${left.title.toLowerCase()}. The range is not sent out.`;
    }
    return plan;
  }
  const v6port = text.match(/^\[([^\]]+)\](?::(\d{1,5}))?$/);
  if (v6port && isIPv6(v6port[1])) {
    if (!v6port[2]) return ipPlan(v6port[1]);
    const port = Number(v6port[2]);
    if (port < 1 || port > 65535) return unknown();
    const scheme = port === 80 || port === 8080 ? "http" : "https";
    return classifyUrl(`${scheme}://[${v6port[1]}]:${port}/`, true);
  }
  if (isIPv6(text)) return ipPlan(text);
  const v4port = text.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/);
  if (v4port && isIPv4(v4port[1])) {
    const port = Number(v4port[2]);
    if (port < 1 || port > 65535) return unknown();
    const scheme = port === 80 || port === 8080 ? "http" : "https";
    return classifyUrl(`${scheme}://${v4port[1]}:${port}/`, true);
  }
  if (isIPv4(text)) return ipPlan(text);
  if (/^\d{1,10}$/.test(text)) {
    const n = Number(text);
    if (n > 4294967295) return unknown();
    const dotted = intToIpv4(n);
    if (n >= 16777216) {
      const plan = ipPlan(dotted);
      plan.summary = `Read as the decimal IPv4 ${dotted}. A bare integer this large is usually an address written without dots. It could also be AS${n}.`;
      plan.alt = { label: `Trace as AS${n}`, query: `AS${n}` };
      return plan;
    }
    const plan = asnPlan(String(n));
    if (n > 0) {
      plan.summary += ` The same integer is the decimal form of ${dotted}.`;
      plan.alt = { label: `Trace as IPv4 ${dotted}`, query: `ip:${n}` };
    }
    return plan;
  }
  return classifyHostish(text) || unknown();
}

export function messageOf(err) {
  if (!err) return "Lookup failed.";
  if (err.name === "TimeoutError") return "Timed out.";
  if (err.name === "AbortError") return "Stopped.";
  if (err instanceof TypeError) return "The browser could not reach that lookup.";
  return err.message || "Lookup failed.";
}

function linkAbort(parent, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new DOMException("Timed out.", "TimeoutError")), ms);
  const onAbort = () => controller.abort(parent.reason);
  if (parent) {
    if (parent.aborted) controller.abort(parent.reason);
    else parent.addEventListener("abort", onAbort, { once: true });
  }
  controller.signal.addEventListener("abort", () => {
    clearTimeout(timer);
    parent?.removeEventListener("abort", onAbort);
  });
  return controller.signal;
}

async function readBody(res, limit) {
  const text = await res.text();
  if (text.length > limit) throw new Error("The reply was too large to show here.");
  try { return JSON.parse(text); } catch { throw new Error("The reply was not valid data."); }
}

function plainError(type, message) {
  switch (type) {
    case "SSRF_BLOCKED": return "That address was blocked because it points at a private or local network.";
    case "INVALID_URL": return message || "That URL could not be fetched.";
    case "TIMEOUT": return "The site took too long to answer.";
    case "MAX_HOPS_EXCEEDED": return "The chain is longer than 15 hops.";
    case "LOOP_DETECTED": return message || "The chain loops.";
    case "FETCH_ERROR": return message || "The site could not be fetched.";
    default: return message || "The redirect check failed.";
  }
}

async function callLookup(op, extra, direct, signal, ms) {
  if (typeof location === "undefined" || location.protocol !== "file:") {
    try {
      const res = await fetch("/api/trace", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ op, ...extra }),
        signal: linkAbort(signal, ms),
      });
      const type = res.headers.get("content-type") || "";
      if (res.status !== 404 && !type.includes("text/html")) return res;
    } catch (err) {
      if (signal?.aborted || err?.name === "AbortError" || err?.name === "TimeoutError") throw err;
    }
  }
  return direct(linkAbort(signal, ms));
}

export async function redirectCheck(url, signal) {
  const res = await callLookup("redirect", { url }, (sig) => fetch(REDIRECT_API, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ url, method: "GET", followMetaRefresh: true, maxHops: 15 }),
    signal: sig,
  }), signal, 22000);
  const data = await readBody(res, 1_500_000);
  if (typeof data?.error === "string") throw new Error(data.error);
  if (data.error) throw new Error(plainError(data.error_type, data.message));
  if (!res.ok) throw new Error(`Redirect check returned ${res.status}.`);
  return data;
}

async function doh(name, type, signal) {
  const res = await callLookup("doh", { name, type }, (sig) => fetch(`${DOH}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`, {
    signal: sig,
    headers: { accept: "application/dns-json" },
  }), signal, 12000);
  if (!res.ok) throw new Error((await res.json().catch(() => null))?.error || `DNS ${type} returned ${res.status}.`);
  return readBody(res, 500_000);
}

async function ripe(endpoint, resource, signal) {
  const res = await callLookup("ripe", { endpoint, resource }, (sig) => fetch(`${RIPE}/${endpoint}/data.json?resource=${encodeURIComponent(resource)}&sourceapp=${SOURCE_APP}`, {
    signal: sig,
    headers: { accept: "application/json" },
  }), signal, 18000);
  const data = await readBody(res, 1_500_000);
  if (!res.ok || data.status === "error") {
    throw new Error(data.error || data.messages?.[0]?.info || data.message || `${endpoint} failed.`);
  }
  return data.data || {};
}

function tidyDns(type, data) {
  let text = String(data ?? "").trim();
  if (type === "TXT") text = text.replace(/" "/g, "").replace(/^"|"$/g, "");
  else if (type !== "SOA" && type !== "CAA") text = text.replace(/\.$/, "");
  return text;
}

function rowsFrom(json, typeName) {
  return (json?.Answer || []).map((answer) => ({
    type: DNS_TYPES[answer.type] || typeName,
    name: String(answer.name || "").replace(/\.$/, ""),
    ttl: answer.TTL,
    data: tidyDns(DNS_TYPES[answer.type] || typeName, answer.data),
  }));
}

function dedupe(rows) {
  const seen = new Set();
  const out = [];
  for (const row of rows) {
    const key = `${row.type}|${row.name}|${row.data}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
}

export function uniqueIps(rows) {
  const ips = [];
  for (const row of rows || []) {
    if ((row.type === "A" || row.type === "AAAA") && (isIPv4(row.data) || isIPv6(row.data)) && !ips.includes(row.data)) ips.push(row.data);
  }
  return ips;
}

export async function loadForward(name, apex, signal) {
  const types = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA", "HTTPS"];
  const settled = await Promise.all(types.map(async (type) => {
    try { return { type, json: await doh(name, type, signal), error: null }; }
    catch (err) {
      if (signal.aborted) throw err;
      return { type, json: null, error: messageOf(err) };
    }
  }));
  let records = [];
  const errors = [];
  let nxdomain = false;
  for (const item of settled) {
    if (item.error) errors.push(`${item.type}: ${item.error}`);
    else {
      if (item.type === "A" && item.json?.Status === 3) nxdomain = true;
      records.push(...rowsFrom(item.json, item.type));
    }
  }
  if (apex) {
    try {
      const json = await doh(`_dmarc.${apex}`, "TXT", signal);
      records.push(...rowsFrom(json, "TXT").filter((row) => /^v=DMARC1/i.test(row.data)).map((row) => ({ ...row, name: `_dmarc.${apex}` })));
    } catch { /* optional */ }
  }
  records = dedupe(records);
  let chain = null;
  let chainError = null;
  try { chain = await ripe("dns-chain", name, signal); }
  catch (err) {
    if (signal.aborted) throw err;
    chainError = messageOf(err);
  }
  return { records, errors, chain, chainError, nxdomain };
}

function ptrName(ip) {
  if (isIPv4(ip)) return `${ip.split(".").reverse().join(".")}.in-addr.arpa`;
  const groups = expandIPv6(ip);
  if (!groups) return null;
  return `${groups.join("").split("").reverse().join(".")}.ip6.arpa`;
}

export async function loadPtr(ip, signal) {
  const name = ptrName(ip);
  let records = [];
  const errors = [];
  if (name) {
    try { records = rowsFrom(await doh(name, "PTR", signal), "PTR"); }
    catch (err) {
      if (signal.aborted) throw err;
      errors.push(`PTR: ${messageOf(err)}`);
    }
  }
  let chain = null;
  let chainError = null;
  try { chain = await ripe("dns-chain", ip, signal); }
  catch (err) {
    if (signal.aborted) throw err;
    chainError = messageOf(err);
  }
  return { records, errors, chain, chainError, nxdomain: false };
}

async function pool(jobs, limit, signal) {
  const queue = jobs.slice();
  await Promise.all(Array.from({ length: Math.min(limit, queue.length) }, async () => {
    while (queue.length && !signal.aborted) await queue.shift()();
  }));
}

export async function ipCard(ip, signal) {
  const [overview, routing, rir, abuse, whois, geo] = await Promise.all([
    ripe("prefix-overview", ip, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("routing-status", ip, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("rir", ip, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("abuse-contact-finder", ip, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("whois", ip, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("geoloc", ip, signal).catch((err) => ({ error: messageOf(err) })),
  ]);
  let asnOverview = null;
  const asn = overview?.asns?.[0]?.asn;
  if (asn) {
    try { asnOverview = await ripe("as-overview", `AS${asn}`, signal); }
    catch (err) { if (!signal.aborted) asnOverview = { error: messageOf(err) }; }
  }
  return { mode: "ip", ip, overview, routing, rir, abuse, whois, geo, asnOverview };
}

export async function prefixCard(prefix, signal) {
  const [overview, routing, rir, whois] = await Promise.all([
    ripe("prefix-overview", prefix, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("routing-status", prefix, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("rir", prefix, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("whois", prefix, signal).catch((err) => ({ error: messageOf(err) })),
  ]);
  return { mode: "prefix", prefix, overview, routing, rir, whois };
}

export async function asnCard(asn, signal) {
  const id = `AS${asn}`;
  const [overview, neighbours, prefixes] = await Promise.all([
    ripe("as-overview", id, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("asn-neighbours", id, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("announced-prefixes", id, signal).catch((err) => ({ error: messageOf(err) })),
  ]);
  return { mode: "asn", asn, overview, neighbours, prefixes };
}

export async function loadRoutesForIps(ips, state, signal, publish, truncated) {
  const notes = [];
  if (truncated) notes.push("Only the first four addresses are routed here.");
  const usable = [];
  for (const ip of ips) {
    if (isSpecialIp(ip)) {
      const info = describeIp(ip);
      notes.push(`${ip} is ${info ? info.title.toLowerCase() : "special-use"}. Not sent to the routing lookup.`);
    } else usable.push(ip);
  }
  state.routeNote = notes;
  if (!usable.length) {
    state.routePhase = "done";
    publish(state);
    return;
  }
  state.routePhase = "loading";
  publish(state);
  await pool(usable.map((ip) => async () => {
    if (signal.aborted) return;
    try {
      const card = await ipCard(ip, signal);
      if (!signal.aborted) state.routes.push(card);
    } catch (err) {
      if (!signal.aborted) state.routes.push({ mode: "ip", ip, error: messageOf(err) });
    }
    state.routePhase = "done";
    if (!signal.aborted) publish(state);
  }), 2, signal);
  if (!signal.aborted) {
    state.routePhase = "done";
    publish(state);
  }
}

export function chainLines(chain) {
  if (!chain) return [];
  const forward = chain.forward_nodes || {};
  const reverse = chain.reverse_nodes || {};
  const keys = Object.keys(forward);
  const findKey = (name) => keys.find((key) => key.toLowerCase().replace(/\.$/, "") === String(name).toLowerCase().replace(/\.$/, ""));
  if (chain.resource && (isIPv4(chain.resource) || isIPv6(chain.resource))) {
    const lines = [{ depth: 0, text: chain.resource, kind: "ip" }];
    const revKey = Object.keys(reverse).find((key) => key === chain.resource);
    for (const ptr of revKey ? reverse[revKey] : []) lines.push({ depth: 1, text: String(ptr).replace(/\.$/, ""), kind: "ptr" });
    return lines;
  }
  const lines = [];
  const seen = new Set();
  function walk(name, depth) {
    const id = String(name).toLowerCase();
    if (depth > 12 || seen.has(id)) return;
    seen.add(id);
    lines.push({ depth, text: String(name).replace(/\.$/, ""), kind: "name" });
    for (const item of forward[findKey(name)] || []) {
      const value = String(item).replace(/\.$/, "");
      if (isIPv4(value) || isIPv6(value)) {
        lines.push({ depth: depth + 1, text: value, kind: "ip" });
        const revKey = Object.keys(reverse).find((key) => key === value);
        for (const ptr of revKey ? reverse[revKey] : []) lines.push({ depth: depth + 2, text: String(ptr).replace(/\.$/, ""), kind: "ptr" });
      } else walk(value, depth + 1);
    }
  }
  if (chain.resource) walk(chain.resource, 0);
  return lines;
}

export { DNS_STATUS };
