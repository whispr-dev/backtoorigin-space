/* Classic script. Opening the HTML as a file makes the origin "null", and Chrome refuses type=module there. */
(function () {
/** Classification and lookups. No DOM. */

const REDIRECT_API = "https://www.redirectcheck.org/api/check";
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

function ipv4ToInt(ip) {
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

function intToIpv4(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

function isIPv4(value) {
  return ipv4ToInt(value) != null;
}

function expandIPv6(ip) {
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

function isIPv6(value) {
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

function describeIp(ip) {
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

function isSpecialIp(ip) {
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

function classify(raw) {
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

function messageOf(err) {
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

async function redirectCheck(url, signal) {
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

function uniqueIps(rows) {
  const ips = [];
  for (const row of rows || []) {
    if ((row.type === "A" || row.type === "AAAA") && (isIPv4(row.data) || isIPv6(row.data)) && !ips.includes(row.data)) ips.push(row.data);
  }
  return ips;
}

async function loadForward(name, apex, signal) {
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

async function loadPtr(ip, signal) {
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

async function ipCard(ip, signal) {
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

async function prefixCard(prefix, signal) {
  const [overview, routing, rir, whois] = await Promise.all([
    ripe("prefix-overview", prefix, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("routing-status", prefix, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("rir", prefix, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("whois", prefix, signal).catch((err) => ({ error: messageOf(err) })),
  ]);
  return { mode: "prefix", prefix, overview, routing, rir, whois };
}

async function asnCard(asn, signal) {
  const id = `AS${asn}`;
  const [overview, neighbours, prefixes] = await Promise.all([
    ripe("as-overview", id, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("asn-neighbours", id, signal).catch((err) => ({ error: messageOf(err) })),
    ripe("announced-prefixes", id, signal).catch((err) => ({ error: messageOf(err) })),
  ]);
  return { mode: "asn", asn, overview, neighbours, prefixes };
}

async function loadRoutesForIps(ips, state, signal, publish, truncated) {
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

function chainLines(chain) {
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



const EXAMPLES = ["http://github.com", "cloudflare.com", "1.1.1.1", "AS13335"];
const RECENT_KEY = "whispr-trace-recent";
const HTTP_TEXT = {
  200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently", 302: "Found",
  303: "See Other", 307: "Temporary Redirect", 308: "Permanent Redirect", 400: "Bad Request",
  401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 410: "Gone", 429: "Too Many Requests",
  500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
};
const PORTS = {
  21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
  465: "SMTPS", 587: "mail submission", 853: "DNS over TLS", 993: "IMAPS", 3306: "MySQL",
  5432: "Postgres", 6379: "Redis", 8080: "HTTP, alternate", 8443: "HTTPS, alternate",
};
const HEADER_LEAD = ["server", "via", "content-type", "cache-control", "strict-transport-security", "alt-svc", "location", "refresh", "x-cache", "cf-ray", "x-redirect-by"];
const TYPE_ORDER = ["CNAME", "A", "AAAA", "HTTPS", "SVCB", "NS", "MX", "TXT", "CAA", "SOA", "PTR"];
const WHOIS_SKIP = new Set(["mnt-by", "mnt-routes", "mnt-irt", "mnt-lower", "last-modified", "created", "changed", "source", "auth", "notify", "remarks"]);

const GRAPH = `<svg viewBox="0 0 360 280" role="img" aria-label="Sketch of a sparse flow graph linking an entity, a relationship, an observation, a place, and time.">
  <g fill="none" stroke="#d7a15f" stroke-width="1.25">
    <path d="M58 70H150"/><path d="M170 58l90 30"/><path d="M52 78l12 70"/><path d="M160 66l12 86"/>
    <path d="M268 100l4 70"/><path d="M76 162h90"/><path d="M180 166l80 14"/><path d="M70 174l52 52"/><path d="M176 176l-42 54"/>
  </g>
  <g fill="#e7e4da">
    <circle cx="48" cy="66" r="4.5"/><circle cx="160" cy="54" r="4.5"/><circle cx="68" cy="158" r="4.5"/>
    <circle cx="172" cy="160" r="4.5"/><circle cx="122" cy="236" r="4.5"/>
  </g>
  <circle cx="268" cy="92" r="4.5" fill="#d7a15f"/><circle cx="268" cy="182" r="4.5" fill="#d7a15f"/>
  <g fill="#b7b4a8" font-family="IBM Plex Sans, Segoe UI, sans-serif" font-size="13">
    <text x="60" y="58">entity</text><text x="176" y="42">relationship</text><text x="228" y="124">observation</text>
    <text x="80" y="152">place</text><text x="186" y="154">time</text><text x="214" y="214">case</text><text x="136" y="240">source</text>
  </g>
</svg>`;

function h(tag, props, ...children) {
  const node = document.createElement(tag);
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value == null || value === false) continue;
      if (key === "class") node.className = String(value);
      else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2).toLowerCase(), value);
      else node.setAttribute(key, String(value));
    }
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function ext(href, text) {
  return h("a", { class: "jump", href, target: "_blank", rel: "noopener noreferrer", referrerpolicy: "no-referrer" }, text);
}
function retrace(query, text) {
  return h("button", { type: "button", class: "jump", "data-trace": query }, text || query);
}
function safeHttp(value) {
  try {
    const url = new URL(value);
    if (url.protocol === "http:" || url.protocol === "https:") return url.href;
  } catch { /* ignore */ }
  return null;
}
function fact(term, ...value) {
  return [h("dt", null, term), h("dd", null, ...value)];
}
function facts(pairs) {
  const rows = pairs.filter(Boolean);
  return rows.length ? h("dl", { class: "facts" }, rows.flat()) : null;
}
function statusClass(code) {
  if (code >= 200 && code < 300) return "ok";
  if (code >= 300 && code < 400) return "go";
  if (code >= 400) return "bad";
  return "";
}

function schemeNote(scheme) {
  switch (scheme) {
    case "http": return "TCP port 80, no TLS.";
    case "https": return "TLS, normally TCP 443. HTTP/3, when advertised, uses QUIC on UDP 443.";
    case "ws": return "WebSocket. It starts as HTTP, then upgrades.";
    case "wss": return "WebSocket over TLS.";
    case "ftp": return "FTP, normally TCP 21, plus a separate data connection.";
    default: return "only http and https are followed hop by hop.";
  }
}

function renderAddress(plan) {
  const pairs = [];
  if (plan.email) pairs.push(fact("Mailbox", plan.email));
  if (plan.parsed) {
    const parsed = plan.parsed;
    pairs.push(fact("Scheme", `${parsed.scheme} — ${schemeNote(parsed.scheme)}`));
    const hostLine = plan.displayHost && plan.displayHost !== parsed.host ? `${parsed.host} · typed as ${plan.displayHost}` : parsed.host;
    pairs.push(fact("Host", hostLine));
    if (plan.dnsName && (plan.dnsName.startsWith("xn--") || plan.dnsName.includes(".xn--"))) {
      pairs.push(fact("Punycode", plan.dnsName, " — the ASCII form DNS stores."));
    }
    if (parsed.port) {
      const portNote = PORTS[Number(parsed.port)];
      pairs.push(fact("Port", parsed.portExplicit ? String(parsed.port) : `${parsed.port}, the default`, portNote ? `. ${portNote}. A common assignment, not proof this host speaks it.` : ""));
    }
    pairs.push(fact("Path", parsed.path || "/"));
    if (parsed.query) {
      const keys = [...new URLSearchParams(parsed.query).keys()];
      pairs.push(fact("Query", keys.length ? keys.slice(0, 12).join(", ") : parsed.query, " · sent to the server."));
    }
    if (parsed.fragment) pairs.push(fact("Fragment", parsed.fragment, " · stays in the browser. Not sent, and not part of a redirect."));
    if (parsed.hadUser) pairs.push(fact("Credentials", "A username or password was in the URL. It was stripped and not sent."));
  }
  if (plan.address) {
    const info = plan.address;
    pairs.push(fact("Version", `IPv${info.version}`));
    pairs.push(fact("Form", info.expanded || plan.ptrIp || ""));
    if (info.hex) pairs.push(fact("Decimal", `${info.int} · ${info.hex}`));
    pairs.push(fact("Space", `${info.title}. ${info.detail}`));
    if (info.mapped) pairs.push(fact("Embedded IPv4", retrace(info.mapped)));
  }
  if (plan.kind === "asn") pairs.push(fact("ASN", `AS${plan.ripeAsn}`));
  if (plan.ripePrefix) pairs.push(fact(plan.kind === "range" ? "Range" : "Prefix", plan.ripePrefix));
  if (plan.apex && plan.dnsName) {
    pairs.push(fact("Zone guess", plan.apex === plan.dnsName ? plan.apex : `${plan.apex} (a name like www sits under this)`));
  }
  const body = facts(pairs);
  const links = [];
  if (plan.dnsName) links.push(ext(`https://dns.google/query?name=${encodeURIComponent(plan.dnsName)}&type=A`, "DNS"));
  if (plan.apex) links.push(ext(`https://rdap.org/domain/${encodeURIComponent(plan.apex)}`, "RDAP"));
  const ripeId = plan.ripeAsn ? `AS${plan.ripeAsn}` : plan.ripePrefix || plan.ptrIp || plan.dnsName;
  if (ripeId && !plan.blocked) links.push(ext(`https://stat.ripe.net/${encodeURIComponent(ripeId)}`, "RIPEstat"));
  if (!body && !links.length) return null;
  return h("section", { class: "block" }, h("h2", null, "What was entered"), body, links.length ? h("p", { class: "links" }, links) : null);
}

function headerLines(headers, lead) {
  return Object.entries(headers || {}).filter(([key]) => {
    const lower = key.toLowerCase();
    const isLead = HEADER_LEAD.includes(lower);
    return lead ? isLead && lower !== "location" : !isLead;
  }).map(([key, value]) => `${key}: ${String(value).length > 180 ? `${String(value).slice(0, 180)}…` : value}`);
}

function hopHostButton(value) {
  const href = safeHttp(value);
  if (!href) return null;
  try {
    const host = new URL(href).hostname;
    return host ? h("p", { class: "links" }, retrace(host, `Trace ${host}`)) : null;
  } catch { return null; }
}

function renderHop(hop, hopIndex, group) {
  const code = Number(hop.status) || 0;
  const kind = hop.type && hop.type !== "http" ? String(hop.type).replace(/-/g, " ") : "";
  const rest = headerLines(hop.headers, false);
  return h(
    "li", { class: "hop" },
    h("div", { class: "hop-top" },
      h("span", { class: `code ${statusClass(code)}` }, String(code || "—")),
      h("span", null, hop.final ? "Final" : HTTP_TEXT[code] || "Redirect"),
      kind ? h("span", { class: "hint" }, kind) : null,
      hop.ms != null ? h("span", { class: "code" }, `${hop.ms} ms`) : null,
    ),
    h("p", { class: "url" }, safeHttp(hop.url) ? ext(safeHttp(hop.url), hop.url) : hop.url),
    hop.to ? h("p", { class: "url" }, "→ ", safeHttp(hop.to) ? ext(safeHttp(hop.to), hop.to) : hop.to) : null,
    hop.server ? h("p", { class: "hdr" }, `server ${hop.server}`) : null,
    hop.contentType ? h("p", { class: "hdr" }, hop.contentType) : null,
    hop.canonical ? h("p", { class: "hdr" }, "canonical ", hop.canonical) : null,
    hop.robots ? h("p", { class: "hdr" }, "x-robots-tag ", hop.robots) : null,
    ...headerLines(hop.headers, true).map((line) => h("p", { class: "hdr" }, line)),
    rest.length ? h("details", { "data-keep": `hdr-${group}-${hopIndex}` }, h("summary", null, "All headers"), ...rest.map((line) => h("p", { class: "hdr" }, line))) : null,
    hopHostButton(hop.url),
  );
}

function renderOneHttp(item, index) {
  const heading = h("h3", { class: "subhead" }, item.url);
  if (item.phase === "loading") return [heading, h("p", { class: "notice" }, "Following hops…")];
  if (item.phase === "error") return [heading, h("p", { class: "err" }, item.error)];
  const data = item.data || {};
  const hops = (data.redirects || []).map((hop) => ({
    url: hop.from, status: hop.status_code, to: hop.to, type: hop.type, ms: hop.duration,
    headers: hop.headers || {}, canonical: hop.canonical, robots: hop.x_robots_tag,
  }));
  if (data.final_result) {
    hops.push({
      url: data.final_result.final_url, status: data.final_result.status_code, final: true,
      server: data.final_result.server, contentType: data.final_result.content_type,
      canonical: data.final_result.canonical, robots: data.final_result.x_robots_tag, headers: {},
    });
  }
  const finalUrl = data.final_result?.final_url;
  const count = (data.redirects || []).length;
  return [
    heading,
    h("p", { class: "hint" }, `${count} redirect${count === 1 ? "" : "s"}${data.total_duration != null ? ` · ${data.total_duration} ms end to end` : ""}`),
    data.loop?.detected ? h("p", { class: "err" }, `Loop detected${data.loop.start_step != null ? ` at hop ${data.loop.start_step}` : ""}. Browsers stop. So did this check.`) : null,
    ...(data.warnings || []).map((warning) => h("p", { class: "notice" }, warning)),
    hops.length ? h("ol", { class: "chain" }, hops.map((hop, hopIndex) => renderHop(hop, hopIndex, index))) : h("p", { class: "notice" }, "No hop data came back."),
    finalUrl ? h("p", { class: "links" },
      safeHttp(finalUrl) ? ext(safeHttp(finalUrl), "Open final") : finalUrl,
      h("button", { type: "button", class: "mini", onclick: (event) => copyText(finalUrl, event.currentTarget) }, "Copy final"),
    ) : null,
  ];
}

function renderHttp(state) {
  return h("section", { class: "block" },
    h("h2", null, "Redirects"),
    state.plan.httpNote ? h("p", { class: "hint" }, state.plan.httpNote) : null,
    h("p", { class: "hint" }, "Each hop is an HTTP response. A redirect is not a change of route. The next request still uses DNS for that hop’s host. 301 and 308 are permanent. 302 and 307 are temporary. 303 is followed as GET. 307 and 308 keep the method."),
    ...state.http.flatMap((item, index) => renderOneHttp(item, index)),
  );
}

function typeNote(type, rows) {
  const blob = rows.map((row) => row.data).join(" ");
  switch (type) {
    case "A": return rows.length > 1 ? "IPv4 addresses. More than one means clients pick, or race them." : "IPv4 address. HTTP/1.1 and HTTP/2 reach it over TCP. HTTP/3, if advertised, uses UDP.";
    case "AAAA": return "IPv6 address for the same name.";
    case "CNAME": return "Alias. This label has no address of its own. Resolvers follow it to an A or AAAA. A CNAME should be the only record at that name.";
    case "NS": return "Delegation. These servers are authoritative for the zone.";
    case "MX": return "Mail route, separate from the website. The lower number is tried first.";
    case "TXT": return /^v=spf1/i.test(blob) ? "Includes SPF, the list of servers allowed to send mail for the domain." : /^v=DMARC1/i.test(blob) ? "Includes DMARC. It tells receivers what to do when SPF or DKIM fails." : "Free-text record. Often SPF, site verification, or a policy.";
    case "CAA": return "Which certificate authorities are allowed to issue for this name.";
    case "HTTPS":
    case "SVCB": return /h3/i.test(blob) ? "Service binding. It advertises HTTP/3, QUIC over UDP 443, before the client connects." : "Service binding. It can name ALPN (h2, h3) and address hints before the connection.";
    case "SOA": return "Start of authority. After the names: serial, refresh, retry, expire, and negative-cache minimum, in seconds.";
    case "PTR": return "Reverse DNS. The address points back at a name. The site works without it.";
    default: return null;
  }
}

function linkableDns(row) {
  if ((row.type === "A" || row.type === "AAAA") && (isIPv4(row.data) || isIPv6(row.data))) return retrace(row.data);
  if ((row.type === "CNAME" || row.type === "NS" || row.type === "PTR") && row.data) return retrace(row.data);
  if (row.type === "MX" && row.data) {
    const host = row.data.replace(/^\d+\s+/, "");
    return h("span", null, row.data.slice(0, row.data.length - host.length), retrace(host, host));
  }
  return row.data;
}

function renderDns(state) {
  const dns = state.dns;
  const title = state.plan.ptrIp && !state.plan.dnsName ? "Reverse DNS" : "DNS";
  if (!dns || dns.phase === "loading") return h("section", { class: "block" }, h("h2", null, title), h("p", { class: "notice" }, "Asking 1.1.1.1 over HTTPS…"));
  if (dns.phase === "error") return h("section", { class: "block" }, h("h2", null, title), h("p", { class: "err" }, dns.error));
  const groups = new Map();
  for (const row of dns.records || []) {
    if (!groups.has(row.type)) groups.set(row.type, []);
    groups.get(row.type).push(row);
  }
  const ordered = [...TYPE_ORDER.filter((type) => groups.has(type)), ...[...groups.keys()].filter((type) => !TYPE_ORDER.includes(type))];
  const lines = chainLines(dns.chain);
  const auth = dns.chain?.authoritative_nameservers || [];
  return h("section", { class: "block" },
    h("h2", null, title),
    h("p", { class: "hint" }, "Answers from Cloudflare’s resolver, DNS-over-HTTPS. Classic DNS is UDP port 53, and TCP 53 if the answer is too big. This request is an encrypted call to 1.1.1.1, so a different resolver can still answer differently."),
    dns.nxdomain ? h("p", { class: "notice" }, "No such name (NXDOMAIN). The resolver is sure this label is not in the zone.") : null,
    groups.has("A") && groups.has("AAAA") ? h("p", { class: "hint" }, "Both IPv4 and IPv6 exist. Clients often race them and keep the winner. That is Happy Eyeballs, RFC 8305.") : null,
    ...ordered.map((type) => {
      const rows = groups.get(type);
      const note = typeNote(type, rows);
      return h("div", { class: "group" },
        h("h3", null, type),
        note ? h("p", { class: "hint" }, note) : null,
        ...rows.map((row) => h("p", { class: "rec" },
          h("span", { class: "url" }, linkableDns(row)),
          row.ttl != null ? h("span", { class: "hint" }, ` · ttl ${row.ttl}s`) : null,
          row.name && row.name !== row.data ? h("span", { class: "hint" }, ` · ${row.name}`) : null,
        )),
      );
    }),
    dns.errors?.length ? h("p", { class: "notice" }, dns.errors.join(" ")) : null,
    lines.length ? h("div", { class: "group" },
      h("h3", null, "Recursive chain"),
      h("p", { class: "hint" }, "Followed by RIPEstat’s resolvers, which may not match 1.1.1.1. A name under an address is the reverse record."),
      h("ol", { class: "chain" }, lines.map((line) => h("li", { class: "hop" }, h("p", { class: "url" }, line.depth ? `${"→ ".repeat(Math.min(line.depth, 6))}` : "", line.kind === "ip" || line.kind === "name" ? retrace(line.text) : line.text)))),
      auth.length ? h("p", { class: "hint" }, "Authoritative name servers: ", ...auth.flatMap((name, i) => [i ? ", " : "", retrace(String(name).replace(/\.$/, ""))])) : null,
    ) : dns.chainError ? h("p", { class: "notice" }, `Recursive chain unavailable. ${dns.chainError}`) : null,
  );
}

function visibilityText(routing) {
  if (!routing || routing.error || !routing.visibility) return routing?.error || null;
  const parts = [];
  if (routing.visibility.v4?.total_ris_peers) parts.push(`IPv4 by ${routing.visibility.v4.ris_peers_seeing} of ${routing.visibility.v4.total_ris_peers} RIS peers`);
  if (routing.visibility.v6?.total_ris_peers) parts.push(`IPv6 by ${routing.visibility.v6.ris_peers_seeing} of ${routing.visibility.v6.total_ris_peers} RIS peers`);
  return parts.join(". ");
}

function whoisRows(whois) {
  if (!whois || whois.error || !Array.isArray(whois.records)) return [];
  const rows = [];
  for (const group of whois.records) {
    if (!Array.isArray(group)) continue;
    for (const row of group) {
      if (!row?.key) continue;
      const key = String(row.key);
      const value = String(row.value ?? "").trim();
      if (!value || /^-+$/.test(value) || WHOIS_SKIP.has(key.toLowerCase())) continue;
      rows.push({ key, value });
    }
  }
  return rows.slice(0, 24);
}

function whoisBlock(whois, id) {
  if (whois?.error) return h("p", { class: "notice" }, `Registration: ${whois.error}`);
  const rows = whoisRows(whois);
  if (!rows.length) return null;
  return h("details", { "data-keep": id }, h("summary", null, "Registration record"), facts(rows.map((row) => fact(row.key, row.value))));
}

function resourceLinks(resource, asn) {
  const links = [ext(`https://stat.ripe.net/${encodeURIComponent(resource)}`, "RIPEstat")];
  const text = String(resource);
  const isRange = text.includes("-") && !text.includes("/");
  if (!isRange && (text.includes("/") || isIPv4(text) || isIPv6(text))) {
    links.push(ext(`https://bgp.tools/prefix/${encodeURIComponent(text)}`, "bgp.tools"));
    links.push(ext(isIPv4(text) || isIPv6(text) ? `https://bgp.he.net/ip/${encodeURIComponent(text)}` : `https://bgp.he.net/net/${encodeURIComponent(text)}`, "Hurricane Electric"));
  }
  if (asn) {
    links.push(ext(`https://bgp.tools/as/${asn}`, `bgp.tools AS${asn}`));
    links.push(ext(`https://bgp.he.net/AS${asn}`, `HE AS${asn}`));
  } else if (/^AS/i.test(text)) {
    const n = text.replace(/^AS/i, "");
    links.push(ext(`https://bgp.tools/as/${n}`, "bgp.tools"));
    links.push(ext(`https://bgp.he.net/AS${n}`, "Hurricane Electric"));
  }
  return h("p", { class: "links" }, links);
}

function originFacts(asns) {
  if (!asns?.length) return null;
  return fact("Origin", ...asns.flatMap((item, i) => [i ? "; " : "", retrace(`AS${item.asn}`, `AS${item.asn}`), item.holder ? ` ${item.holder}` : ""]));
}

function renderIp(card) {
  const prefix = card.overview?.resource || card.routing?.last_seen?.prefix || card.ip;
  const asns = card.overview?.asns || [];
  const geo = card.geo?.located_resources?.[0]?.locations?.[0];
  const place = geo ? [geo.city, geo.country].filter(Boolean).join(", ") || geo.country || "unspecified" : null;
  return h("div", { class: "panel group" },
    h("h3", { class: "subhead" }, card.ip),
    facts([
      fact("Address", retrace(card.ip)),
      prefix ? fact("Prefix", retrace(prefix)) : null,
      fact("Announced", card.overview?.error ? card.overview.error : card.overview?.announced ? "Yes, this prefix is in the global table." : "No announcement seen."),
      originFacts(asns),
      card.asnOverview && !card.asnOverview.error && card.asnOverview.block ? fact("ASN block", `${card.asnOverview.block.resource} · ${card.asnOverview.block.desc || card.asnOverview.block.name || ""}`) : null,
      card.rir?.rirs?.[0]?.rir ? fact("RIR", `${card.rir.rirs[0].rir}. The registry that allocated this space.`) : null,
      card.abuse?.abuse_contacts?.[0] ? fact("Abuse", card.abuse.abuse_contacts[0]) : null,
      place ? fact("Place", place, geo.latitude != null ? ` · ${geo.latitude}, ${geo.longitude}. Approximate registry geolocation, not a device.` : "") : null,
      visibilityText(card.routing) ? fact("Seen by", visibilityText(card.routing)) : null,
      card.routing?.first_seen?.time ? fact("History", `First seen ${card.routing.first_seen.time} from AS${card.routing.first_seen.origin}. Last seen ${card.routing.last_seen?.time || ""} from AS${card.routing.last_seen?.origin || ""}.`) : null,
      card.overview?.block ? fact("IANA block", `${card.overview.block.resource} · ${card.overview.block.desc || ""}`) : null,
    ]),
    whoisBlock(card.whois, `whois-${card.ip}`),
    resourceLinks(prefix || card.ip, asns[0]?.asn),
  );
}

function renderPrefix(card) {
  return h("div", { class: "panel group" },
    h("h3", { class: "subhead" }, card.prefix),
    facts([
      fact("Announced", card.overview?.error ? card.overview.error : card.overview?.announced ? "Yes." : "No announcement seen."),
      originFacts(card.overview?.asns),
      visibilityText(card.routing) ? fact("Seen by", visibilityText(card.routing)) : null,
      card.rir?.rirs?.[0]?.rir ? fact("RIR", card.rir.rirs[0].rir) : null,
      card.overview?.block ? fact("Covering block", `${card.overview.block.resource} · ${card.overview.block.desc || ""}`) : null,
    ]),
    whoisBlock(card.whois, `whois-${card.prefix}`),
    resourceLinks(card.prefix, card.overview?.asns?.[0]?.asn),
  );
}

function renderAsn(card) {
  const counts = card.neighbours?.neighbour_counts;
  const neighbours = [...(card.neighbours?.neighbours || [])].sort((a, b) => (b.power || 0) - (a.power || 0)).slice(0, 8);
  const prefixes = card.prefixes?.prefixes || [];
  return h("div", { class: "panel group" },
    h("h3", { class: "subhead" }, `AS${card.asn}`),
    facts([
      fact("Network", card.overview?.error ? card.overview.error : card.overview?.holder || "No holder name returned."),
      fact("Announced", card.overview?.announced ? "Yes, this AS is visible in BGP." : "Not seen as announced."),
      card.overview?.block ? fact("Number block", `${card.overview.block.resource} · ${card.overview.block.desc || card.overview.block.name || ""}`) : null,
      counts ? fact("Neighbours", `${counts.unique ?? 0} unique. RIPEstat marks ${counts.left ?? 0} left, ${counts.right ?? 0} right, ${counts.uncertain ?? 0} uncertain. Those are its names for the two directions of a relationship, not a packet path.`) : card.neighbours?.error ? fact("Neighbours", card.neighbours.error) : null,
    ]),
    neighbours.length ? h("div", { class: "chip-row" }, neighbours.map((item) => h("button", { type: "button", class: "mini", "data-trace": `AS${item.asn}` }, `AS${item.asn} · ${item.type || "link"} · ${item.power ?? 0}`))) : null,
    card.prefixes?.error ? h("p", { class: "notice" }, card.prefixes.error) : prefixes.length ? h("div", null,
      h("p", { class: "hint" }, `${prefixes.length} announced prefix${prefixes.length === 1 ? "" : "es"}.`),
      h("div", { class: "chip-row" }, prefixes.slice(0, 12).map((item) => h("button", { type: "button", class: "mini", "data-trace": item.prefix }, item.prefix))),
    ) : h("p", { class: "notice" }, "No announced prefixes returned."),
    resourceLinks(`AS${card.asn}`, card.asn),
  );
}

function renderCard(card) {
  if (card.error && !card.overview) return h("div", { class: "panel group" }, h("p", { class: "err" }, card.error));
  if (card.mode === "asn") return renderAsn(card);
  if (card.mode === "prefix") return renderPrefix(card);
  return renderIp(card);
}

function renderRoutes(state) {
  return h("section", { class: "block" },
    h("h2", null, "Routing"),
    h("p", { class: "hint" }, "BGP carries prefixes between autonomous systems over TCP port 179, router to router. The figures here are RIPE RIS observations of those announcements. This page cannot send ICMP, raw TCP, or raw UDP, so this is not a traceroute."),
    state.routePhase === "wait" ? h("p", { class: "notice" }, "Waiting for the addresses.") : null,
    state.routePhase === "loading" && !state.routes.length ? h("p", { class: "notice" }, "Asking RIPEstat…") : null,
    ...(state.routeNote || []).map((note) => h("p", { class: "notice" }, note)),
    ...state.routes.map(renderCard),
    state.routePhase === "done" && !state.routes.length && !(state.routeNote || []).length ? h("p", { class: "notice" }, "No public route to show.") : null,
  );
}

function renderNotes(plan) {
  const lines = ["The browser asks this site, and this site asks the lookup services. Same address, so the browser’s cross-site block does not apply. Redirect hops still come from redirectcheck.org. Nothing is stored here."];
  if (plan.email) lines.unshift("The mailbox and the website are different routes. MX is who accepts the mail. The redirect chain is only the site.");
  return h("section", { class: "block" }, h("h2", null, "How this was traced"), ...lines.map((line) => h("p", { class: "hint" }, line)));
}

function capture(root) {
  const ids = new Set();
  root.querySelectorAll("details[data-keep][open]").forEach((node) => ids.add(node.getAttribute("data-keep")));
  return ids;
}
function restore(root, ids) {
  root.querySelectorAll("details[data-keep]").forEach((node) => { if (ids.has(node.getAttribute("data-keep"))) node.open = true; });
}
async function copyText(text, button) {
  const previous = button.textContent;
  try { await navigator.clipboard.writeText(text); button.textContent = "Copied"; }
  catch { button.textContent = "Copy failed"; }
  setTimeout(() => { button.textContent = previous; }, 1200);
}
function readRecent() {
  try {
    const parsed = JSON.parse(sessionStorage.getItem(RECENT_KEY) || "[]");
    return Array.isArray(parsed) ? parsed.filter((item) => typeof item === "string").slice(0, 6) : [];
  } catch { return []; }
}
function pushRecent(query) {
  const trimmed = String(query).trim().slice(0, 200);
  const next = [trimmed, ...readRecent().filter((item) => item !== trimmed)].slice(0, 6);
  try { sessionStorage.setItem(RECENT_KEY, JSON.stringify(next)); } catch { /* private mode */ }
}

/**
 * @param {HTMLElement} root
 * @returns {() => void}
 */
function mount(root) {
  root.replaceChildren();
  const input = h("input", {
    id: "q", name: "q", type: "text", autocomplete: "off", spellcheck: "false",
    enterkeyhint: "go", placeholder: "https://example.com", "aria-describedby": "read",
  });
  const read = h("p", { class: "read", id: "read", "aria-live": "polite" });
  const examples = h("div", { class: "examples" });
  const results = h("div", { class: "results" });
  const status = h("p", { class: "sr", "aria-live": "polite" });
  const form = h("form", { class: "ask" }, input, h("button", { type: "submit" }, "Trace"));
  const graph = h("div", { class: "graph" });
  graph.innerHTML = GRAPH;
  const page = h("div", { class: "page" },
    h("header", { class: "topbar" }, ext("https://whispr.dev", "by whispr.dev")),
    h("div", { class: "layout" },
      h("main", { class: "tool" },
        h("h1", null, "Trace a link"),
        h("label", { class: "lead", for: "q" }, "Paste a URL, domain, IP, prefix, or ASN."),
        form, read, examples, results, status,
      ),
      h("aside", { class: "ad", "aria-label": "SkeleTrace" },
        h("h2", null, "SkeleTrace"),
        h("p", { class: "tag" }, "OSINT made simple."),
        graph,
        h("p", null, "A sparse flow-graph engine that brings entities, relationships, observations and time into one inspectable model."),
        h("p", null, "Local-first. Explore topology, geographic context and the evidence behind a case."),
        h("a", { class: "ad-cta", href: "https://skeletrace.com", target: "_blank", rel: "noopener noreferrer" }, "skeletrace.com"),
      ),
    ),
    h("footer", { class: "foot" }, "© 2026 ", ext("https://whispr.dev", "whispr.dev")),
  );
  root.append(page);

  let run = 0;
  let current = null;

  function paintRead(plan) {
    read.replaceChildren();
    if (!plan || plan.kind === "empty") return;
    read.append(plan.summary || "");
    if (plan.alt) {
      read.append(" ");
      read.append(h("button", { type: "button", class: "jump", "data-trace": plan.alt.query }, plan.alt.label));
    }
  }
  function paintExamples() {
    const recent = readRecent().filter((item) => !EXAMPLES.includes(item));
    examples.replaceChildren(
      ...EXAMPLES.map((sample) => h("button", { type: "button", class: "ex", "data-trace": sample }, sample)),
      ...recent.map((item) => h("button", { type: "button", class: "ex", "data-trace": item }, item)),
    );
  }
  function paint(state) {
    const open = capture(results);
    const chunks = [renderAddress(state.plan)];
    if (state.plan.blocked && state.plan.blockReason) chunks.push(h("p", { class: "notice block" }, state.plan.blockReason));
    if (state.http.length) chunks.push(renderHttp(state));
    if (state.dns) chunks.push(renderDns(state));
    if (state.routePhase !== "skip") chunks.push(renderRoutes(state));
    chunks.push(renderNotes(state.plan));
    if (state.http.length || state.dns || state.routes.length) {
      chunks.push(h("p", { class: "hint" }, "Sources: redirectcheck.org for hops, Cloudflare 1.1.1.1 for DNS, RIPEstat for the chain, routing, and registration."));
    }
    results.replaceChildren(...chunks.filter(Boolean));
    restore(results, open);
    const waiting = state.http.some((item) => item.phase === "loading") || state.dns?.phase === "loading" || state.routePhase === "loading" || state.routePhase === "wait";
    status.textContent = waiting ? "Tracing." : "Trace finished.";
  }

  async function execute(plan, signal) {
    const state = {
      plan,
      http: plan.httpUrls.map((url) => ({ url, phase: "loading", data: null, error: null })),
      dns: plan.dnsName || plan.ptrIp ? { phase: "loading" } : null,
      routes: [],
      routeNote: [],
      routePhase: !plan.blocked && (plan.ptrIp || plan.ripePrefix || plan.ripeAsn) ? "loading" : plan.dnsName && !plan.blocked ? "wait" : "skip",
    };
    paint(state);
    const jobs = [];
    if (!plan.blocked) {
      plan.httpUrls.forEach((url, index) => {
        jobs.push(async () => {
          try { state.http[index] = { url, phase: "done", data: await redirectCheck(url, signal), error: null }; }
          catch (err) { if (!signal.aborted) state.http[index] = { url, phase: "error", data: null, error: messageOf(err) }; }
          if (!signal.aborted) paint(state);
        });
      });
      if (plan.dnsName) {
        jobs.push(async () => {
          try {
            const pack = await loadForward(plan.dnsName, plan.apex, signal);
            state.dns = { phase: "done", ...pack };
            if (!signal.aborted) paint(state);
            const ips = uniqueIps(pack.records);
            if (ips.length) await loadRoutesForIps(ips.slice(0, 4), state, signal, paint, ips.length > 4);
            else { state.routePhase = "done"; if (!signal.aborted) paint(state); }
          } catch (err) {
            if (signal.aborted) return;
            state.dns = { phase: "error", error: messageOf(err), records: [] };
            if (state.routePhase === "wait") state.routePhase = "done";
            paint(state);
          }
        });
      }
      if (plan.ptrIp) {
        jobs.push(async () => {
          try { state.dns = { phase: "done", ...(await loadPtr(plan.ptrIp, signal)) }; }
          catch (err) { if (!signal.aborted) state.dns = { phase: "error", error: messageOf(err), records: [] }; }
          if (!signal.aborted) paint(state);
        });
        jobs.push(() => loadRoutesForIps([plan.ptrIp], state, signal, paint, false));
      }
      if (plan.ripePrefix) {
        jobs.push(async () => {
          try { state.routes.push(await prefixCard(plan.ripePrefix, signal)); }
          catch (err) { if (!signal.aborted) state.routes.push({ mode: "prefix", prefix: plan.ripePrefix, error: messageOf(err) }); }
          state.routePhase = "done";
          if (!signal.aborted) paint(state);
        });
      }
      if (plan.ripeAsn) {
        jobs.push(async () => {
          try { state.routes.push(await asnCard(plan.ripeAsn, signal)); }
          catch (err) { if (!signal.aborted) state.routes.push({ mode: "asn", asn: plan.ripeAsn, error: messageOf(err) }); }
          state.routePhase = "done";
          if (!signal.aborted) paint(state);
        });
      }
    }
    await Promise.all(jobs.map((job) => job()));
  }

  function go(value) {
    const plan = classify(value);
    paintRead(plan);
    if (plan.kind === "empty") { results.replaceChildren(); status.textContent = ""; return; }
    if (plan.kind === "unknown") {
      results.replaceChildren(h("p", { class: "notice block" }, plan.summary));
      status.textContent = plan.summary;
      return;
    }
    pushRecent(value);
    paintExamples();
    run += 1;
    current?.abort();
    current = new AbortController();
    const signal = current.signal;
    execute(plan, signal).catch(() => { if (!signal.aborted) status.textContent = "Trace stopped."; });
  }

  input.addEventListener("input", () => paintRead(classify(input.value)));
  form.addEventListener("submit", (event) => { event.preventDefault(); go(input.value); });
  page.addEventListener("click", (event) => {
    const button = event.target.closest("[data-trace]");
    if (!button || !page.contains(button)) return;
    const query = button.getAttribute("data-trace");
    if (!query) return;
    input.value = query;
    go(query);
  });
  paintExamples();
  return () => { run += 1; current?.abort(); root.replaceChildren(); };
}


  var root = document.querySelector("[data-trace-root]");
  if (root) mount(root);
})();
