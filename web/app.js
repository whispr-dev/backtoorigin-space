// @ts-nocheck
import {
  asnCard,
  chainLines,
  classify,
  isIPv4,
  isIPv6,
  loadForward,
  loadPtr,
  loadRoutesForIps,
  messageOf,
  prefixCard,
  redirectCheck,
  uniqueIps,
} from "./trace-core.js";

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
  const lines = ["Browser scripts cannot read another site’s Location header, and they cannot send ICMP, raw TCP, or raw UDP. Redirect hops are fetched by redirectcheck.org. Nothing is stored here."];
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
export function mount(root) {
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

export { classify };
