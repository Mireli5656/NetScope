"use strict";

/*
 * NetScope — passive public-IP intelligence
 * Sources: Shodan InternetDB, ipapi.co, Atlas IPinfo and Shodan CVEDB.
 * No port scan is performed. Product/CPE matches are potential matches only.
 */

const SOURCES = {
  internetDB: "https://internetdb.shodan.io/",
  ipapi: "https://ipapi.co/",
  atlas: "https://atlas.ipinfo.app/api/v2/ip/"
};

const CVEDB_API = "https://cvedb.shodan.io";
const $ = id => document.getElementById(id);

const form = $("search-form");
const ipInput = $("ip-input");
const searchButton = $("search-button");
const buttonLabel = $("button-label");
const statusBox = $("status");
const results = $("results");
const overview = $("overview");
const portsContainer = $("ports");
const bannersContainer = $("banners");
const portCount = $("port-count");
const serviceCount = $("service-count");
const countryStat = $("country-stat");
const resultIP = $("result-ip");
const shodanLink = $("shodan-link");
const bannerCount = $("banner-count");

let activeController = null;
let securityPanel = null;

const cveCache = new Map();
const cpeCache = new Map();

let kevCache = null;
let kevCacheTime = 0;

const CACHE_TTL = 30 * 60 * 1000;
const MAX_DIRECT_CVES = 8;
const MAX_CPE_QUERIES = 5;
const MAX_PRODUCT_CVES = 20;
const MAX_KEV_CVES = 8;

function showStatus(message, type = "") {
  if (!statusBox) return;

  statusBox.textContent = message;
  statusBox.className = "status";

  if (type) statusBox.classList.add(type);

  statusBox.hidden = false;
}

function validIPv4(ip) {
  const parts = String(ip).split(".");

  return parts.length === 4 && parts.every(part =>
    /^\d{1,3}$/.test(part) &&
    !(part.length > 1 && part.startsWith("0")) &&
    Number(part) >= 0 &&
    Number(part) <= 255
  );
}

function ipv4ToNumber(ip) {
  return ip.split(".").reduce(
    (total, part) => total * 256 + Number(part),
    0
  );
}

function inIPv4Range(number, network, prefix) {
  const start = ipv4ToNumber(network);
  const size = 2 ** (32 - prefix);

  return Math.floor(number / size) ===
    Math.floor(start / size);
}

function isPublicIPv4(ip) {
  if (!validIPv4(ip)) return false;

  const specialRanges = [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4]
  ];

  const number = ipv4ToNumber(ip);

  return !specialRanges.some(([network, prefix]) =>
    inIPv4Range(number, network, prefix)
  );
}

function el(tag, className = "", text) {
  const node = document.createElement(tag);

  if (className) node.className = className;

  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }

  return node;
}

function displayValue(item) {
  if (Array.isArray(item)) {
    return item.length ? item.join(", ") : "None reported";
  }

  if (item === null || item === undefined || item === "") {
    return "Not reported";
  }

  return String(item);
}

async function fetchJSON(url, signal) {
  const response = await fetch(url, {
    method: "GET",
    headers: {
      Accept: "application/json"
    },
    signal,
    cache: "no-store"
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  return response.json();
}

async function optionalJSON(url, signal) {
  try {
    return await fetchJSON(url, signal);
  } catch (error) {
    if (error && error.name === "AbortError") {
      throw error;
    }

    return {
      _sourceError: error && error.message
        ? error.message
        : "Request failed"
    };
  }
}

function addInfo(label, val, source = "") {
  const row = el("div", "info-row");
  const key = el("span", "info-key", label);
  const content = el("span", "info-value", displayValue(val));

  if (source) {
    content.title = `Source: ${source}`;
  }

  row.append(key, content);
  overview.appendChild(row);
}

function getCveIds(rawVulns) {
  if (!Array.isArray(rawVulns)) return [];

  const ids = rawVulns.map(item => {
    if (typeof item === "string") {
      return item.trim().toUpperCase();
    }

    if (item && typeof item === "object") {
      return String(
        item.cve || item.id || item.cve_id || ""
      ).trim().toUpperCase();
    }

    return "";
  }).filter(id => /^CVE-\d{4}-\d{4,}$/.test(id));

  return [...new Set(ids)];
}

function renderOverview(ip, db, geo, atlas) {
  overview.replaceChildren();

  const location = atlas.location || {};
  const asn = atlas.as_number
    ? `AS${atlas.as_number}`
    : "";

  const coordinates =
    geo.latitude != null && geo.longitude != null
      ? `${geo.latitude}, ${geo.longitude}`
      : location.latitude != null && location.longitude != null
        ? `${location.latitude}, ${location.longitude}`
        : null;

  addInfo("IP address", ip, "Input");
  addInfo("Country", geo.country_name || atlas.country, "ipapi / Atlas");
  addInfo("Country code", geo.country || atlas.country_code, "ipapi / Atlas");
  addInfo("City", geo.city || location.city, "ipapi / Atlas");
  addInfo("Region", geo.region || location.region, "ipapi / Atlas");
  addInfo("Coordinates", coordinates, "ipapi / Atlas");
  addInfo("ASN", geo.asn || asn, "ipapi / Atlas");
  addInfo(
    "Organization / ISP",
    geo.org || atlas.as_description,
    "ipapi / Atlas"
  );
  addInfo("BGP prefix", atlas.cidr, "Atlas");
  addInfo("Timezone", geo.timezone, "ipapi");
  addInfo("Hostnames", db.hostnames, "Shodan InternetDB");
  addInfo("Tags", db.tags, "Shodan InternetDB");
  addInfo("CPEs", db.cpes, "Shodan InternetDB");
  addInfo(
    "Host CVEs reported",
    getCveIds(db.vulns).length,
    "Shodan InternetDB"
  );
}

function getReportedPorts(db) {
  return Array.isArray(db.ports)
    ? [
        ...new Set(
          db.ports
            .map(Number)
            .filter(port =>
              Number.isInteger(port) &&
              port >= 1 &&
              port <= 65535
            )
        )
      ].sort((a, b) => a - b)
    : [];
}

function renderPorts(db) {
  portsContainer.replaceChildren();

  const ports = getReportedPorts(db);

  portCount.textContent = String(ports.length);

  if (!ports.length) {
    portsContainer.appendChild(
      el("div", "empty-state", "No ports reported by InternetDB.")
    );
    return;
  }

  ports.forEach(port => {
    portsContainer.appendChild(
      el("span", "port-chip", port)
    );
  });
}

function renderRecords(db) {
  bannersContainer.replaceChildren();

  const groups = [
    ["Detected technologies (CPE)", db.cpes],
    ["Tags", db.tags],
    ["Hostnames", db.hostnames]
  ];

  const records = groups.flatMap(([title, list]) =>
    (Array.isArray(list) ? list : [])
      .map(item => ({ title, item }))
  );

  serviceCount.textContent = String(records.length);

  bannerCount.textContent =
    `${records.length} ${records.length === 1 ? "record" : "records"}`;

  if (!records.length) {
    bannersContainer.appendChild(
      el("div", "empty-state", "No additional records reported.")
    );
    return;
  }

  records.forEach((record, index) => {
    const card = el("article", "banner-card");
    const heading = el("div", "banner-heading");

    heading.append(
      el("span", "", record.title),
      el("span", "", `#${index + 1}`)
    );

    card.append(
      heading,
      el("pre", "banner-body", record.item)
    );

    bannersContainer.appendChild(card);
  });
}

function normalizeCpe23(raw) {
  if (typeof raw !== "string") return null;

  const cpe = raw.trim();

  if (cpe.startsWith("cpe:2.3:")) {
    const parts = cpe.split(":");

    if (
      parts.length >= 5 &&
      ["a", "h", "o"].includes(parts[2]) &&
      parts[3] &&
      parts[4]
    ) {
      return parts.slice(0, Math.min(parts.length, 13)).join(":");
    }

    return null;
  }

  // Convert older InternetDB identifiers such as:
  // cpe:/a:apache:http_server:2.4.49
  if (cpe.startsWith("cpe:/")) {
    const parts = cpe.slice(5).split(":");

    const part = parts[0];
    const vendor = parts[1];
    const product = parts[2];
    const version = parts[3] || "*";

    if (
      !["a", "h", "o"].includes(part) ||
      !vendor ||
      !product
    ) {
      return null;
    }

    const values = [
      part,
      vendor,
      product,
      version,
      "*",
      "*",
      "*",
      "*",
      "*",
      "*",
      "*"
    ];

    return `cpe:2.3:${values.join(":")}`;
  }

  return null;
}

function recordId(record) {
  const id = String(
    record && (record.cve_id || record.id || record.cve) || ""
  ).toUpperCase();

  return /^CVE-\d{4}-\d{4,}$/.test(id) ? id : "";
}

function cveUrl(id) {
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`;
}

function severityFromScore(score) {
  if (
    score === null ||
    score === undefined ||
    score === "" ||
    !Number.isFinite(Number(score))
  ) {
    return "Unrated";
  }

  const number = Number(score);

  if (number >= 9) return "Critical";
  if (number >= 7) return "High";
  if (number >= 4) return "Medium";
  if (number > 0) return "Low";

  return "None";
}

function severityClass(severity) {
  const value = String(severity || "").toLowerCase();

  if (value === "critical") return "risk-badge risk-critical";
  if (value === "high") return "risk-badge risk-high";
  if (value === "medium") return "risk-badge risk-medium";
  if (value === "low") return "risk-badge risk-low";

  return "risk-badge risk-unknown";
}

function safeExternalLink(url, label) {
  try {
    const parsed = new URL(url);

    if (
      parsed.protocol !== "https:" &&
      parsed.protocol !== "http:"
    ) {
      return null;
    }

    const link = el("a", "", label || parsed.hostname);

    link.href = parsed.href;
    link.target = "_blank";
    link.rel = "noopener noreferrer";

    return link;
  } catch (_error) {
    return null;
  }
}

function formatDate(input) {
  if (!input) return "Not reported";

  const date = new Date(input);

  return Number.isNaN(date.getTime())
    ? String(input)
    : date.toISOString().slice(0, 10);
}

function injectSecurityStyles() {
  if ($("netscope-security-styles")) return;

  const style = el("style");
  style.id = "netscope-security-styles";

  style.textContent = `
    .security-panel {
      margin-top: 22px;
    }

    .security-summary {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
      margin: 16px 0 20px;
    }

    .security-metric {
      min-width: 0;
      padding: 15px;
      border: 1px solid var(--border, #243047);
      border-radius: 13px;
      background: rgba(20, 31, 49, .62);
    }

    .security-metric-label {
      display: block;
      color: var(--muted, #8c9ab2);
      font-size: 11px;
      font-weight: 800;
      letter-spacing: .7px;
      text-transform: uppercase;
    }

    .security-metric-value {
      display: block;
      margin-top: 7px;
      font-size: clamp(19px, 3vw, 27px);
      font-weight: 800;
      line-height: 1.25;
      overflow-wrap: anywhere;
    }

    .security-metric-note {
      display: block;
      margin-top: 5px;
      color: var(--muted, #8c9ab2);
      font-size: 12px;
    }

    .security-note {
      margin: 12px 0;
      padding: 12px 14px;
      border: 1px solid var(--border, #243047);
      border-radius: 11px;
      color: var(--muted, #8c9ab2);
      font-size: 13px;
      line-height: 1.55;
    }

    .security-subheading {
      margin: 22px 0 10px;
      font-size: 15px;
    }

    .cve-list {
      display: grid;
      gap: 12px;
    }

    .cve-card {
      min-width: 0;
      padding: 15px;
      border: 1px solid var(--border, #243047);
      border-radius: 13px;
      background: rgba(9, 13, 23, .38);
    }

    .cve-card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      flex-wrap: wrap;
    }

    .cve-link {
      color: var(--cyan, #54d8e8);
      font-weight: 800;
      text-decoration: underline;
      text-underline-offset: 3px;
    }

    .risk-badge {
      display: inline-flex;
      align-items: center;
      padding: 4px 9px;
      border: 1px solid var(--border, #243047);
      border-radius: 99px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: .3px;
    }

    .risk-critical {
      color: #ff7788;
      border-color: rgba(255, 119, 136, .5);
      background: rgba(255, 119, 136, .09);
    }

    .risk-high {
      color: #ffad75;
      border-color: rgba(255, 173, 117, .45);
      background: rgba(255, 173, 117, .08);
    }

    .risk-medium {
      color: #f5d27a;
      border-color: rgba(245, 210, 122, .4);
      background: rgba(245, 210, 122, .08);
    }

    .risk-low {
      color: var(--green, #46d6a0);
      border-color: rgba(70, 214, 160, .35);
      background: rgba(70, 214, 160, .07);
    }

    .risk-unknown {
      color: var(--muted, #8c9ab2);
    }

    .cve-description {
      margin: 12px 0;
      color: var(--text, #edf2ff);
      font-size: 13px;
      line-height: 1.65;
      overflow-wrap: anywhere;
    }

    .cve-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 7px 14px;
      color: var(--muted, #8c9ab2);
      font-size: 12px;
    }

    .cve-reference-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px 14px;
      margin-top: 12px;
      font-size: 12px;
    }

    .cve-reference-list a {
      color: var(--cyan, #54d8e8);
      overflow-wrap: anywhere;
    }

    .security-empty {
      padding: 13px;
      border: 1px dashed var(--border, #243047);
      border-radius: 10px;
      color: var(--muted, #8c9ab2);
      font-size: 13px;
    }

    .intel-label {
      display: inline-flex;
      align-items: center;
      margin: 0 0 10px;
      padding: 4px 8px;
      border: 1px solid var(--border, #243047);
      border-radius: 6px;
      color: var(--muted, #8c9ab2);
      font-size: 10px;
      font-weight: 800;
      letter-spacing: .5px;
      text-transform: uppercase;
    }

    .port-warning-list {
      display: grid;
      gap: 8px;
      margin: 10px 0 0;
      padding-left: 20px;
      color: var(--muted, #8c9ab2);
      font-size: 13px;
    }

    @media (max-width: 620px) {
      .security-summary {
        grid-template-columns: 1fr;
        gap: 9px;
      }

      .security-metric,
      .cve-card {
        padding: 12px;
      }
    }
  `;

  document.head.appendChild(style);
}

function ensureSecurityPanel() {
  if (securityPanel) return securityPanel;

  injectSecurityStyles();

  securityPanel = el("section", "panel security-panel");
  securityPanel.id = "security-analysis";

  securityPanel.setAttribute(
    "aria-labelledby",
    "security-analysis-title"
  );

  const heading = el("div", "panel-heading");
  const titleWrap = el("div");

  const title = el("h3", "", "Vulnerability intelligence");
  title.id = "security-analysis-title";

  titleWrap.append(
    title,
    el(
      "p",
      "panel-description",
      "Passive analysis using public InternetDB and Shodan CVEDB records. No port scan is performed."
    )
  );

  const badge = el("span", "count-badge", "CVE intelligence");
  heading.append(titleWrap, badge);

  const summary = el("div", "security-summary");
  summary.id = "security-summary";

  const note = el("div", "security-note");
  note.id = "security-risk-note";

  const hostTitle = el("h4", "security-subheading", "Host CVEs");
  const hostList = el("div", "cve-list");
  hostList.id = "host-cve-list";

  const productTitle = el(
    "h4",
    "security-subheading",
    "Potential product/CPE CVE matches"
  );

  const productNote = el(
    "p",
    "security-note",
    "These CVEs are associated with product identifiers reported by InternetDB. They are possible matches only, not proof that this host is affected."
  );

  const productList = el("div", "cve-list");
  productList.id = "product-cve-list";

  const kevTitle = el(
    "h4",
    "security-subheading",
    "Global Known Exploited Vulnerabilities (KEV)"
  );

  const kevNote = el(
    "p",
    "security-note",
    "This is a global threat-intelligence sample, not a list of vulnerabilities detected on the searched IP. It is not included in host-risk indicators."
  );

  const kevList = el("div", "cve-list");
  kevList.id = "global-kev-list";

  const portTitle = el(
    "h4",
    "security-subheading",
    "Port exposure indicators"
  );

  const portList = el(
    "div",
    "security-empty",
    "No indicators evaluated yet."
  );

  portList.id = "port-risk-list";

  securityPanel.append(
    heading,
    summary,
    note,
    hostTitle,
    hostList,
    productTitle,
    productNote,
    productList,
    kevTitle,
    kevNote,
    kevList,
    portTitle,
    portList
  );

  const contentGrid = results.querySelector(".content-grid");

  if (contentGrid) {
    results.insertBefore(securityPanel, contentGrid);
  } else {
    results.appendChild(securityPanel);
  }

  return securityPanel;
}

function makeMetric(label, metricValue, note) {
  const card = el("div", "security-metric");

  card.append(
    el("span", "security-metric-label", label),
    el("strong", "security-metric-value", metricValue),
    el("span", "security-metric-note", note)
  );

  return card;
}

function renderCveCard(record, mode) {
  const id = recordId(record) ||
    String(record && record.id || "Unknown CVE");

  const card = el("article", "cve-card");
  const header = el("div", "cve-card-header");
  const link = safeExternalLink(cveUrl(id), id);

  if (link) {
    link.className = "cve-link";
    header.appendChild(link);
  } else {
    header.appendChild(el("strong", "", id));
  }

  const score =
    record &&
    record.cvss !== null &&
    record.cvss !== undefined
      ? Number(record.cvss)
      : NaN;

  const severity = Number.isFinite(score)
    ? severityFromScore(score)
    : "Unrated";

  let badgeText = Number.isFinite(score)
    ? `${severity} · ${score.toFixed(1)}`
    : severity;

  if (record && record.kev) {
    badgeText += " · KEV";
  }

  header.appendChild(
    el("span", severityClass(severity), badgeText)
  );

  card.appendChild(header);

  if (mode === "direct") {
    card.appendChild(
      el("span", "intel-label", "Reported by InternetDB for this IP")
    );
  }

  if (mode === "product") {
    card.appendChild(
      el(
        "span",
        "intel-label",
        "Potential CPE/product match — not confirmed"
      )
    );
  }

  if (mode === "kev") {
    card.appendChild(
      el(
        "span",
        "intel-label",
        "Global KEV feed — not IP-specific"
      )
    );
  }

  const summary = record && (record.summary || record.description);

  card.appendChild(
    el(
      "p",
      "cve-description",
      summary || "No summary was returned by CVEDB."
    )
  );

  const meta = el("div", "cve-meta");

  if (Number.isFinite(score)) {
    meta.appendChild(
      el(
        "span",
        "",
        `CVSS v${record.cvss_version || "?"}: ${score.toFixed(1)}`
      )
    );
  }

  if (
    record &&
    record.epss !== null &&
    record.epss !== undefined &&
    Number.isFinite(Number(record.epss))
  ) {
    meta.appendChild(
      el(
        "span",
        "",
        `EPSS: ${(Number(record.epss) * 100).toFixed(1)}%`
      )
    );
  }

  if (record && record.published_time) {
    meta.appendChild(
      el("span", "", `Published: ${formatDate(record.published_time)}`)
    );
  }

  if (record && record.vendor) {
    meta.appendChild(el("span", "", `Vendor: ${record.vendor}`));
  }

  if (record && record.product) {
    meta.appendChild(el("span", "", `Product: ${record.product}`));
  }

  card.appendChild(meta);

  if (record && Array.isArray(record.references) && record.references.length) {
    const refs = el("div", "cve-reference-list");

    record.references.slice(0, 3).forEach((url, index) => {
      const refLink = safeExternalLink(url, `Reference ${index + 1} ↗`);

      if (refLink) refs.appendChild(refLink);
    });

    if (refs.childNodes.length) {
      card.appendChild(refs);
    }
  }

  return card;
}

const PORT_ADVISORIES = {
  21: "FTP is reported. Check for clear-text authentication and restrict network access.",
  23: "Telnet is reported. It is unencrypted; prefer SSH and restrict access.",
  445: "SMB is reported. Restrict it to trusted networks and keep it patched.",
  3389: "Remote Desktop (RDP) is reported. Restrict exposure and use strong authentication, ideally with MFA.",
  5900: "VNC is reported. Restrict access and verify encryption and authentication.",
  2375: "A Docker API port is reported. Verify remote access is authenticated and tightly restricted.",
  9200: "An Elasticsearch HTTP port is reported. Verify authentication and access controls.",
  27017: "MongoDB is reported. Verify the database is not publicly accessible without strong access controls.",
  6379: "Redis is reported. Verify authentication and firewall rules.",
  3306: "MySQL is reported. Database access should normally be restricted to trusted hosts.",
  5432: "PostgreSQL is reported. Database access should normally be restricted to trusted hosts."
};

function renderPortAdvisories(db) {
  const container = $("port-risk-list");
  container.replaceChildren();

  const ports = getReportedPorts(db);
  const flagged = ports.filter(port => PORT_ADVISORIES[port]);

  if (!flagged.length) {
    container.className = "security-empty";

    container.textContent = ports.length
      ? "No ports in this basic advisory list were reported. This does not mean all services are secure."
      : "No ports were reported by InternetDB, so there are no port indicators to display.";

    return 0;
  }

  container.className = "";

  const list = el("ul", "port-warning-list");

  flagged.forEach(port => {
    list.appendChild(
      el("li", "", `Port ${port}: ${PORT_ADVISORIES[port]}`)
    );
  });

  container.append(
    list,
    el(
      "p",
      "security-note",
      "These are review prompts based on indexed port data, not confirmed vulnerabilities. InternetDB data may be stale and this tool does not test current reachability."
    )
  );

  return flagged.length;
}

async function getCveDetails(id, signal) {
  if (cveCache.has(id)) {
    return cveCache.get(id);
  }

  const result = await optionalJSON(
    `${CVEDB_API}/cve/${encodeURIComponent(id)}`,
    signal
  );

  if (!result._sourceError && recordId(result)) {
    cveCache.set(id, result);
    return result;
  }

  return {
    cve_id: id,
    _sourceError: result._sourceError || "No record returned"
  };
}

async function getDirectCveRecords(ids, signal) {
  const chosen = ids.slice(0, MAX_DIRECT_CVES);

  const records = await Promise.all(
    chosen.map(id => getCveDetails(id, signal))
  );

  return {
    records,
    truncated: ids.length > chosen.length
  };
}

async function getProductCveMatches(rawCpes, signal) {
  const inputCpes = Array.isArray(rawCpes) ? rawCpes : [];

  const cpes = [
    ...new Set(
      inputCpes.map(normalizeCpe23).filter(Boolean)
    )
  ].slice(0, MAX_CPE_QUERIES);

  if (!cpes.length) {
    return {
      records: [],
      queried: 0,
      failed: false,
      truncatedCpes: false
    };
  }

  const settled = await Promise.all(
    cpes.map(async cpe => {
      const cached = cpeCache.get(cpe);

      if (cached && Date.now() - cached.time < CACHE_TTL) {
        return cached.records;
      }

      const url =
        `${CVEDB_API}/cves?cpe23=${encodeURIComponent(cpe)}&limit=20`;

      const payload = await optionalJSON(url, signal);

      if (payload._sourceError) {
        return {
          _sourceError: true,
          records: []
        };
      }

      const records = Array.isArray(payload.cves)
        ? payload.cves
        : Array.isArray(payload)
          ? payload
          : [];

      cpeCache.set(cpe, {
        time: Date.now(),
        records
      });

      return records;
    })
  );

  let failed = false;
  const unique = new Map();

  settled.forEach(result => {
    if (result && result._sourceError) {
      failed = true;
      return;
    }

    (Array.isArray(result) ? result : []).forEach(record => {
      const id = recordId(record);

      if (id && !unique.has(id)) {
        unique.set(id, record);
      }
    });
  });

  const sorted = [...unique.values()].sort(
    (a, b) => Number(b.cvss || 0) - Number(a.cvss || 0)
  );

  return {
    records: sorted.slice(0, MAX_PRODUCT_CVES),
    queried: cpes.length,
    failed,
    truncatedCpes: inputCpes.length > cpes.length
  };
}

async function getGlobalKev(signal) {
  if (kevCache && Date.now() - kevCacheTime < CACHE_TTL) {
    return {
      records: kevCache,
      failed: false
    };
  }

  const payload = await optionalJSON(
    `${CVEDB_API}/cves?is_kev=true&sort_by_epss=true&limit=${MAX_KEV_CVES}`,
    signal
  );

  if (payload._sourceError) {
    return {
      records: [],
      failed: true
    };
  }

  const records = Array.isArray(payload.cves)
    ? payload.cves
    : Array.isArray(payload)
      ? payload
      : [];

  kevCache = records.slice(0, MAX_KEV_CVES);
  kevCacheTime = Date.now();

  return {
    records: kevCache,
    failed: false
  };
}

function renderCveSection(container, records, mode, emptyMessage) {
  container.replaceChildren();

  const valid = (records || []).filter(
    record => record && (recordId(record) || record._sourceError)
  );

  if (!valid.length) {
    container.appendChild(
      el("div", "security-empty", emptyMessage)
    );
    return;
  }

  valid.forEach(record => {
    if (record._sourceError) {
      const card = el("article", "cve-card");
      const header = el("div", "cve-card-header");

      const link = safeExternalLink(
        cveUrl(record.cve_id),
        record.cve_id
      );

      if (link) header.appendChild(link);

      card.append(
        header,
        el(
          "p",
          "cve-description",
          `${record.cve_id}: CVEDB could not return details. Open the NVD record to review it.`
        )
      );

      container.appendChild(card);
    } else {
      container.appendChild(
        renderCveCard(record, mode)
      );
    }
  });
}

function renderSecurityAnalysis(db, directData, productData, kevData) {
  ensureSecurityPanel();

  const summary = $("security-summary");
  const note = $("security-risk-note");

  const direct = directData.records || [];
  const products = productData.records || [];
  const kevs = kevData.records || [];

  const reportedIds = getCveIds(db.vulns);

  const directScores = direct
    .filter(record =>
      !record._sourceError &&
      record.cvss !== null &&
      record.cvss !== undefined &&
      Number.isFinite(Number(record.cvss))
    )
    .map(record => Number(record.cvss));

  const productScores = products
    .filter(record =>
      record.cvss !== null &&
      record.cvss !== undefined &&
      Number.isFinite(Number(record.cvss))
    )
    .map(record => Number(record.cvss));

  const allHostRelatedScores = [
    ...directScores,
    ...productScores
  ];

  const highest = allHostRelatedScores.length
    ? Math.max(...allHostRelatedScores)
    : null;

  const productKevCount = products.filter(
    record => record.kev === true
  ).length;

  const portIndicators = renderPortAdvisories(db);

  summary.replaceChildren();

  summary.append(
    makeMetric(
      "Host CVEs",
      reportedIds.length,
      "Directly reported by InternetDB"
    ),
    makeMetric(
      "Potential CPE matches",
      products.length,
      "Product associations; not confirmed"
    ),
    makeMetric(
      "Highest CVSS",
      highest === null ? "N/A" : highest.toFixed(1),
      "Among host/CPE results only; global KEV excluded"
    )
  );

  const paragraphs = [];

  if (reportedIds.length) {
    paragraphs.push(
      `InternetDB reported ${reportedIds.length} CVE identifier(s). CVEDB details were retrieved for up to ${MAX_DIRECT_CVES}.`
    );
  } else {
    paragraphs.push(
      "InternetDB did not report CVE identifiers for this IP. That alone does not prove the host is free of vulnerabilities."
    );
  }

  if (products.length) {
    paragraphs.push(
      `${products.length} potential CVE match(es) were found through product/CPE associations. They may not apply to the software version actually running on this host.`
    );
  } else if (productData.queried) {
    paragraphs.push(
      "No matching CVEs were returned for the CPE identifiers queried. This is not a guarantee that the products are secure."
    );
  } else {
    paragraphs.push(
      "No usable CPE identifiers were available for product-associated CVE lookups."
    );
  }

  if (portIndicators) {
    paragraphs.push(
      `${portIndicators} indexed-port review indicator(s) are shown below; port numbers alone do not confirm a vulnerability.`
    );
  }

  if (productKevCount) {
    paragraphs.push(
      `${productKevCount} potential product match(es) are flagged in CVEDB as KEV; verify affected product/version before drawing conclusions.`
    );
  }

  note.textContent = paragraphs.join(" ");

  renderCveSection(
    $("host-cve-list"),
    direct,
    "direct",
    reportedIds.length
      ? "No detailed records were available from CVEDB for the reported identifiers."
      : "No CVE identifiers were reported by InternetDB for this IP."
  );

  renderCveSection(
    $("product-cve-list"),
    products,
    "product",
    productData.failed
      ? "CPE lookup was partly unavailable. This is not a clean bill of health."
      : "No potential CPE-associated CVEs were returned for the indexed product identifiers."
  );

  renderCveSection(
    $("global-kev-list"),
    kevs,
    "kev",
    kevData.failed
      ? "The global KEV feed could not be loaded in this session."
      : "No global KEV records were returned by the feed."
  );

  const badge = securityPanel.querySelector(
    ".panel-heading .count-badge"
  );

  if (badge) {
    badge.textContent =
      `${reportedIds.length} host CVE${reportedIds.length === 1 ? "" : "s"} · ${products.length} possible match${products.length === 1 ? "" : "es"}`;
  }

  if (directData.truncated) {
    $("host-cve-list").appendChild(
      el(
        "p",
        "security-note",
        `Only the first ${MAX_DIRECT_CVES} directly reported CVEs were enriched in this lookup.`
      )
    );
  }

  if (productData.truncatedCpes) {
    $("product-cve-list").appendChild(
      el(
        "p",
        "security-note",
        `Only the first ${MAX_CPE_QUERIES} CPE identifiers were queried to keep the lookup lightweight.`
      )
    );
  }
}

async function lookup(ip) {
  if (!validIPv4(ip)) {
    showStatus(
      "Enter a valid IPv4 address, e.g. 8.8.8.8.",
      "error"
    );
    ipInput.focus();
    return;
  }

  if (!isPublicIPv4(ip)) {
    showStatus(
      "Enter a public IPv4 address. Private and special-use IP ranges are not sent to third-party services.",
      "error"
    );
    ipInput.focus();
    return;
  }

  if (activeController) {
    activeController.abort();
  }

  activeController = new AbortController();

  const current = activeController;
  const sourceTimeout = setTimeout(
    () => current.abort(),
    25000
  );

  searchButton.disabled = true;
  buttonLabel.textContent = "Analyzing...";
  results.hidden = true;

  showStatus(
    "Collecting public host, network and vulnerability intelligence..."
  );

  const encodedIP = encodeURIComponent(ip);

  try {
    const [
      dbResult,
      geoResult,
      atlasResult
    ] = await Promise.all([
      optionalJSON(
        SOURCES.internetDB + encodedIP,
        current.signal
      ),
      optionalJSON(
        SOURCES.ipapi + encodedIP + "/json/",
        current.signal
      ),
      optionalJSON(
        SOURCES.atlas + encodedIP,
        current.signal
      )
    ]);

    if (activeController !== current) return;

    if (
      dbResult._sourceError &&
      geoResult._sourceError &&
      atlasResult._sourceError
    ) {
      throw new Error(
        "All public-data sources failed. Check your connection or try again later."
      );
    }

    const db = dbResult._sourceError ? {} : dbResult;
    const geo = geoResult._sourceError ? {} : geoResult;
    const atlas = atlasResult._sourceError ? {} : atlasResult;

    const ids = getCveIds(db.vulns);

    showStatus(
      "Public data received. Enriching reported CVEs, CPE matches and global KEV intelligence..."
    );

    const [
      directData,
      productData,
      kevData
    ] = await Promise.all([
      getDirectCveRecords(ids, current.signal),
      getProductCveMatches(db.cpes, current.signal),
      getGlobalKev(current.signal)
    ]);

    if (activeController !== current) return;

    results.hidden = false;

    resultIP.textContent = ip;
    shodanLink.href =
      "https://www.shodan.io/host/" + encodedIP;

    countryStat.textContent =
      geo.country_name || atlas.country || "N/A";

    renderOverview(ip, db, geo, atlas);
    renderPorts(db);
    renderRecords(db);

    renderSecurityAnalysis(
      db,
      directData,
      productData,
      kevData
    );

    const successfulSources = [
      !dbResult._sourceError,
      !geoResult._sourceError,
      !atlasResult._sourceError
    ].filter(Boolean).length;

    const cveProblems =
      directData.records.some(record => record._sourceError) ||
      productData.failed ||
      kevData.failed;

    if (successfulSources === 3) {
      showStatus(
        cveProblems
          ? "Lookup completed with partial vulnerability intelligence. Review the source notes below."
          : "Lookup completed. Public host and passive vulnerability intelligence loaded.",
        "success"
      );
    } else {
      showStatus(
        `Lookup completed with partial public data (${successfulSources}/3 host sources). Some data providers may be unavailable.`,
        "error"
      );
    }

    results.scrollIntoView({
      behavior: "smooth",
      block: "start"
    });
  } catch (error) {
    if (activeController === current) {
      showStatus(
        error && error.name === "AbortError"
          ? "The lookup timed out. Please try again."
          : (error && error.message) || "Lookup failed.",
        "error"
      );
    }
  } finally {
    clearTimeout(sourceTimeout);

    if (activeController === current) {
      activeController = null;
      searchButton.disabled = false;
      buttonLabel.textContent = "Analyze IP";
    }
  }
}

// Re-label the older record panel without changing index.html or style.css.
const oldBannerPanel = bannersContainer.closest(".panel");

const oldBannerHeading =
  oldBannerPanel && oldBannerPanel.querySelector("h3");

if (oldBannerHeading) {
  oldBannerHeading.textContent = "Additional intelligence";
}

const oldBannerDescription =
  oldBannerPanel &&
  oldBannerPanel.querySelector(".panel-description");

if (oldBannerDescription) {
  oldBannerDescription.textContent =
    "Hostnames, detected technologies (CPEs) and tags reported by InternetDB.";
}

const serviceCard = serviceCount.closest(".stat-card");

const serviceLabel =
  serviceCard && serviceCard.querySelector(".stat-label");

const serviceNote =
  serviceCard && serviceCard.querySelector(".stat-note");

if (serviceLabel) {
  serviceLabel.textContent = "Intel Records";
}

if (serviceNote) {
  serviceNote.textContent = "CPEs, tags and hostnames";
}

form.addEventListener("submit", event => {
  event.preventDefault();
  lookup(ipInput.value.trim());
});
