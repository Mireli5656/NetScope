"use strict";

const SOURCES = {
  internetDB: "https://internetdb.shodan.io/",
  ipapi: "https://ipapi.co/",
  atlas: "https://atlas.ipinfo.app/api/v2/ip/"
};

const NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_WINDOW_MS = 30_000;
const NVD_REQUEST_BUDGET = 4;
const NVD_CACHE = new Map();
let nvdRequestTimes = [];

const $ = (id) => document.getElementById(id);

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

let controller = null;
let securityPanel = null;

function showStatus(message, type = "") {
  statusBox.textContent = message;
  statusBox.className = "status";
  if (type) statusBox.classList.add(type);
  statusBox.hidden = false;
}

function validIPv4(ip) {
  const parts = ip.split(".");
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

function inIPv4Range(ipNumber, network, prefix) {
  const networkNumber = ipv4ToNumber(network);
  const blockSize = 2 ** (32 - prefix);

  return (
    Math.floor(ipNumber / blockSize) ===
    Math.floor(networkNumber / blockSize)
  );
}

function isPublicIPv4(ip) {
  if (!validIPv4(ip)) return false;

  // Do not send private or special-use IP addresses
  // to third-party public intelligence providers.
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

function el(tag, className, text) {
  const node = document.createElement(tag);

  if (className) node.className = className;

  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }

  return node;
}

function value(v) {
  if (Array.isArray(v)) {
    return v.length ? v.join(", ") : "None reported";
  }

  if (v === null || v === undefined || v === "") {
    return "Not reported";
  }

  return String(v);
}

async function fetchJSON(url, signal) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/json"
    },
    signal
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
    if (error.name === "AbortError") throw error;

    return {
      _sourceError: error.message || "Request failed"
    };
  }
}

function addInfo(label, val, source = "") {
  const row = el("div", "info-row");
  const key = el("span", "info-key", label);
  const content = el("span", "info-value", value(val));

  if (source) {
    content.title = `Source: ${source}`;
  }

  row.append(key, content);
  overview.appendChild(row);
}

function renderOverview(ip, db, geo, atlas) {
  overview.replaceChildren();

  const atlasLocation = atlas.location || {};
  const atlasASN = atlas.as_number
    ? `AS${atlas.as_number}`
    : "";

  const cveCount = Array.isArray(db.vulns)
    ? getCveIds(db.vulns).length
    : 0;

  addInfo("IP address", ip, "Input");

  addInfo(
    "Country",
    geo.country_name || atlas.country,
    "ipapi / Atlas"
  );

  addInfo(
    "Country code",
    geo.country || atlas.country_code,
    "ipapi / Atlas"
  );

  addInfo(
    "City",
    geo.city || atlasLocation.city,
    "ipapi / Atlas"
  );

  addInfo(
    "Region",
    geo.region || atlasLocation.region,
    "ipapi / Atlas"
  );

  addInfo(
    "Coordinates",
    geo.latitude != null && geo.longitude != null
      ? `${geo.latitude}, ${geo.longitude}`
      : atlasLocation.latitude != null &&
        atlasLocation.longitude != null
        ? `${atlasLocation.latitude}, ${atlasLocation.longitude}`
        : null,
    "ipapi / Atlas"
  );

  addInfo(
    "ASN",
    geo.asn || atlasASN,
    "ipapi / Atlas"
  );

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
    "Known CVEs reported",
    cveCount,
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
      el(
        "div",
        "empty-state",
        "No ports reported by InternetDB."
      )
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
    (Array.isArray(list) ? list : []).map(item => ({
      title,
      item
    }))
  );

  serviceCount.textContent = String(records.length);

  bannerCount.textContent =
    `${records.length} ${records.length === 1 ? "record" : "records"}`;

  if (!records.length) {
    bannersContainer.appendChild(
      el(
        "div",
        "empty-state",
        "No additional records reported."
      )
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

function getCveIds(rawVulns) {
  if (!Array.isArray(rawVulns)) return [];

  const ids = rawVulns
    .map(item => {
      if (typeof item === "string") {
        return item.trim().toUpperCase();
      }

      if (item && typeof item === "object") {
        return String(
          item.cve || item.id || item.cve_id || ""
        ).trim().toUpperCase();
      }

      return "";
    })
    .filter(id => /^CVE-\d{4}-\d{4,}$/.test(id));

  return [...new Set(ids)];
}

function normalizeSeverity(severity, score, version) {
  const supplied = String(severity || "")
    .trim()
    .toLowerCase();

  if (
    ["critical", "high", "medium", "low", "none"]
      .includes(supplied)
  ) {
    return supplied.charAt(0).toUpperCase() +
      supplied.slice(1);
  }

  if (!Number.isFinite(score)) return "Unrated";
  if (score === 0) return "None";

  if (version === "2.0") {
    if (score < 4) return "Low";
    if (score < 7) return "Medium";
    return "High";
  }

  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";

  return "Critical";
}

function extractCvss(cve) {
  const metrics = cve && cve.metrics
    ? cve.metrics
    : {};

  const candidates = [
    ["4.0", metrics.cvssMetricV40],
    ["3.1", metrics.cvssMetricV31],
    ["3.0", metrics.cvssMetricV30],
    ["2.0", metrics.cvssMetricV2]
  ];

  for (const [fallbackVersion, entries] of candidates) {
    if (!Array.isArray(entries) || !entries.length) {
      continue;
    }

    const metric =
      entries.find(entry => entry.type === "Primary") ||
      entries[0];

    const data = metric && metric.cvssData
      ? metric.cvssData
      : {};

    const score = Number(data.baseScore);

    if (Number.isFinite(score)) {
      const version = String(
        data.version || fallbackVersion
      );

      return {
        version,
        score,
        severity: normalizeSeverity(
          data.baseSeverity || metric.baseSeverity,
          score,
          version
        ),
        vector: data.vectorString || ""
      };
    }
  }

  return null;
}

function parseCveResponse(id, payload) {
  const entry = Array.isArray(payload.vulnerabilities)
    ? payload.vulnerabilities[0]
    : null;

  if (!entry || !entry.cve) {
    return {
      id,
      found: false,
      notFound: true
    };
  }

  const cve = entry.cve;

  const descriptions = Array.isArray(cve.descriptions)
    ? cve.descriptions
    : [];

  const description =
    descriptions.find(
      item => item.lang === "en" && item.value
    ) ||
    descriptions.find(item => item.value) ||
    null;

  const weaknesses = Array.isArray(cve.weaknesses)
    ? [
        ...new Set(
          cve.weaknesses.flatMap(item =>
            (
              Array.isArray(item.description)
                ? item.description
                : []
            )
              .map(desc => desc.value)
              .filter(value => /^CWE-\d+$/i.test(value || ""))
          )
        )
      ]
    : [];

  const references = Array.isArray(cve.references)
    ? cve.references
        .map(item => ({
          url: item.url,
          tags: Array.isArray(item.tags)
            ? item.tags
            : []
        }))
        .filter(item =>
          typeof item.url === "string" &&
          /^https?:\/\//i.test(item.url)
        )
        .slice(0, 3)
    : [];

  return {
    id,
    found: true,
    status: cve.vulnStatus || "Not reported",
    description: description
      ? description.value
      : "No description was supplied by NVD.",
    published: cve.published || "",
    lastModified: cve.lastModified || "",
    sourceIdentifier: cve.sourceIdentifier || "",
    cvss: extractCvss(cve),
    weaknesses,
    references
  };
}

function userFriendlyNvdError(error) {
  const message = String(
    error && error.message
      ? error.message
      : ""
  );

  if (/HTTP 403|HTTP 429/i.test(message)) {
    return "NVD temporarily refused the request or rate-limited it. Try again later.";
  }

  if (/HTTP 5\d\d/i.test(message)) {
    return "NVD is temporarily unavailable.";
  }

  if (error && error.name === "AbortError") {
    return "NVD lookup timed out; this CVE was not assessed in this pass.";
  }

  return "NVD could not be reached from this browser. Check connectivity or CORS availability.";
}

async function fetchCveDetails(id, signal) {
  try {
    const url =
      `${NVD_API}?cveId=${encodeURIComponent(id)}`;

    const payload = await fetchJSON(url, signal);
    const parsed = parseCveResponse(id, payload);

    NVD_CACHE.set(id, parsed);

    return parsed;
  } catch (error) {
    return {
      id,
      found: false,
      lookupError: userFriendlyNvdError(error)
    };
  }
}

async function enrichCveIds(ids, signal) {
  const now = Date.now();

  nvdRequestTimes = nvdRequestTimes.filter(
    timestamp => now - timestamp < NVD_WINDOW_MS
  );

  const missing = ids.filter(
    id => !NVD_CACHE.has(id)
  );

  const availableBudget = Math.max(
    0,
    NVD_REQUEST_BUDGET - nvdRequestTimes.length
  );

  const selected = missing.slice(0, availableBudget);

  // Keep this tab's requests under a conservative rolling budget.
  selected.forEach(() => {
    nvdRequestTimes.push(Date.now());
  });

  const fetched = await Promise.all(
    selected.map(id => fetchCveDetails(id, signal))
  );

  const fetchedById = new Map(
    fetched.map(detail => [detail.id, detail])
  );

  return ids.map(id => {
    if (NVD_CACHE.has(id)) {
      return NVD_CACHE.get(id);
    }

    if (fetchedById.has(id)) {
      return fetchedById.get(id);
    }

    return {
      id,
      found: false,
      notQueried: true
    };
  });
}

function injectSecurityStyles() {
  if (document.getElementById("netscope-security-styles")) {
    return;
  }

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

    .port-warning-list {
      display: grid;
      gap: 8px;
      margin: 10px 0 0;
      padding-left: 20px;
      color: var(--muted, #8c9ab2);
      font-size: 13px;
    }

    .security-empty {
      padding: 13px;
      border: 1px dashed var(--border, #243047);
      border-radius: 10px;
      color: var(--muted, #8c9ab2);
      font-size: 13px;
    }

    @media (max-width: 620px) {
      .security-summary {
        grid-template-columns: 1fr;
        gap: 9px;
      }

      .security-metric {
        padding: 12px;
      }

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
  const headingText = el("div");

  headingText.append(
    el("h3", "", "Vulnerability intelligence"),
    el(
      "p",
      "panel-description",
      "Passive analysis based on public InternetDB and NVD records. No port scan is performed."
    )
  );

  const badge = el("span", "count-badge", "CVE analysis");

  heading.append(headingText, badge);

  headingText.querySelector("h3").id =
    "security-analysis-title";

  const summary = el("div", "security-summary");
  summary.id = "security-summary";

  const riskNote = el("div", "security-note");
  riskNote.id = "security-risk-note";

  const cveHeading = el(
    "h4",
    "security-subheading",
    "CVE details"
  );

  const cveList = el("div", "cve-list");
  cveList.id = "cve-list";

  const portHeading = el(
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
    riskNote,
    cveHeading,
    cveList,
    portHeading,
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

function severityClass(severity) {
  const key = String(severity || "").toLowerCase();

  if (key === "critical") {
    return "risk-badge risk-critical";
  }

  if (key === "high") {
    return "risk-badge risk-high";
  }

  if (key === "medium") {
    return "risk-badge risk-medium";
  }

  if (key === "low") {
    return "risk-badge risk-low";
  }

  return "risk-badge risk-unknown";
}

function formattedDate(input) {
  if (!input) return "Not reported";

  const date = new Date(input);

  return Number.isNaN(date.getTime())
    ? input
    : date.toISOString().slice(0, 10);
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

    const link = el(
      "a",
      "",
      label || parsed.hostname
    );

    link.href = parsed.href;
    link.target = "_blank";
    link.rel = "noopener noreferrer";

    return link;
  } catch (_error) {
    return null;
  }
}

function renderCveCard(id, detail) {
  const card = el("article", "cve-card");
  const header = el("div", "cve-card-header");

  const link = safeExternalLink(
    `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`,
    id
  );

  if (link) {
    link.className = "cve-link";
    header.appendChild(link);
  } else {
    header.appendChild(el("strong", "", id));
  }

  let badgeText = "Not enriched";
  let badgeClass = severityClass("unknown");

  if (
    detail &&
    detail.found &&
    String(detail.status || "").toLowerCase() === "rejected"
  ) {
    badgeText = "Rejected by NVD";
  } else if (detail && detail.found && detail.cvss) {
    badgeText =
      `${detail.cvss.severity} · ${detail.cvss.score.toFixed(1)}`;

    badgeClass = severityClass(detail.cvss.severity);
  } else if (detail && detail.found) {
    badgeText = "No CVSS score";
  } else if (detail && detail.notFound) {
    badgeText = "Not found in NVD";
  } else if (detail && detail.lookupError) {
    badgeText = "Lookup unavailable";
  }

  header.appendChild(
    el("span", badgeClass, badgeText)
  );

  card.appendChild(header);

  if (detail && detail.found) {
    card.appendChild(
      el("p", "cve-description", detail.description)
    );

    const meta = el("div", "cve-meta");

    meta.appendChild(
      el(
        "span",
        "",
        `Status: ${detail.status || "Not reported"}`
      )
    );

    if (detail.cvss) {
      meta.appendChild(
        el(
          "span",
          "",
          `CVSS v${detail.cvss.version}: ${detail.cvss.score.toFixed(1)}`
        )
      );
    }

    meta.appendChild(
      el(
        "span",
        "",
        `Published: ${formattedDate(detail.published)}`
      )
    );

    meta.appendChild(
      el(
        "span",
        "",
        `Modified: ${formattedDate(detail.lastModified)}`
      )
    );

    if (detail.weaknesses && detail.weaknesses.length) {
      meta.appendChild(
        el(
          "span",
          "",
          `Weaknesses: ${detail.weaknesses.join(", ")}`
        )
      );
    }

    card.appendChild(meta);

    if (detail.references && detail.references.length) {
      const references = el("div", "cve-reference-list");

      detail.references.forEach(reference => {
        const refLink = safeExternalLink(
          reference.url,
          "Reference ↗"
        );

        if (refLink) references.appendChild(refLink);
      });

      if (references.childNodes.length) {
        card.appendChild(references);
      }
    }

    if (
      detail.status &&
      String(detail.status).toLowerCase() === "rejected"
    ) {
      card.appendChild(
        el(
          "p",
          "security-note",
          "NVD marks this CVE as rejected. It is not counted toward the observed CVSS summary."
        )
      );
    }
  } else if (detail && detail.notFound) {
    card.appendChild(
      el(
        "p",
        "cve-description",
        "NVD returned no matching CVE record. This does not establish whether the host is vulnerable."
      )
    );
  } else if (detail && detail.lookupError) {
    card.appendChild(
      el(
        "p",
        "cve-description",
        detail.lookupError
      )
    );
  } else {
    card.appendChild(
      el(
        "p",
        "cve-description",
        "Not enriched in this pass. The public NVD request budget may have been reached; the CVE can still be opened on NVD using the link above."
      )
    );
  }

  return card;
}

const PORT_ADVISORIES = {
  21: "FTP is reported. Confirm whether it permits clear-text authentication and restrict access where possible.",
  23: "Telnet is reported. Telnet is unencrypted; prefer SSH and restrict network access.",
  445: "SMB is reported. Restrict it to trusted networks and keep the service patched.",
  3389: "Remote Desktop (RDP) is reported. Restrict exposure and use strong authentication, ideally with MFA.",
  5900: "VNC is reported. Restrict access and verify encryption and authentication settings.",
  2375: "A Docker API port is reported. Verify that remote access is authenticated and tightly restricted.",
  9200: "An Elasticsearch HTTP port is reported. Verify that authentication and access controls prevent public data exposure.",
  27017: "MongoDB is reported. Verify that the database is not publicly accessible without strong access controls.",
  6379: "Redis is reported. Verify authentication and firewall rules; do not assume public exposure is safe.",
  3306: "MySQL is reported. Database access should normally be restricted to trusted hosts.",
  5432: "PostgreSQL is reported. Database access should normally be restricted to trusted hosts."
};

function renderPortAdvisories(db) {
  const container = $("port-risk-list");
  container.replaceChildren();

  const ports = getReportedPorts(db);
  const flagged = ports.filter(
    port => PORT_ADVISORIES[port]
  );

  if (!flagged.length) {
    container.className = "security-empty";

    container.textContent = ports.length
      ? "No ports in this basic advisory list were reported. This does not mean that every service is secure."
      : "No ports were reported by InternetDB, so there are no port indicators to display.";

    return 0;
  }

  container.className = "";

  const list = el("ul", "port-warning-list");

  flagged.forEach(port => {
    list.appendChild(
      el(
        "li",
        "",
        `Port ${port}: ${PORT_ADVISORIES[port]}`
      )
    );
  });

  container.appendChild(list);

  container.appendChild(
    el(
      "p",
      "security-note",
      "These are review prompts based on indexed port data, not confirmed vulnerabilities. InternetDB data can be stale and this tool does not test whether a service is currently reachable."
    )
  );

  return flagged.length;
}

function renderSecurityAnalysis(db, cveDetails) {
  ensureSecurityPanel();

  const summary = $("security-summary");
  const riskNote = $("security-risk-note");
  const cveList = $("cve-list");

  const detailsById = new Map(
    cveDetails.map(detail => [detail.id, detail])
  );

  const ids = getCveIds(db.vulns);

  const scored = cveDetails.filter(detail =>
    detail &&
    detail.found &&
    String(detail.status || "").toLowerCase() !== "rejected" &&
    detail.cvss
  );

  const highest = scored.reduce(
    (best, detail) =>
      !best || detail.cvss.score > best.cvss.score
        ? detail
        : best,
    null
  );

  const portIndicators = renderPortAdvisories(db);

  const highOrCritical = scored.filter(
    detail => detail.cvss.score >= 7
  ).length;

  const unqueried = cveDetails.filter(
    detail => detail.notQueried
  ).length;

  const failed = cveDetails.filter(
    detail => detail.lookupError
  ).length;

  summary.replaceChildren();

  summary.append(
    makeMetric(
      "Reported CVEs",
      ids.length,
      "From Shodan InternetDB"
    ),
    makeMetric(
      "CVEs with CVSS",
      scored.length,
      "Enriched successfully in this session"
    ),
    makeMetric(
      "Highest CVSS",
      highest
        ? highest.cvss.score.toFixed(1)
        : (ids.length ? "Unrated" : "N/A"),
      highest
        ? `${highest.id} · ${highest.cvss.severity}`
        : "No usable NVD score available"
    )
  );

  riskNote.replaceChildren();

  let summaryText;

  if (highest) {
    summaryText =
      `Highest score observed among the CVEs enriched in this pass: ` +
      `${highest.cvss.score.toFixed(1)} (${highest.cvss.severity}), ` +
      `from ${highest.id}. ${highOrCritical} enriched CVE(s) have ` +
      `a CVSS score of 7.0 or higher. This is vulnerability intelligence, ` +
      `not proof that the scanned host runs an affected product version.`;
  } else if (ids.length) {
    summaryText =
      "InternetDB reported CVE identifiers, but no usable CVSS score was available from the CVEs enriched in this pass. Treat the result as unassessed, not low risk.";
  } else {
    summaryText =
      "InternetDB did not report CVE identifiers for this IP. This is not proof that the host is free of vulnerabilities.";
  }

  if (portIndicators) {
    summaryText +=
      ` ${portIndicators} port-based review indicator(s) were also reported below; ` +
      "port numbers alone do not prove a vulnerability.";
  }

  riskNote.textContent = summaryText;

  cveList.replaceChildren();

  if (!ids.length) {
    cveList.appendChild(
      el(
        "div",
        "security-empty",
        "No CVE identifiers were reported by InternetDB for this IP."
      )
    );
  } else {
    ids.forEach(id => {
      cveList.appendChild(
        renderCveCard(id, detailsById.get(id))
      );
    });
  }

  const headingBadge =
    securityPanel.querySelector(
      ".panel-heading .count-badge"
    );

  if (headingBadge) {
    headingBadge.textContent =
      `${ids.length} reported CVE${ids.length === 1 ? "" : "s"}`;
  }

  const notes = [];

  if (unqueried) {
    notes.push(
      `${unqueried} CVE(s) were not queried because the conservative unauthenticated NVD request budget was reached.`
    );
  }

  if (failed) {
    notes.push(
      `${failed} CVE lookup(s) could not be completed; the relevant cards show the limitation.`
    );
  }

  if (notes.length) {
    cveList.appendChild(
      el("p", "security-note", notes.join(" "))
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

  if (controller) controller.abort();

  controller = new AbortController();

  const current = controller;

  let sourceTimeout = setTimeout(
    () => current.abort(),
    20000
  );

  let nvdTimeout = null;
  let nvdController = null;
  let cancelNvdOnNewLookup = null;

  searchButton.disabled = true;
  buttonLabel.textContent = "Analyzing...";
  results.hidden = true;

  showStatus("Collecting public host and network data...");

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

    if (controller !== current) return;

    clearTimeout(sourceTimeout);
    sourceTimeout = null;

    if (
      dbResult._sourceError &&
      geoResult._sourceError &&
      atlasResult._sourceError
    ) {
      throw new Error(
        "All sources failed. Check your internet connection or source availability."
      );
    }

    const db = dbResult._sourceError
      ? {}
      : dbResult;

    const geo = geoResult._sourceError
      ? {}
      : geoResult;

    const atlas = atlasResult._sourceError
      ? {}
      : atlasResult;

    const cveIds = getCveIds(db.vulns);

    showStatus(
      cveIds.length
        ? `Public data received. Enriching up to ${NVD_REQUEST_BUDGET} CVE records with NVD...`
        : "Public data received. Preparing the security report..."
    );

    nvdController = new AbortController();

    cancelNvdOnNewLookup = () => {
      if (nvdController) nvdController.abort();
    };

    current.signal.addEventListener(
      "abort",
      cancelNvdOnNewLookup,
      { once: true }
    );

    nvdTimeout = setTimeout(
      () => nvdController.abort(),
      12000
    );

    const cveDetails = await enrichCveIds(
      cveIds,
      nvdController.signal
    );

    clearTimeout(nvdTimeout);
    nvdTimeout = null;

    if (cancelNvdOnNewLookup) {
      current.signal.removeEventListener(
        "abort",
        cancelNvdOnNewLookup
      );

      cancelNvdOnNewLookup = null;
    }

    if (controller !== current) return;

    results.hidden = false;

    resultIP.textContent = ip;

    shodanLink.href =
      "https://www.shodan.io/host/" + encodedIP;

    countryStat.textContent =
      geo.country_name || atlas.country || "N/A";

    renderOverview(ip, db, geo, atlas);
    renderPorts(db);
    renderRecords(db);
    renderSecurityAnalysis(db, cveDetails);

    const successful = [
      !dbResult._sourceError,
      !geoResult._sourceError,
      !atlasResult._sourceError
    ].filter(Boolean).length;

    const nvdProblems = cveDetails.some(
      detail => detail.lookupError || detail.notQueried
    );

    if (successful === 3) {
      showStatus(
        nvdProblems
          ? "Lookup completed. Public host data loaded; CVE enrichment is partial. See the security report for details."
          : "Lookup completed. Public host data and available CVE enrichment loaded.",
        "success"
      );
    } else {
      showStatus(
        `Lookup completed with partial host data (${successful}/3 sources). Some providers may be unavailable; review the source notes and security report.`,
        "error"
      );
    }

    results.scrollIntoView({
      behavior: "smooth",
      block: "start"
    });
  } catch (error) {
    if (controller === current) {
      showStatus(
        error.name === "AbortError"
          ? "The host lookup timed out. Please try again."
          : error.message || "Lookup failed.",
        "error"
      );
    }
  } finally {
    if (sourceTimeout) clearTimeout(sourceTimeout);
    if (nvdTimeout) clearTimeout(nvdTimeout);

    if (cancelNvdOnNewLookup) {
      current.signal.removeEventListener(
        "abort",
        cancelNvdOnNewLookup
      );
    }

    if (controller === current) {
      controller = null;
      searchButton.disabled = false;
      buttonLabel.textContent = "Analyze IP";
    }
  }
}

// Update the existing panel labels without changing index.html.
const oldBannerHeading =
  bannersContainer.closest(".panel")?.querySelector("h3");

if (oldBannerHeading) {
  oldBannerHeading.textContent = "Additional intelligence";
}

const oldBannerDescription =
  bannersContainer.closest(".panel")
    ?.querySelector(".panel-description");

if (oldBannerDescription) {
  oldBannerDescription.textContent =
    "Hostnames, detected technologies (CPEs) and tags reported by InternetDB.";
}

const serviceLabel =
  serviceCount.closest(".stat-card")
    ?.querySelector(".stat-label");

const serviceNote =
  serviceCount.closest(".stat-card")
    ?.querySelector(".stat-note");

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
