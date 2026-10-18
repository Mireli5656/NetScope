
"use strict";

const SOURCES = {
  internetDB: "https://internetdb.shodan.io/",
  ipapi: "https://ipapi.co/",
  atlas: "https://atlas.ipinfo.app/api/v2/ip/"
};

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

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }
  return node;
}

function value(v) {
  if (Array.isArray(v)) return v.length ? v.join(", ") : "None reported";
  if (v === null || v === undefined || v === "") return "Not reported";
  return String(v);
}

async function fetchJSON(url, signal) {
  const response = await fetch(url, {
    headers: { Accept: "application/json" },
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
    return { _sourceError: error.message };
  }
}

function addInfo(label, val, source = "") {
  const row = el("div", "info-row");
  const key = el("span", "info-key", label);
  const content = el("span", "info-value", value(val));

  if (source) content.title = `Source: ${source}`;

  row.append(key, content);
  overview.appendChild(row);
}

function renderOverview(ip, db, geo, atlas) {
  overview.replaceChildren();

  const atlasLocation = atlas.location || {};
  const atlasASN = atlas.as_number
    ? `AS${atlas.as_number}`
    : "";

  addInfo("IP address", ip, "Input");
  addInfo("Country", geo.country_name || atlas.country, "ipapi / Atlas");
  addInfo("Country code", geo.country || atlas.country_code, "ipapi / Atlas");
  addInfo("City", geo.city || atlasLocation.city, "ipapi / Atlas");
  addInfo("Region", geo.region || atlasLocation.region, "ipapi / Atlas");
  addInfo("Coordinates",
    geo.latitude != null && geo.longitude != null
      ? `${geo.latitude}, ${geo.longitude}`
      : atlasLocation.latitude != null && atlasLocation.longitude != null
        ? `${atlasLocation.latitude}, ${atlasLocation.longitude}`
        : null,
    "ipapi / Atlas"
  );
  addInfo("ASN", geo.asn || atlasASN, "ipapi / Atlas");
  addInfo("Organization / ISP", geo.org || atlas.as_description, "ipapi / Atlas");
  addInfo("BGP prefix", atlas.cidr, "Atlas");
  addInfo("Timezone", geo.timezone, "ipapi");
  addInfo("Hostnames", db.hostnames, "Shodan InternetDB");
  addInfo("Tags", db.tags, "Shodan InternetDB");
  addInfo("CPEs", db.cpes, "Shodan InternetDB");
  addInfo("Known CVEs", db.vulns, "Shodan InternetDB");
}

function renderPorts(db) {
  portsContainer.replaceChildren();

  const ports = Array.isArray(db.ports)
    ? [...new Set(db.ports)].sort((a, b) => a - b)
    : [];

  portCount.textContent = String(ports.length);

  if (!ports.length) {
    portsContainer.appendChild(
      el("div", "empty-state", "No ports reported by InternetDB.")
    );
    return;
  }

  ports.forEach(port => {
    portsContainer.appendChild(el("span", "port-chip", port));
  });
}

function renderRecords(db) {
  bannersContainer.replaceChildren();

  const groups = [
    ["Known vulnerabilities (CVE)", db.vulns],
    ["Detected technologies (CPE)", db.cpes],
    ["Tags", db.tags],
    ["Hostnames", db.hostnames]
  ];

  const records = groups.flatMap(([title, list]) =>
    (Array.isArray(list) ? list : []).map(item => ({ title, item }))
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

async function lookup(ip) {
  if (!validIPv4(ip)) {
    showStatus("Enter a valid IPv4 address, e.g. 8.8.8.8.", "error");
    ipInput.focus();
    return;
  }

  if (controller) controller.abort();

  controller = new AbortController();
  const current = controller;
  const timeout = setTimeout(() => current.abort(), 20000);

  searchButton.disabled = true;
  buttonLabel.textContent = "Analyzing...";
  results.hidden = true;
  showStatus("Collecting data from InternetDB, ipapi.co and Atlas...");

  const encodedIP = encodeURIComponent(ip);

  try {
    const [dbResult, geoResult, atlasResult] = await Promise.all([
      optionalJSON(SOURCES.internetDB + encodedIP, current.signal),
      optionalJSON(SOURCES.ipapi + encodedIP + "/json/", current.signal),
      optionalJSON(SOURCES.atlas + encodedIP, current.signal)
    ]);

    if (dbResult._sourceError &&
        geoResult._sourceError &&
        atlasResult._sourceError) {
      throw new Error(
        "All sources failed. Check your internet connection or API availability."
      );
    }

    const db = dbResult._sourceError ? {} : dbResult;
    const geo = geoResult._sourceError ? {} : geoResult;
    const atlas = atlasResult._sourceError ? {} : atlasResult;

    results.hidden = false;
    resultIP.textContent = ip;
    shodanLink.href =
      "https://www.shodan.io/host/" + encodedIP;

    countryStat.textContent =
      geo.country_name || atlas.country || "N/A";

    renderOverview(ip, db, geo, atlas);
    renderPorts(db);
    renderRecords(db);

    const successful = [
      !dbResult._sourceError,
      !geoResult._sourceError,
      !atlasResult._sourceError
    ].filter(Boolean).length;

    if (successful === 3) {
      showStatus("Lookup completed. All three sources responded.", "success");
    } else {
      showStatus(
        `Lookup completed with partial data (${successful}/3 sources). Some providers may have blocked the request or be temporarily unavailable.`,
        "error"
      );
    }

    results.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    showStatus(
      error.name === "AbortError"
        ? "Request timed out. Please try again."
        : error.message || "Lookup failed.",
      "error"
    );
  } finally {
    clearTimeout(timeout);

    if (controller === current) {
      controller = null;
      searchButton.disabled = false;
      buttonLabel.textContent = "Analyze IP";
    }
  }
}

form.addEventListener("submit", event => {
  event.preventDefault();
  lookup(ipInput.value.trim());
});
