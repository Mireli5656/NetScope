
"use strict";

const CONFIG = {
  API_URL: "https://internetdb.shodan.io/"
};

const form = document.getElementById("search-form");
const ipInput = document.getElementById("ip-input");
const searchButton = document.getElementById("search-button");
const buttonLabel = document.getElementById("button-label");
const statusBox = document.getElementById("status");
const results = document.getElementById("results");

const overview = document.getElementById("overview");
const portsContainer = document.getElementById("ports");
const bannersContainer = document.getElementById("banners");

const portCount = document.getElementById("port-count");
const serviceCount = document.getElementById("service-count");
const countryStat = document.getElementById("country-stat");

const resultIP = document.getElementById("result-ip");
const shodanLink = document.getElementById("shodan-link");
const bannerCount = document.getElementById("banner-count");

let controller = null;

function showStatus(message, type = "") {
  statusBox.textContent = message;
  statusBox.className = "status";
  if (type) statusBox.classList.add(type);
  statusBox.hidden = false;
}

function setLoading(loading) {
  searchButton.disabled = loading;
  buttonLabel.textContent = loading ? "Loading..." : "Analyze IP";
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

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined && value !== null) {
    node.textContent = String(value);
  }
  return node;
}

function addInfo(label, value) {
  const row = element("div", "info-row");
  row.append(
    element("span", "info-key", label),
    element(
      "span",
      "info-value",
      Array.isArray(value)
        ? value.join(", ") || "None reported"
        : value || "Not reported"
    )
  );
  overview.appendChild(row);
}

function renderOverview(data, ip) {
  overview.replaceChildren();

  addInfo("IP address", data.ip || ip);
  addInfo("Hostnames", data.hostnames);
  addInfo("Tags", data.tags);
  addInfo("CPEs", data.cpes);
  addInfo("Known CVEs", data.vulns);
  addInfo("Data source", "Shodan InternetDB");
  addInfo("Update cycle", "Weekly");
}

function renderPorts(data) {
  portsContainer.replaceChildren();

  const ports = Array.isArray(data.ports)
    ? [...new Set(data.ports)].sort((a, b) => a - b)
    : [];

  portCount.textContent = String(ports.length);

  if (!ports.length) {
    portsContainer.appendChild(
      element("div", "empty-state", "No ports reported.")
    );
    return;
  }

  ports.forEach(port => {
    portsContainer.appendChild(
      element("span", "port-chip", port)
    );
  });
}

function renderBanners(data) {
  bannersContainer.replaceChildren();

  // InternetDB does not provide full service banners.
  // Display its available CPE, tag and vulnerability records instead.
  const groups = [
    ["Known vulnerabilities", data.vulns],
    ["Detected technologies (CPE)", data.cpes],
    ["Tags", data.tags],
    ["Hostnames", data.hostnames]
  ];

  const entries = groups.flatMap(([name, values]) =>
    (Array.isArray(values) ? values : []).map(value => ({
      name,
      value
    }))
  );

  serviceCount.textContent = String(entries.length);
  bannerCount.textContent =
    `${entries.length} ${entries.length === 1 ? "record" : "records"}`;

  if (!entries.length) {
    bannersContainer.appendChild(
      element(
        "div",
        "empty-state",
        "No additional records were reported by InternetDB."
      )
    );
    return;
  }

  entries.forEach((entry, index) => {
    const card = element("article", "banner-card");
    const heading = element("div", "banner-heading");

    heading.append(
      element("span", "", entry.name),
      element("span", "", `#${index + 1}`)
    );

    card.append(
      heading,
      element("pre", "banner-body", entry.value)
    );

    bannersContainer.appendChild(card);
  });
}

async function lookupIP(ip) {
  if (!validIPv4(ip)) {
    showStatus("Enter a valid IPv4 address, e.g. 8.8.8.8.", "error");
    ipInput.focus();
    return;
  }

  if (controller) controller.abort();
  controller = new AbortController();

  const currentController = controller;
  const timeout = setTimeout(
    () => currentController.abort(),
    20000
  );

  setLoading(true);
  results.hidden = true;
  showStatus(`Looking up ${ip} in Shodan InternetDB...`);

  try {
    const response = await fetch(
      CONFIG.API_URL + encodeURIComponent(ip),
      {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: currentController.signal
      }
    );

    if (response.status === 404) {
      throw new Error(
        "No InternetDB record was found for this IP address."
      );
    }

    if (!response.ok) {
      throw new Error(`InternetDB returned HTTP ${response.status}.`);
    }

    const data = await response.json();

    results.hidden = false;
    resultIP.textContent = data.ip || ip;
    shodanLink.href =
      "https://www.shodan.io/host/" + encodeURIComponent(ip);

    countryStat.textContent = "N/A";
    renderOverview(data, ip);
    renderPorts(data);
    renderBanners(data);

    showStatus("InternetDB lookup completed.", "success");

    results.scrollIntoView({
      behavior: "smooth",
      block: "start"
    });
  } catch (error) {
    if (error.name === "AbortError") {
      showStatus("Request timed out or was cancelled.", "error");
    } else if (error instanceof TypeError) {
      showStatus(
        "Could not reach InternetDB. Check your connection and try again.",
        "error"
      );
    } else {
      showStatus(error.message || "Lookup failed.", "error");
    }
  } finally {
    clearTimeout(timeout);

    if (controller === currentController) {
      controller = null;
      setLoading(false);
    }
  }
}

form.addEventListener("submit", event => {
  event.preventDefault();
  lookupIP(ipInput.value.trim());
});
