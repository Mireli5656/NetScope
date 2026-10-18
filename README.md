# NetScope 🌐

A lightweight, multi-source IP intelligence dashboard built with HTML, CSS, and JavaScript.

NetScope collects publicly available IP information from multiple sources and displays it in a clean, responsive interface.

🔗 **Live Demo:** [https://mireli5656.github.io/NetScope/](https://mireli5656.github.io/NetScope/)

## ✨ Features

- 🔍 **IP Lookup** — Search public IPv4 addresses.
- 🌍 **Geolocation** — Country, region, city, coordinates, and timezone.
- 🏢 **ASN & ISP Information** — Network ownership and Autonomous System Number.
- 🔌 **Open Ports** — Ports reported by Shodan InternetDB.
- 🖥️ **Hostnames** — Associated hostnames when available.
- 🛡️ **CVE Information** — Known vulnerability identifiers reported by InternetDB.
- 🧩 **CPE & Tags** — Reported technology identifiers and tags.
- 🔗 **Multiple Data Sources** — Combines information from different public services.
- 📱 **Responsive Design** — Supports desktop and mobile screens.
- 🔑 **No API Key Required** — The current implementation uses public endpoints without a Shodan API key.
- 🚀 **GitHub Pages** — No application server required.

## 🔎 Data Sources

| Source              | Information                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| **Shodan InternetDB** | Ports, hostnames, CPEs, tags, and known CVEs                               |
| **ipapi.co**          | Geolocation, ASN, organization, and timezone                               |
| **Atlas IPinfo**      | Additional ASN, network organization, and prefix information (where supported) |

> Data availability depends on each provider, its response format, rate limits, and browser CORS policies.

## 🛠️ Built With

- HTML5
- CSS3
- Vanilla JavaScript
- Public IP intelligence services
- GitHub Pages

## 🚀 Getting Started

### Run Locally

1. Clone or download this repository.
2. Open `index.html` in a modern browser.
3. Enter a public IPv4 address.
4. Click **Analyze IP** to view available information.

> Some browsers may restrict cross-origin requests when opening local HTML files. A local development server may be required.

### Deploy with GitHub Pages

1. Push the project files to your GitHub repository.
2. Open **Settings → Pages**.
3. Select **Deploy from a branch**.
4. Choose the `main` branch and `/` (root).
5. Save your settings and open the published website.

## 🔐 Privacy & Security

- No user account or password is required.
- No Shodan API key is needed by the current implementation.
- Requests are sent directly from the browser to third-party providers.
- Providers may receive the queried IP address and standard request metadata.
- NetScope does not perform active port scanning, exploitation, or vulnerability testing.
- **Never place private API keys in public JavaScript files.**

## ⚠️ Limitations

- The current version supports **IPv4 addresses only**.
- IP geolocation is approximate and does not reveal an exact physical address.
- Port and vulnerability records may be outdated or incomplete.
- InternetDB does not provide full service banners or every field available through Shodan's Host API.
- Third-party services may limit requests or block browser access.
- A reported port does not guarantee that a service is currently reachable.
- A CVE listing does not prove that a system is vulnerable or exploitable.

## 🤝 Contributing

Suggestions, bug reports, and pull requests are welcome.

When reporting a bug, include the steps to reproduce it and describe the expected behavior.

## 📄 License

No open-source license has been specified yet. Add a `LICENSE` file before distributing the project under a particular license.

---

**NetScope** — Public IP intelligence in one place.

Created by [Mireli5656](https://github.com/mireli5656).
