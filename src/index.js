
const ALLOWED_ORIGIN = "https://mireli5656.github.io";

function jsonResponse(data, status, origin) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  };

  if (origin === ALLOWED_ORIGIN) {
    headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN;
    headers["Vary"] = "Origin";
  }

  return new Response(JSON.stringify(data), { status, headers });
}

function isValidIPv4(ip) {
  const parts = ip.split(".");
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith("0")) return false;
    const number = Number(part);
    return number >= 0 && number <= 255;
  });
}

function isValidIPv6(ip) {
  if (!ip.includes(":")) return false;

  try {
    const parsed = new URL(`http://[${ip}]/`);
    return parsed.hostname === `[${ip.toLowerCase()}]`;
  } catch {
    return false;
  }
}

function isValidIP(ip) {
  return isValidIPv4(ip) || isValidIPv6(ip);
}

function cleanText(value, maxLength = 4000) {
  if (typeof value !== "string") return "";
  return value.slice(0, maxLength);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");

    if (origin && origin !== ALLOWED_ORIGIN) {
      return jsonResponse({ error: "Origin not allowed." }, 403, null);
    }

    if (request.method === "OPTIONS") {
      if (origin !== ALLOWED_ORIGIN) {
        return new Response(null, { status: 403 });
      }

      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
          "Access-Control-Allow-Methods": "GET, OPTIONS",
          "Access-Control-Allow-Headers": "Accept",
          "Access-Control-Max-Age": "86400",
          "Vary": "Origin"
        }
      });
    }

    if (request.method !== "GET" || url.pathname !== "/api/host") {
      return jsonResponse({ error: "Not found." }, 404, origin);
    }

    const ip = (url.searchParams.get("ip") || "").trim();

    if (!isValidIP(ip)) {
      return jsonResponse({ error: "Enter a valid IPv4 or IPv6 address." }, 400, origin);
    }

    if (!env.SHODAN_API_KEY) {
      return jsonResponse({ error: "Server API key is not configured." }, 500, origin);
    }

    try {
      const apiUrl = new URL(
        `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}`
      );
      apiUrl.searchParams.set("key", env.SHODAN_API_KEY);

      const apiResponse = await fetch(apiUrl.toString(), {
        method: "GET",
        headers: { "Accept": "application/json" }
      });

      if (apiResponse.status === 404) {
        return jsonResponse(
          { error: "Shodan has no host record for this IP." },
          404,
          origin
        );
      }

      if (apiResponse.status === 401 || apiResponse.status === 403) {
        return jsonResponse(
          { error: "Shodan rejected the API key or access is not permitted." },
          502,
          origin
        );
      }

      if (apiResponse.status === 429) {
        return jsonResponse(
          { error: "Shodan API rate limit reached. Try again later." },
          429,
          origin
        );
      }

      if (!apiResponse.ok) {
        return jsonResponse(
          { error: `Shodan API returned status ${apiResponse.status}.` },
          502,
          origin
        );
      }

      const data = await apiResponse.json();

      const services = (Array.isArray(data.data) ? data.data : [])
        .slice(0, 100)
        .map((item) => ({
          port: Number.isInteger(item.port) ? item.port : null,
          transport: cleanText(item.transport, 20),
          product: cleanText(item.product, 150),
          version: cleanText(item.version, 100),
          module: cleanText(item._shodan?.module, 100),
          banner: cleanText(item.data, 4000)
        }));

      const host = {
        ip_str: cleanText(data.ip_str || ip, 100),
        country_name: cleanText(data.country_name, 100),
        country_code: cleanText(data.country_code, 10),
        city: cleanText(data.city, 150),
        org: cleanText(data.org, 200),
        isp: cleanText(data.isp, 200),
        asn: cleanText(data.asn, 50),
        ports: Array.isArray(data.ports)
          ? data.ports.filter(Number.isInteger).slice(0, 200)
          : [],
        last_update: cleanText(data.last_update, 100),
        services
      };

      return jsonResponse({ host }, 200, origin);
    } catch {
      return jsonResponse(
        { error: "Unable to reach Shodan. Try again later." },
        502,
        origin
      );
    }
  }
};
