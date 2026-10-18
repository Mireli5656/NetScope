
# NetScope

NetScope is a read-only IP intelligence dashboard powered by the Shodan Host API.

## Features

- Look up IPv4 and IPv6 host records
- View observed ports
- Display ISP, organization, ASN, country, and city metadata
- Review available service banners
- Responsive interface for desktop and mobile
- Keep the Shodan API key on the server side with Cloudflare Workers

## Architecture

- **Frontend:** GitHub Pages
- **Backend:** Cloudflare Workers
- **Data source:** Shodan Host API

The frontend never receives the Shodan API key. The Worker retrieves the host record and returns a limited set of inventory fields.

## Deployment

1. Publish this repository using GitHub Pages.
2. Deploy the Cloudflare Worker backend.
3. Add `SHODAN_API_KEY` as a Cloudflare Worker secret.
4. Configure the allowed GitHub Pages origin in the Worker.
5. Set `WORKER_URL` in `index.html` to the deployed Worker URL.

## Privacy and Safety

NetScope displays existing Shodan inventory data only. It does not scan target systems, attempt authentication, exploit vulnerabilities, or access camera feeds.

Shodan data may be incomplete or outdated. A listed port does not prove that a service is currently reachable or that its owner has authorized access.

## License

MIT
