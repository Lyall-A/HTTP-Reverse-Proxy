# HTTP Reverse Proxy
This project has been re-written as [Yet-Another-Proxy](https://github.com/Lyall-A/Yet-Another-Proxy), there will probably be no more updates here

## NOTE: You should REALLY use [Nginx](https://www.nginx.com) instead!

A proxy that routes requests based on the host header (eg. `plex.yourdomain.com` > `localhost:32400`)

Pre-configured to work behind Cloudflare proxy and disallow robots

## Features
* Authorization using Cookies, WWW-Authenticate header or a custom header
* IP range whitelist and blacklist
* URI bypass
* Each server can have different configurations