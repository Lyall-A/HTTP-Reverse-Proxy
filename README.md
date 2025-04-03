# HTTP Reverse Proxy
**This project is being continued at https://github.com/victornpb/HTTP-Reverse-Proxy**

 My new version of this is [Yet-Another-Proxy](https://github.com/Lyall-A/Yet-Another-Proxy)

## NOTE: You should REALLY use [Nginx](https://www.nginx.com) instead!

A proxy that routes requests based on the host header (eg. `plex.yourdomain.com` > `localhost:32400`)

Pre-configured to work behind Cloudflare proxy and disallow robots

## Features
* Authorization using Cookies, WWW-Authenticate header or a custom header
* IP range whitelist and blacklist
* URI bypass
* Each server can have different configurations
