# HTTP Reverse Proxy

## WARNING: IT IS NOT RECOMMENDED THAT YOU USE THIS! PLEASE USE [NGINX](https://www.nginx.com) INSTEAD

## A proxy that routes requests based on the host header (eg. `plex.yourdomain.com` > `localhost:32400`), Pre-configured to work behind Cloudflare proxy

## Features:
* Authorization using cookies (may break if application makes requests without the `Cookie` header)
* IP range whitelist and blacklist