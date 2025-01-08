HTTP Reverse Proxy
===================
> NOTE: You should REALLY use [Nginx](https://www.nginx.com) instead!

A proxy that routes requests based on the host header (eg. `plex.yourdomain.com` > `localhost:32400`)

Pre-configured to work behind Cloudflare proxy and disallow robots

## Features
* Authorization using Cookies, WWW-Authenticate header or a custom header
* IP range whitelist and blacklist
* URI bypass
* Each service can have different configurations
* Live reload of services and configurations


# How to use

1. Install the CLI
    ```sh
    npm i -g git@github.com:victornpb/HTTP-Reverse-Proxy.git
    ```
2. Create a folder for containing your proxy files
    ```sh
    mkdir myproxy
    cd myproxy
    ```
3. Create a new server
    ```sh
    reverseproxy create
    ```
4. Edit files (see readme inside folder for instructions)
5. Start the proxy running
    ```sh
    reverseproxy start
    ```
