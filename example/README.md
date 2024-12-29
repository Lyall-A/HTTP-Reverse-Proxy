# Reverse Proxy Configuration

Steps to Setup
---------------------

1. Edit Configuration Files
   - Adjust proxy settings editing `config.json`
   - Add IP ranges to `ip-whitelist.conf` and `ip-blacklist.conf`

2. Create services
   - Edit the defaults editing `_defaults.json`
   - Add files inside the `/services` folder

3. Start the Proxy Server
   - Run the proxy server using the cli command  
    ` $ reverseproxy start `


Proxy Global Config
--------------------
Global proxy configuration. Customize the following settings in `config.json`:

- **Port**: Set the listening port for the proxy server (default: 80).
- **Hostname**: Specify the server hostname (default: null).
- **TLS**: Enable by providing paths to `key` and `cert` files.
- **Whitelist**: Set the path to `ip-whitelist.conf` for allowed IPs.
- **Blacklist**: Optionally set the path to `ip-blacklist.conf` to block IPs.

Services
---------
Create a JSON file in the `/services` folder for each service you want to expose.

Any service file can be added, removed, or modified at any time. Changes take effect live for new incoming connections. (existing connections are not terminated, they might still be using old settings).

A service looks something like this:

### Example: `chat.json`
```json
{
    "proxyHostnames": ["chat.example.com", "chat.example.net"],
    "serverHostname": "10.0.0.11",
    "serverPort": 3000,
    "authorization": true,
    "authorizationType": "cookies",
    "authorizationPassword": "password",
    "useTls": true
}
```

For more details, consult the comments in `_defaults.json` and `_example.json`.

Files prefixed with `_` are ignored. (except `_defaults.json` read below).
You can use this to draft services or to disable them.

## Defaults
`_defaults.json` is a special file in the `/services` folder used as a base configuration for all services.

Properties not specified in individual service files will inherit values from `_defaults.json`.

Values defined in services take preference over defaults.

This file supports live changes.


IP Blocking
------------

You can allow / disallow IPs using whitelist and blacklists

