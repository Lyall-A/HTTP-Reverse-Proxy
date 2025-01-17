Services
=========

Create a JSON file in the `/services` folder for each service you want to expose.

Any service file can be added, removed, or modified at any time. Changes take effect live for new incoming connections. (existing connections are not terminated, they might still be using old settings).

A service looks something like this:

### Example:
chat.json
```json
{
    "proxyHostnames": ["chat.example.com", "chat.example.net"],
    "serverHostname": "10.0.0.11",
    "serverPort": 3000,
    "useTls": true,
    "auth": true,
    "authType": "cookies",
    "authPassword": "password"
}
```

Files prefixed with `_` are ignored. (except `_defaults.json` read below).
You can use this to draft services or to disable them.

## Properties
```jsonc
{
    "proxyHostnames": ["localhost", "127.0.0.1"],                      // The hostnames to look for (start/end with period to match with ends/start with instead of exact match)
    "serverHostname": "example.com",                                   // The hostname to connect to
    "serverPort": 443,                                                 // The port to connect to
    "useTls": true,                                                    // Connect using TLS (HTTPS)
    "whitelist": "whitelist.json",                                     // Path to custom whitelist for server
    "blacklist": null,                                                 // Path to custom blacklist for server
    "realIpHeader": "CF-Connecting-Ip",                                // Header that contains real IP if behind another proxy
    "auth": false,                                                     // If this server should require authorization before connecting
    "authType": "cookies",                                             // Type of authorization to use (cookies, www-authenticate, custom-header)
    "authPassword": "password",                                        // The password required to connect, do not set this to null, remove to use defaults
    "customAuthHeader": "X-HTTP-Reverse-Proxy-Authorization",          // Cookie used for custom header based authorization
    "authCookie": "HTTP-Reverse-Proxy-Authorization",                  // Cookie used for cookie based authorization
    "cookieMaxAge": 86400,                                             // How long the authorization cookie lasts
    "authRemembersIp": false,                                          // Skip re-authentication for IPs that have previously proven themselves
    "authRemembersIpTtl": 86400,                                       // How long the IP will be remembered
    "forceUri": "/test",                                               // Force a specific URI/path
    "redirect": "https://google.com",                                  // Redirect
    "modifiedHeaders": {                                               // Remove or change HTTP headers, you will probably need to change the Host header to the server hostname and remove any proxy related headers
        "Host": "example.com",
        "X-Forwarded-For": null
    },
    "uriBypass": {                                                     // Bypass URI's and send custom data without connecting to server
        "/robots.txt": {
            "statusCode": 200,                                         // Defaults to 200
            "statusMessage": "OK",                                     // NOTE: This does not default to "OK", "Forbidden", etc
            "headers": { "Content-Type": "text/plain" },               // NOTE: Content-Length is set by default
            "data": "User-agent: *\nDisallow: /"
        }
    },
    "additionalServerOptions": { }                                    // Additional options for when connecting to server, useful for stuff like SNI
}
```

_defaults.json
------------
`_defaults.json` is a special file in the `/services` folder used as a base configuration for all services.

Properties not specified in individual service files will inherit values from `_defaults.json`.

Values defined in services take preference over defaults.

This file supports live changes.
