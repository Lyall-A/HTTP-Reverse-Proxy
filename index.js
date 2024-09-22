const net = require("net");
const tls = require("tls");
const fs = require("fs");

const { readJson, log, logProxyError, logServerError, ipMatch, getHeaders, findServer, formatString, parseCookies, stringifyCookies, objectDefaults, watch, getHeader, setHeader, timestamp } = require("./utils");

// Config
global.config = readJson("config.json");
global.unwatchConfig = watch("config.json", true, file => {
    config = file;
    log(0, "Updated config");
});

// Servers
global.servers = readJson("servers.json").filter(i => !i?.disabled);
global.unwatchServers = watch("servers.json", true, file => {
    servers = file.filter(i => !i?.disabled);
    log(0, "Updated servers");
});

// Default authorization HTML
let defaultAuthorizationHtmlFile = fs.readFileSync("authorization.html", "utf-8");
let defaultAuthorizationHtml = formatString(defaultAuthorizationHtmlFile, { config, cookieExpiry: config.defaultServerOptions.cookieExpiry, authorizationCookie: config.defaultServerOptions.authorizationCookie });
global.unwatchAuthorizationHtml = watch("authorization.html", false, file => {
    defaultAuthorizationHtmlFile = file;
    defaultAuthorizationHtml = formatString(defaultAuthorizationHtmlFile, { config, cookieExpiry: config.defaultServerOptions.cookieExpiry, authorizationCookie: config.defaultServerOptions.authorizationCookie });
    log(0, "Updated authorization HTML");
});

// Default whitelist
let defaultWhitelist;
if (config.defaultServerOptions.whitelist) {
    defaultWhitelist = readJson(config.defaultServerOptions.whitelist);
    global.unwatchDefaultWhitelist = watch(config.defaultServerOptions.whitelist, true, file => {
        defaultWhitelist = file;
        log(0, "Updated default whitelist");
    });
}

// Default blacklist
let defaultBlacklist;
if (config.defaultServerOptions.blacklist) {
    defaultBlacklist = readJson(config.defaultServerOptions.blacklist);
    global.unwatchDefaultBlacklist = watch(config.defaultServerOptions.blacklist, true, file => {
        defaultBlacklist = file;
        log(0, "Updated default blacklist");
    });
}

// Regex
const requestLineRegex = /^(.*) (.*) (HTTP\/\d*\.\d*)$/im; // GET /hello/world HTTP/1.1
const hostnameRegex = /[^:]*/; // localhost (excludes port)

// Initial logs
if (defaultWhitelist) log(0, `\nDefault whitelist: ${defaultWhitelist.length}\n${defaultWhitelist.join("\n")}`);
if (defaultBlacklist) log(0, `\nDefault blacklist: ${defaultBlacklist.length}\n${defaultBlacklist.join("\n")}`);
log(0, `\nServers: ${servers.length}\n${servers.map(i => `${i.proxyHostnames.join(", ")} > ${i.redirect || `${i.serverHostname}:${i.serverPort}${i.tls ? " (TLS)" : ""}`}`).join("\n")}\n`);

// Create proxy server
const proxyServer = (config.tls ? tls : net).createServer({
    key: fs.existsSync(config.key) ? fs.readFileSync(config.key) : undefined,
    cert: fs.existsSync(config.cert) ? fs.readFileSync(config.cert) : undefined,
    ...config.additionalProxyServerOptions
});

// Proxy server on connection
proxyServer.on("connection", proxyConnection => {
    // Get IP
    const ip = proxyConnection.remoteAddress?.split("::ffff:")[1] || proxyConnection.remoteAddress;
    if (!ip) return proxyConnection.end(); // Why does this happen sometimes?

    // Default whitelist
    if (defaultWhitelist && !ipMatch(ip, defaultWhitelist)) {
        log(1, `Unwhitelisted IP ${ip} attempted to connect!`);
        return proxyConnection.end();
    }
    // Default blacklist
    if (defaultBlacklist && ipMatch(ip, defaultBlacklist)) {
        log(1, `Blacklisted IP ${ip} attempted to connect!`);
        return proxyConnection.end();
    }

    let serverConnection;

    proxyConnection.on("data", data => {
        // Proxy server on data
        const [rawHeaders, ...splitRawData] = data.toString().split("\r\n\r\n");
        const rawData = splitRawData.join("\r\n\r\n");
        const splitHeaders = rawHeaders.split("\r\n");

        const [requestLine, method, uri, version] = splitHeaders.splice(0, 1)[0].match(requestLineRegex) || []; // Get and remove request line from headers

        if (requestLine) {
            const headers = getHeaders(splitHeaders); // Get headers

            // Get hostname
            const [hostname] = getHeader(headers, "Host")?.match(hostnameRegex) || [];

            // Find server
            const server = findServer(hostname);
            if (!server) {
                log(2, `IP ${ipFormatted} tried to reach unknown hostname ${hostname}`);
                return proxyConnection.end();
            }

            const serverOptions = objectDefaults(server, config.defaultServerOptions || {}); // Get default server options + found server options

            let realIp = config.defaultServerOptions.realIpHeader ? headers[config.defaultServerOptions.realIpHeader] : null; // Get real IP using default realIpHeader config (if using some sort of proxy like Cloudflare)
            let ipFormatted = `${ip}${realIp ? ` (${realIp})` : ""}`;

            // Make sure using supported version
            if (serverOptions.supportedVersions && !serverOptions.supportedVersions.includes(version)) {
                log(2, `IP ${ipFormatted} using unsupported version ${version}`);
                return proxyConnection.end();
            }

            realIp = serverOptions.realIpHeader ? headers[serverOptions.realIpHeader] : null; // Get real IP (if using some sort of proxy like Cloudflare)
            ipFormatted = `${ip}${realIp ? ` (${realIp})` : ""}`;

            // Check whitelist/blacklist again with custom options
            // Whitelist
            const whitelist = serverOptions.whitelist !== config.defaultServerOptions.whitelist ? readJson(serverOptions.whitelist) : null;
            if (whitelist && !ipMatch(ip, whitelist)) {
                log(1, `Unwhitelisted IP ${ip} attempted to connect!`);
                return proxyConnection.end();
            }
            // Blacklist
            const blacklist = serverOptions.blacklist !== config.defaultServerOptions.blacklist ? readJson(serverOptions.blacklist) : null;
            if (blacklist && ipMatch(ip, blacklist)) {
                log(1, `Blacklisted IP ${ip} attempted to connect!`);
                return proxyConnection.end();
            }

            // Server requires authorization
            if (serverOptions.authorization) {
                if (!serverOptions.authorizationPassword) {
                    // No authorization password set, end
                    log(1, `IP ${ipFormatted} tried to reach ${hostname} which requires authorization, but no authorization password was set`);
                    return proxyConnection.end();
                }

                let authorized = false;

                if (typeof serverOptions.authorizationType === "object") {
                    serverOptions.authorizationType.forEach((authorizationType, index, array) => {
                        checkAuthorization(authorizationType.toLowerCase(), index === array.length - 1);
                    });
                } else {
                    checkAuthorization(serverOptions.authorizationType?.toLowerCase(), true);
                };

                function checkAuthorization(authorizationType, isLastType) {
                    if (authorized) return;

                    if (authorizationType === "cookies") {
                        // Authorize using Cookies
                        const cookies = parseCookies(getHeader(headers, "Cookie") || "");

                        if (cookies[serverOptions.authorizationCookie] !== serverOptions.authorizationPassword) {
                            // Incorrect or no authorization cookie
                            if (!isLastType) return;
                            const authorizationHtml = serverOptions.authorizationCookie !== config.defaultServerOptions.authorizationCookie ? formatString(defaultAuthorizationHtmlFile, { config, serverOptions, cookieExpiry: config.defaultServerOptions.cookieExpiry, authorizationCookie: serverOptions.authorizationCookie }) : defaultAuthorizationHtml
                            log(2, `IP ${ipFormatted} tried to reach ${hostname} which requires authorization`);
                            proxyConnection.write(`${version} 401 Unauthorized\r\nContent-Type: text/html\r\nContent-Length: ${authorizationHtml.length}\r\n\r\n${authorizationHtml}`);
                            return;
                        };

                        authorized = true;

                        // Remove cookie before sending to server
                        delete cookies[serverOptions.authorizationCookie];
                        setHeader(headers, "Cookie", stringifyCookies(cookies));
                    } else if (authorizationType === "www-authenticate") {
                        // Authorize using WWW-Authenticate header
                        const password = Buffer.from((getHeader(headers, "Authorization") || "").split(" ")[1] || "", "base64").toString().split(":")[1];

                        if (password !== serverOptions.authorizationPassword) {
                            // Incorrect or no WWW-Authorization header
                            if (!isLastType) return;
                            log(2, `IP ${ipFormatted} tried to reach ${hostname} which requires authorization`);
                            proxyConnection.write(`${version} 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n`);
                            return;
                        }

                        authorized = true;
                    } else if (authorizationType === "custom-header") {
                        // Authorize using custom header
                        const header = getHeader(headers, serverOptions.customAuthorizationHeader);

                        if (header !== serverOptions.authorizationPassword) {
                            // Incorrect or no custom header
                            if (!isLastType) return;
                            log(2, `IP ${ipFormatted} tried to reach ${hostname} which requires authorization`);
                            proxyConnection.write(`${version} 401 Unauthorized\r\nContent-Length: 0\r\n\r\n`);
                            return;
                        }

                        authorized = true;
                    } else {
                        // Unknown authorization type, end
                        log(1, `IP ${ipFormatted} tried to reach ${hostname} which requires authorization, but an unknown authorization type was set`);
                        return proxyConnection.end();
                    }
                }
            }

            // Is redirect
            if (serverOptions.redirect) {
                return proxyConnection.write(`${version} 301 Moved Permanently\r\nLocation: ${serverOptions.redirect}\r\n\r\n`);
            }

            // Modify headers
            Object.entries(serverOptions.modifiedHeaders || {}).forEach(([header, value]) => {
                if (value === true) return;

                if (!value) {
                    setHeader(headers, header);
                } else
                    setHeader(headers, header, formatString(value, {
                        proxyHostname: hostname, // OLD
                        serverHostname: serverOptions.serverHostname, // OLD
                        serverPort: serverOptions.serverPort, // OLD
                        hostname,
                        serverOptions,
                        headers,
                        ip
                    }));
            });

            // Is bypassed URI
            // TODO: make this better
            const bypassOptions = serverOptions.uriBypass?.[uri];
            if (bypassOptions) {
                const bypassHeaders = objectDefaults(bypassOptions.headers, { "Content-Length": bypassOptions.data.length || 0 });
                return proxyConnection.write(`${version} ${bypassOptions.statusCode || 200} ${bypassOptions.statusMessage || ""}\r\n${Object.entries(bypassHeaders).map(i => `${i[0]}: ${i[1]}`).join("\r\n")}\r\n\r\n${bypassOptions.data || ""}`);
            }

            // Reconstruct data
            const reconstructedData = Buffer.concat([
                Buffer.from(`${method} ${serverOptions.forceUri || uri} ${version}`), // Request line
                Buffer.from("\r\n"), // New line
                Buffer.from(Object.entries(headers).map(i => `${i[0]}: ${i[1]}`).join("\r\n")), // Headers
                Buffer.from("\r\n\r\n"), // New line before data
                Buffer.from(rawData) // Data
            ]);

            // console.log(reconstructedData.toString());

            if (!serverConnection) {
                // Connect to server
                log(3, `IP ${ipFormatted} connecting to ${hostname}`);

                serverConnection = (serverOptions.useTls ? tls : net).connect({
                    host: serverOptions.serverHostname,
                    port: serverOptions.serverPort,
                    rejectUnauthorized: false,
                    ...serverOptions.additionalServerOptions
                });

                // Server events
                serverConnection.on("data", i => writeProxyConnection(i));
                serverConnection.on("close", closeProxyConnection);
                serverConnection.on("end", i => closeProxyConnection);
                serverConnection.on("error", err => {
                    closeProxyConnection();
                    logServerError(err);
                });

                serverConnection.on("drain", () => proxyConnection.resume());
            }

            writeServerConnection(reconstructedData); // Write changed data if this buffer contains headers
        } else
            writeServerConnection(data); // Write unchanged data if this buffer does not contain headers
    });

    // Proxy events
    proxyConnection.on("close", closeServerConnection);
    proxyConnection.on("end", closeServerConnection);
    proxyConnection.on("error", err => {
        closeServerConnection();
        logProxyError(err);
    });
    proxyConnection.on("drain", () => serverConnection?.resume());

    function closeServerConnection() { if (serverConnection && !serverConnection.ended) serverConnection.end() }
    function closeProxyConnection() { if (proxyConnection && !proxyConnection.ended) proxyConnection.end() }
    function writeServerConnection(data) { if (serverConnection && !serverConnection.ended) if (!serverConnection.write(data)) proxyConnection.pause() }
    function writeProxyConnection(data) { if (proxyConnection && !proxyConnection.ended) if (!proxyConnection.write(data)) serverConnection.pause() }
});

// Listen
proxyServer.listen(config.port, config.hostname, () => log(1, `Listening at :${config.port}`));

// Close
process.on("SIGINT", closeProxy);
process.on("SIGTERM", closeProxy);

function closeProxy() {
    log(0, "Closing proxy");
    proxyServer.close();
    global.unwatchConfig?.();
    global.unwatchServers?.();
    global.unwatchAuthorizationHtml?.();
    global.unwatchDefaultWhitelist?.();
    global.unwatchDefaultBlacklist?.();
    process.exit(0);
}