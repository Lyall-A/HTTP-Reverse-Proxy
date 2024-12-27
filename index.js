const net = require("net");
const tls = require("tls");
const fs = require("fs");
const {
    readJson,
    parseTxtFile,
    log,
    logProxyError,
    logServerError,
    ipMatch,
    getHeaders,
    findService,
    formatString,
    parseCookies,
    stringifyCookies,
    objectDefaults,
    watch,
    unwatch,
    unwatchAll,
    createLiveFileMap,
    getHeader,
    setHeader,
    timestamp,
    defaults
} = require("./utils");

// Regex
const requestLineRegex = /^(.*) (.*) (HTTP\/\d*\.\d*)$/im; // GET /hello/world HTTP/1.1
const hostnameRegex = /[^:]*/; // localhost (excludes port)

// Global variables
let proxyConfig = {};
let serviceDefaults = {};
let services = new Map();

let globalWhitelist;
let globalBlacklist;


function main () {    

    // Config
    watch("config.json", json => {
        log(0, "Loaded config");
        proxyConfig = json;
    });

    // Defaults for services
    watch("./services/_defaults.json", json => {
        log(0, "serviceDefaults config");
        serviceDefaults = json;
    });

    // Live load services
    services = createLiveFileMap('./services/*.json', (service, key, filename) => {
        log(0, "Loaded service", filename);
        // const service = defaults(serviceDefaults, json);
        return service;
    });
    services.watch();

    // Authorization HTML
    watch("authorization.html", file => {
        defaultAuthorizationHtmlFile = file;
        log(0, "Loaded authorization HTML");
    });

    // Global whitelist
    if (proxyConfig.whitelist)
    watch(proxyConfig.whitelist, file => {
        globalWhitelist = parseTxtFile(file);
        log(0, "Loaded global whitelist", `(${globalWhitelist.length} entries)`);
    });
    if (globalWhitelist) log(0, `\nDefault whitelist: ${globalWhitelist.length}\n${globalWhitelist.join("\n")}`);

    // Global blacklist
    if (proxyConfig.blacklist)
    watch(proxyConfig.blacklist, file => {
        globalBlacklist = parseTxtFile(file);
        log(0, "Loaded global blacklist", `(${globalBlacklist.length} entries)`);
    });
    if (globalBlacklist) log(0, `\nDefault blacklist: ${globalBlacklist.length}\n${globalBlacklist.join("\n")}`);
    

}

main();



// log(0, `\nServers: ${services.size}\n${Object.entries(Array.from(services.entries()).map(i => `${i.proxyHostnames.join(", ")} > ${i.redirect || `${i.serverHostname}:${i.serverPort}${i.tls ? " (TLS)" : ""}`}`).join("\n")}\n`);

// Create proxy server
const proxyServer = (proxyConfig.tls ? tls : net).createServer({
    key: fs.existsSync(proxyConfig.key) ? fs.readFileSync(proxyConfig.key) : undefined,
    cert: fs.existsSync(proxyConfig.cert) ? fs.readFileSync(proxyConfig.cert) : undefined,
    ...proxyConfig.additionalProxyServerOptions
});

// Proxy server on connection
proxyServer.on("connection", proxyConnection => {
    // Get IP
    const ip = proxyConnection.remoteAddress?.split("::ffff:")[1] || proxyConnection.remoteAddress;

    if (!ip) {
        log(1, `[REFUSED] No IP?!`);
        return proxyConnection.destroy(); // Why does this happen sometimes?
    }

    // Global Blacklist
    if (globalBlacklist && ipMatch(ip, globalBlacklist)) {
        log(1, `[REFUSED] Blacklisted IP ${ip} attempted to connect!`);
        return proxyConnection.destroy();
    }
    // Global Whitelist
    if (globalWhitelist && !ipMatch(ip, globalWhitelist)) {
        log(1, `[REFUSED] Unwhitelisted IP ${ip} attempted to connect!`);
        return proxyConnection.destroy();
    }

    let serverConnection;

    proxyConnection.on("data", data => {
        // Proxy server on data
        const [rawHeaders, ...splitRawData] = data.toString().split("\r\n\r\n");
        const rawData = splitRawData.join("\r\n\r\n");
        const splitHeaders = rawHeaders.split("\r\n");

        const [requestLine, method, uri, version] = splitHeaders.splice(0, 1)[0].match(requestLineRegex) || []; // Get and remove request line from headers

        if (requestLine) {
            // Get headers
            const headers = getHeaders(splitHeaders);

            // Get hostname
            const [hostname] = getHeader(headers, "Host")?.match(hostnameRegex) || [];

            // Get real IP using default realIpHeader config (if using some sort of proxy like Cloudflare)
            let realIp = serviceDefaults.realIpHeader ? headers[serviceDefaults.realIpHeader] : null;
            let ipFormatted = `${ip}${realIp ? ` (${realIp})` : ""}`;

            // Find service to handle this request
            const service = findService(services, hostname);
            if (!service) {
                log(2, `[NOHOST] IP ${ipFormatted} tried to reach unknown hostname ${hostname}`);
                return proxyConnection.destroy();
            }

            // Get default server options + found server options
            const serviceOptions = objectDefaults(service, serviceDefaults || {});

            // Get real IP (if using some sort of proxy like Cloudflare)
            realIp = serviceOptions.realIpHeader ? headers[serviceOptions.realIpHeader] : null;
            ipFormatted = `${ip}${realIp ? ` (${realIp})` : ""}`;

            // Make sure using supported version
            if (serviceOptions.supportedVersions && !serviceOptions.supportedVersions.includes(version)) {
                log(2, `[UNSUPPORTED] IP ${ipFormatted} using unsupported version ${version}`);
                return proxyConnection.destroy();
            }

            // Check whitelist/blacklist again with custom options
            // Whitelist
            const whitelist = serviceOptions.whitelist !== serviceDefaults.whitelist ? readJson(serviceOptions.whitelist) : null;
            if (whitelist && !ipMatch(ip, whitelist)) {
                log(1, `[REFUSED] Unwhitelisted IP ${ip} attempted to connect!`);
                return proxyConnection.destroy();
            }
            // Blacklist
            const blacklist = serviceOptions.blacklist !== serviceDefaults.blacklist ? readJson(serviceOptions.blacklist) : null;
            if (blacklist && ipMatch(ip, blacklist)) {
                log(1, `[REFUSED] Blacklisted IP ${ip} attempted to connect!`);
                return proxyConnection.destroy();
            }

            // Service requires authorization
            if (serviceOptions.authorization) {
                if (!serviceOptions.authorizationPassword) {
                    // No authorization password set
                    log(1, `[AUTH] IP ${ipFormatted} tried to reach ${hostname} which requires authorization, but no authorization password was set`);
                    return proxyConnection.destroy();
                }

                let authorized = false;

                if (typeof serviceOptions.authorizationType === "object") {
                    serviceOptions.authorizationType.forEach((authorizationType, index, array) => {
                        checkAuthorization(authorizationType.toLowerCase(), index === array.length - 1);
                    });
                } else {
                    checkAuthorization(serviceOptions.authorizationType?.toLowerCase(), true);
                };

                function checkAuthorization(authorizationType, isLastType) {
                    if (authorized) return;

                    if (authorizationType === "cookies") {
                        // Authorize using Cookies
                        const cookies = parseCookies(getHeader(headers, "Cookie") || "");

                        if (cookies[serviceOptions.authorizationCookie] !== serviceOptions.authorizationPassword) {
                            // Incorrect or no authorization cookie
                            if (!isLastType) return;
                            const vars = {
                                config,
                                serverOptions: serviceOptions,
                                cookieMaxAge: serviceDefaults.cookieMaxAge,
                                authorizationCookie: serviceOptions.authorizationCookie,
                                hostname,
                                ip: realIp || ip,
                            };
                            const authorizationHtml = formatString(defaultAuthorizationHtmlFile, vars);
                            log(2, `[AUTH] IP ${ipFormatted} tried to reach ${hostname} which requires authorization`);
                            proxyConnection.write(`${version} 401 Unauthorized\r\nContent-Type: text/html\r\nContent-Length: ${authorizationHtml.length}\r\n\r\n${authorizationHtml}`);
                            return;
                        };

                        authorized = true;

                        // Remove cookie before sending to server
                        delete cookies[serviceOptions.authorizationCookie];
                        setHeader(headers, "Cookie", stringifyCookies(cookies));
                    } else if (authorizationType === "www-authenticate") {
                        // Authorize using WWW-Authenticate header
                        const password = Buffer.from((getHeader(headers, "Authorization") || "").split(" ")[1] || "", "base64").toString().split(":")[1];

                        if (password !== serviceOptions.authorizationPassword) {
                            // Incorrect or no WWW-Authorization header
                            if (!isLastType) return;
                            log(2, `[AUTH] IP ${ipFormatted} tried to reach ${hostname} which requires authorization`);
                            proxyConnection.write(`${version} 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n`);
                            return;
                        }

                        authorized = true;
                    } else if (authorizationType === "custom-header") {
                        // Authorize using custom header
                        const header = getHeader(headers, serviceOptions.customAuthorizationHeader);

                        if (header !== serviceOptions.authorizationPassword) {
                            // Incorrect or no custom header
                            if (!isLastType) return;
                            log(2, `[AUTH] IP ${ipFormatted} tried to reach ${hostname} which requires authorization`);
                            proxyConnection.write(`${version} 401 Unauthorized\r\nContent-Length: 0\r\n\r\n`);
                            return;
                        }

                        authorized = true;
                    } else {
                        // Unknown authorization type
                        log(1, `[AUTH] IP ${ipFormatted} tried to reach ${hostname} which requires authorization, but an unknown authorization type was set`);
                        return proxyConnection.destroy();
                    }
                }
            }

            // Is redirect
            if (serviceOptions.redirect) {
                return proxyConnection.end(`${version} 301 Moved Permanently\r\nLocation: ${serviceOptions.redirect}\r\n\r\n`);
            }

            // Modify headers
            Object.entries(serviceOptions.modifiedHeaders || {}).forEach(([header, value]) => {
                if (value === true) return;

                if (!value) {
                    setHeader(headers, header);
                } else
                    setHeader(headers, header, formatString(value, {
                        proxyHostname: hostname, // OLD
                        serverHostname: serviceOptions.serverHostname, // OLD
                        serverPort: serviceOptions.serverPort, // OLD
                        hostname,
                        serverOptions: serviceOptions,
                        headers,
                        ip
                    }));
            });

            // Is bypassed URI
            // TODO: make this better
            const bypassOptions = serviceOptions.uriBypass?.[uri];
            if (bypassOptions) {
                const bypassHeaders = objectDefaults(bypassOptions.headers, { "Content-Length": bypassOptions.data.length || 0 });
                return proxyConnection.write(`${version} ${bypassOptions.statusCode || 200} ${bypassOptions.statusMessage || ""}\r\n${Object.entries(bypassHeaders).map(i => `${i[0]}: ${i[1]}`).join("\r\n")}\r\n\r\n${bypassOptions.data || ""}`);
            }

            // Reconstruct data
            const reconstructedData = Buffer.concat([
                Buffer.from(`${method} ${serviceOptions.forceUri || uri} ${version}`), // Request line
                Buffer.from("\r\n"), // New line
                Buffer.from(Object.entries(headers).map(i => `${i[0]}: ${i[1]}`).join("\r\n")), // Headers
                Buffer.from("\r\n\r\n"), // New line before data
                Buffer.from(rawData) // Data
            ]);

            // console.log(reconstructedData.toString());

            if (!serverConnection) {
                // Connect to server
                log(3, `CONNECTING IP ${ipFormatted} connecting to ${hostname}`);

                serverConnection = (serviceOptions.useTls ? tls : net).connect({
                    host: serviceOptions.serverHostname,
                    port: serviceOptions.serverPort,
                    rejectUnauthorized: false,
                    ...serviceOptions.additionalServerOptions
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
proxyServer.listen(proxyConfig.port, proxyConfig.hostname, () => log(0, `Proxy server listening at :${proxyConfig.port}`));

// Close
process.on("SIGINT", closeProxy);
process.on("SIGTERM", closeProxy);

function closeProxy() {
    log(0, "Closing proxy");
    proxyServer.close();
    unwatchAll();
    services.unwatch();
    process.exit(0);
}
