const net = require("net");
const tls = require("tls");
const fs = require("fs");

// Config
let config = readJson("config.json");
watch("config.json", true, file => {
    config = file;
    log(0, "Updated config");
});

// Servers
let servers = readJson("servers.json").filter(i => !i?.disabled);
watch("servers.json", true, file => {
    servers = file.filter(i => !i?.disabled);
    log(0, "Updated servers");
});

// Default authorization HTML
let defaultAuthorizationHtmlFile = fs.readFileSync("authorization.html", "utf-8");
let defaultAuthorizationHtml = formatString(defaultAuthorizationHtmlFile, { authorizationCookie: config.defaultServerOptions.authorizationCookie });
watch("authorization.html", false, file => {
    defaultAuthorizationHtmlFile = file;
    defaultAuthorizationHtml = formatString(defaultAuthorizationHtmlFile, { authorizationCookie: config.defaultServerOptions.authorizationCookie });
    log(0, "Updated authorization HTML");
});

// Default whitelist
let defaultWhitelist;
if (config.defaultServerOptions.whitelist) {
    whitelist = readJson(config.defaultServerOptions.whitelist);
    watch(config.defaultServerOptions.whitelist, true, file => {
        defaultWhitelist = file;
        log(0, "Updated default whitelist");
    });
}

// Default blacklist
let defaultBlacklist;
if (config.defaultServerOptions.blacklist) {
    defaultBlacklist = readJson(config.defaultServerOptions.blacklist);
    watch(config.defaultServerOptions.blacklist, true, file => {
        defaultBlacklist = file;
        log(0, "Updated default blacklist");
    });
}

// Regex
const requestLineRegex = /^(.*) (.*) (HTTP\/\d*\.\d*)$/im; // GET /hello/world HTTP/1.1
// const statusLineRegex = /^(HTTP\/\d*\.\d*) (\d*) (.*)$/im; // HTTP/1.1 200 OK
const headersRegex = /^(.*?): ?(.*)$/m; // Host: localhost
const hostnameRegex = /[^:]*/; // localhost (excludes port)

// Log
if (defaultWhitelist) log(0, `\nDefault whitelist: ${defaultWhitelist.length}\n${defaultWhitelist.join("\n")}`);
if (defaultBlacklist) log(0, `\nDefault blacklist: ${defaultBlacklist.length}\n${defaultBlacklist.join("\n")}`);
log(0, `\nServers: ${servers.length}\n${servers.map(i => `${i.proxyHostnames.join(", ")} > ${i.serverHostname}:${i.serverPort}${i.tls ? " (TLS)" : ""}`).join("\n")}\n`);

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
    if (!ip) return; // Why does this happen sometimes?

    // Default whitelist
    if (defaultWhitelist && !ipMatch(ip, defaultWhitelist)) {
        log(1, `Unwhitelisted IP ${ip} attempted to connect!`);
        return proxyConnection.destroy();
    }
    // Default blacklist
    if (defaultBlacklist && ipMatch(ip, defaultBlacklist)) {
        log(1, `Blacklisted IP ${ip} attempted to connect!`);
        return proxyConnection.destroy();
    }

    log(3, `New connection from ${ip}`);

    let serverConnection;

    let proxyQueue = [];
    let proxySending = false;
    let serverQueue = [];
    let serverSending = false;

    proxyConnection.on("data", data => {
        // Proxy server on data
        const [rawHeaders, rawData = ""] = data.toString().split("\r\n\r\n");
        const splitHeaders = rawHeaders.split("\r\n");

        const [requestLine, method, uri, version] = splitHeaders[0].match(requestLineRegex) || [];
        if (requestLine) {
            const headers = getHeaders(splitHeaders); // Get headers

            let realIp = config.defaultServerOptions.realIpHeader ? headers[config.defaultServerOptions.realIpHeader] : null; // Get real IP using default realIpHeader config (if using some sort of proxy like Cloudflare)

            // Make sure using supported version
            if (config.supportedVersions && !config.supportedVersions.includes(version)) {
                log(2, `IP ${ip}${realIp ? ` (${realIp})` : ""} using unsupported version ${version}`);
                return proxyConnection.destroy();
            }

            // Get hostname
            const [hostname] = getHeader(headers, "Host")?.match(hostnameRegex) || [];

            const server = findServer(hostname);

            // Find server
            if (!server) {
                log(2, `IP ${ip}${realIp ? ` (${realIp})` : ""} tried to reach unknown hostname ${hostname}`);
                return proxyConnection.destroy();
            }

            const serverOptions = objectDefaults(server, config.defaultServerOptions || {}); // Get default server options + found server options

            // Check whitelist/blacklist again with custom options
            // Whitelist
            const whitelist = serverOptions.whitelist != config.defaultServerOptions.whitelist ? readJson(serverOptions.whitelist) : null;
            if (whitelist && !ipMatch(ip, whitelist)) {
                log(1, `Unwhitelisted IP ${ip} attempted to connect!`);
                return proxyConnection.destroy();
            }
            // Blacklist
            const blacklist = serverOptions.blacklist != config.defaultServerOptions.blacklist ? readJson(serverOptions.blacklist) : null;
            if (blacklist && ipMatch(ip, blacklist)) {
                log(1, `Blacklisted IP ${ip} attempted to connect!`);
                return proxyConnection.destroy();
            }

            realIp = serverOptions.realIpHeader ? headers[serverOptions.realIpHeader] : null; // Get real IP (if using some sort of proxy like Cloudflare)

            // Server requires authorization
            if (serverOptions.authorization) {
                if (!serverOptions.authorizationPassword) {
                    // No authorization password set, destroy
                    log(1, `IP ${ip}${realIp ? ` (${realIp})` : ""} tried to reach ${hostname} which requires authorization, but no authorization password was set`);
                    return proxyConnection.destroy();
                }

                let authorized = false;

                if (typeof serverOptions.authorizationType == "object") {
                    serverOptions.authorizationType.forEach((authorizationType, index, array) => {
                        checkAuthorization(authorizationType.toLowerCase(), index == array.length - 1);
                    });
                } else {
                    checkAuthorization(serverOptions.authorizationType?.toLowerCase(), true);
                };

                function checkAuthorization(authorizationType, isLastType) {
                    if (authorized) return;

                    if (authorizationType == "cookies") {
                        // Authorize using Cookies
                        const cookies = parseCookies(getHeader(headers, "Cookie") || "");

                        if (cookies[serverOptions.authorizationCookie] != serverOptions.authorizationPassword) {
                            // Incorrect or no authorization cookie
                            if (!isLastType) return;
                            const authorizationHtml = serverOptions.authorizationCookie != config.defaultServerOptions.authorizationCookie ? formatString(defaultAuthorizationHtmlFile, { authorizationCookie: serverOptions.authorizationCookie }) : defaultAuthorizationHtml
                            log(2, `IP ${ip}${realIp ? ` (${realIp})` : ""} tried to reach ${hostname} which requires authorization`);
                            proxyConnection.write(`${version} 401 Unauthorized\r\nContent-Type: text/html\r\nContent-Length: ${authorizationHtml.length}\r\n\r\n${authorizationHtml}`);
                            return;
                        };

                        authorized = true;

                        // Remove cookie before sending to server
                        delete cookies[serverOptions.authorizationCookie];
                        setHeader(headers, "Cookie", stringifyCookies(cookies));
                    } else if (authorizationType == "www-authenticate") {
                        // Authorize using WWW-Authenticate header
                        const password = Buffer.from((getHeader(headers, "Authorization") || "").split(" ")[1] || "", "base64").toString().split(":")[1];

                        if (password != serverOptions.authorizationPassword) {
                            // Incorrect or no WWW-Authorization header
                            if (!isLastType) return;
                            log(2, `IP ${ip}${realIp ? ` (${realIp})` : ""} tried to reach ${hostname} which requires authorization`);
                            proxyConnection.write(`${version} 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n`);
                            return;
                        }

                        authorized = true;
                    } else if (authorizationType == "custom-header") {
                        // Authorize using custom header
                        const header = getHeader(headers, serverOptions.customAuthorizationHeader);

                        if (header != serverOptions.authorizationPassword) {
                            // Incorrect or no custom header
                            if (!isLastType) return;
                            log(2, `IP ${ip}${realIp ? ` (${realIp})` : ""} tried to reach ${hostname} which requires authorization`);
                            proxyConnection.write(`${version} 401 Unauthorized\r\nContent-Length: 0\r\n\r\n`);
                            return;
                        }

                        authorized = true;
                    } else {
                        // Unknown authorization type, destroy
                        log(1, `IP ${ip}${realIp ? ` (${realIp})` : ""} tried to reach ${hostname} which requires authorization, but an unknown authorization type was set`);
                        return proxyConnection.destroy();
                    }
                }
            }

            // Modify headers
            Object.entries(serverOptions.modifiedHeaders || {}).forEach(([header, value]) => {
                if (value === true) return;

                if (!value) {
                    setHeader(headers, header);
                } else
                    setHeader(headers, header, formatString(value, {
                        proxyHostname: hostname,
                        serverHostname: serverOptions.serverHostname,
                        serverPort: serverOptions.serverPort
                    }));
            });

            // Is bypassed URI
            const bypassOptions = serverOptions.uriBypass?.[uri];
            if (bypassOptions) {
                const bypassHeaders = objectDefaults(bypassOptions.headers, { "Content-Length": bypassOptions.data.length || 0 });
                return proxyConnection.write(`${version} ${bypassOptions.statusCode || 200} ${bypassOptions.statusMessage || ""}\r\n${Object.entries(bypassHeaders).map(i => `${i[0]}: ${i[1]}`).join("\r\n")}\r\n\r\n${bypassOptions.data || ""}`);
            }

            // Reconstruct data
            const reconstructedData = Buffer.concat([
                Buffer.from(requestLine),
                Buffer.from("\r\n"),
                Buffer.from(Object.entries(headers).map(i => `${i[0]}: ${i[1]}`).join("\r\n")),
                Buffer.from("\r\n\r\n"),
                Buffer.from(rawData)
            ]);

            // console.log(reconstructedData.toString());

            if (!serverConnection || serverConnection.ended) {
                // Connect to server
                serverConnection = (serverOptions.useTls ? tls : net).connect({
                    host: serverOptions.serverHostname,
                    port: serverOptions.serverPort,
                    rejectUnauthorized: false,
                    ...serverOptions.additionalServerOptions
                });

                serverConnection.on("data", i => writeProxyConnection(i));
                serverConnection.on("close", i => closeAll());
                serverConnection.on("end", i => closeAll());
                serverConnection.on("error", err => {
                    closeAll();
                    logServerError(err);
                });
            }

            writeServerConnection(reconstructedData);
        } else
            writeServerConnection(data);
    });

    proxyConnection.on("close", i => closeAll());
    proxyConnection.on("end", i => closeAll());
    proxyConnection.on("error", err => {
        closeAll();
        logProxyError(err);
    });

    function closeAll() {
        closeServerConnection();
        closeProxyConnection();
    }

    function closeServerConnection() {
        if (serverConnection && !serverConnection.ended && !proxyConnection.destroyed) serverConnection.destroy();
        serverQueue = [];
    }

    function closeProxyConnection() {
        if (proxyConnection && !proxyConnection.ended && !proxyConnection.destroyed) proxyConnection.destroy();
        proxyQueue = [];
    }

    function writeServerConnection(data) {
        if (serverConnection && !serverConnection.ended && !serverConnection.destroyed) serverConnection.write(data);
        // if (serverConnection && !serverConnection.ended && !serverConnection.destroyed) {
        //     if (data !== true) {
        //         serverQueue.push(data);
        //     }

        //     if (serverSending || !serverQueue.length) return;
            
        //     serverSending = true;
        //     data = serverQueue.shift();

        //     if (!serverConnection.write(data)) {
        //         serverConnection.once("drain", () => {
        //             serverSending = false;
        //             writeServerConnection(true);
        //         });
        //     } else {
        //         serverSending = false;
        //         writeServerConnection(true);
        //     }
        // }
    }

    function writeProxyConnection(data) {
        if (proxyConnection && !proxyConnection.ended && !proxyConnection.destroyed) proxyConnection.write(data);
        // if (proxyConnection && !proxyConnection.ended && !proxyConnection.destroyed) {
        //     if (data !== true) {
        //         proxyQueue.push(data);
        //     }

        //     if (proxySending || !proxyQueue.length) return;
            
        //     proxySending = true;
        //     data = proxyQueue.shift();

        //     if (!proxyConnection.write(data)) {
        //         proxyConnection.once("drain", () => {
        //             proxySending = false;
        //             writeProxyConnection(true);
        //         });
        //     } else {
        //         proxySending = false;
        //         writeProxyConnection(true);
        //     }
        // }
    }
});

// Listen
proxyServer.listen(config.port, config.hostname, () => log(1, `Listening at :${config.port}`));

function readJson(filePath) {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

function log(level, ...msg) {
    if (config.loggingLevel >= level) console.log(`[${new Date().toUTCString()}]`, ...msg);
}

function logProxyError(err) {
    if (!config.ignoreErrors && !config.ignoreProxyErrors) console.error(`[${new Date().toUTCString()}]`, "[PROXY ERROR]", err);
}

function logServerError(err) {
    if (!config.ignoreErrors && !config.ignoreServerErrors) console.error(`[${new Date().toUTCString()}]`, "[SERVER ERROR]", err);
}

function ipMatch(ip, matches) {
    let matched = false;
    matches.forEach(match => {
        if (matched) return;
        const [subnet, bits] = match.split("/");
        if (bits) {
            const subnetBinary = subnet.split(".").map(octet => parseInt(octet).toString(2).padStart(8, "0")).join("");
            const ipBinary = ip.split(".").map(octet => parseInt(octet).toString(2).padStart(8, "0")).join("");
            const maskedSubnet = subnetBinary.substring(0, parseInt(bits));
            const maskedIp = ipBinary.substring(0, parseInt(bits));
            if (maskedSubnet == maskedIp) matched = match;
        } else {
            if (ip == match) matched = match;
        }
    });
    return matched;
}

function getHeaders(splitHeaders) {
    return Object.fromEntries(splitHeaders.map(i => {
        const match = i.match(headersRegex);
        if (!match) return null;
        return [match[1], match[2]];
    }).filter(i => i));
}

function findServer(hostname) {
    if (typeof hostname != "string") return null;
    return servers.find(i => i?.proxyHostnames?.find(i =>
        i.startsWith(".") ? hostname.endsWith(i) :
            i.endsWith(".") ? hostname.startsWith(i) :
                hostname == i
    ));
}

function formatString(string, options) {
    let formatted = string;
    Object.entries(options).forEach(([key, value]) => formatted = formatted.replace(new RegExp(`%{${key}}`, "g"), value));
    return formatted;
}

function parseCookies(cookiesString) {
    return Object.fromEntries(cookiesString.split("; ").map(i => {
        const [name, value] = i.split("=");
        if (!name) return null;
        return [name, value];
    }).filter(i => i));
}

function stringifyCookies(cookies) {
    return Object.entries(cookies).map(i => `${i[0]}=${i[1]}`).join("; ");
}

function objectDefaults(obj, def) {
    if (typeof obj != "object") return def;

    return (function checkEntries(object = obj, defaultObj = def) {
        Object.entries(defaultObj).forEach(([key, value]) => {
            if (object[key] == undefined) object[key] = value;
            else if (value != null && typeof value == "object") checkEntries(object[key], defaultObj[key]);
        });
        return object;
    })();
}

function watch(file, json, callback) {
    fs.watchFile(file, () => {
        if (!json) return callback(fs.readFileSync(file, "utf-8"));
        try {
            callback(readJson(file));
        } catch (err) {
            console.error(`Failed to read ${file}, error:`, err);
        }
    });
}

function getHeader(headers, name) {
    const key = Object.keys(headers).find(i => i.toLowerCase() == name.toLowerCase());
    return headers[key];
}

function setHeader(headers, name, value) {
    const key = Object.keys(headers).find(i => i.toLowerCase() == name.toLowerCase());
    value ?
        headers[key || name] = value :
        delete headers[key || name];
}
