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
let defaultAuthorizationHtml = formatString(defaultAuthorizationHtmlFile, { config, cookieExpiry: config.defaultServerOptions.cookieExpiry, authorizationCookie: config.defaultServerOptions.authorizationCookie });
watch("authorization.html", false, file => {
    defaultAuthorizationHtmlFile = file;
    defaultAuthorizationHtml = formatString(defaultAuthorizationHtmlFile, { config, cookieExpiry: config.defaultServerOptions.cookieExpiry, authorizationCookie: config.defaultServerOptions.authorizationCookie });
    log(0, "Updated authorization HTML");
});

// Default whitelist
let defaultWhitelist;
if (config.defaultServerOptions.whitelist) {
    defaultWhitelist = readJson(config.defaultServerOptions.whitelist);
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

    let serverConnection;

    // NOTE: Attempt to fix memory leak (fail)
    // let proxyQueue = [];
    // let proxySending = false;
    // let serverQueue = [];
    // let serverSending = false;

    proxyConnection.on("data", data => {
        // Proxy server on data
        const [rawHeaders, rawData = ""] = data.toString().split("\r\n\r\n");
        const splitHeaders = rawHeaders.split("\r\n");

        const [requestLine, method, uri, version] = splitHeaders[0].match(requestLineRegex) || [];
        if (requestLine) {
            const headers = getHeaders(splitHeaders); // Get headers

            let realIp = config.defaultServerOptions.realIpHeader ? headers[config.defaultServerOptions.realIpHeader] : null; // Get real IP using default realIpHeader config (if using some sort of proxy like Cloudflare)
            let ipFormatted = `${ip}${realIp ? ` (${realIp})` : ""}`;

            // Make sure using supported version
            if (config.supportedVersions && !config.supportedVersions.includes(version)) {
                log(2, `IP ${ipFormatted} using unsupported version ${version}`);
                return proxyConnection.destroy();
            }

            // Get hostname
            const [hostname] = getHeader(headers, "Host")?.match(hostnameRegex) || [];

            const server = findServer(hostname);

            // Find server
            if (!server) {
                log(2, `IP ${ipFormatted} tried to reach unknown hostname ${hostname}`);
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
            ipFormatted = `${ip}${realIp ? ` (${realIp})` : ""}`;

            // Server requires authorization
            if (serverOptions.authorization) {
                if (!serverOptions.authorizationPassword) {
                    // No authorization password set, destroy
                    log(1, `IP ${ipFormatted} tried to reach ${hostname} which requires authorization, but no authorization password was set`);
                    return proxyConnection.destroy();
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

                        if (cookies[serverOptions.authorizationCookie] != serverOptions.authorizationPassword) {
                            // Incorrect or no authorization cookie
                            if (!isLastType) return;
                            const authorizationHtml = serverOptions.authorizationCookie != config.defaultServerOptions.authorizationCookie ? formatString(defaultAuthorizationHtmlFile, { config, serverOptions, cookieExpiry: config.defaultServerOptions.cookieExpiry, authorizationCookie: serverOptions.authorizationCookie }) : defaultAuthorizationHtml
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

                        if (password != serverOptions.authorizationPassword) {
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

                        if (header != serverOptions.authorizationPassword) {
                            // Incorrect or no custom header
                            if (!isLastType) return;
                            log(2, `IP ${ipFormatted} tried to reach ${hostname} which requires authorization`);
                            proxyConnection.write(`${version} 401 Unauthorized\r\nContent-Length: 0\r\n\r\n`);
                            return;
                        }

                        authorized = true;
                    } else {
                        // Unknown authorization type, destroy
                        log(1, `IP ${ipFormatted} tried to reach ${hostname} which requires authorization, but an unknown authorization type was set`);
                        return proxyConnection.destroy();
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
                log(3, `IP ${ipFormatted} connecting to ${hostname}`);

                serverConnection = (serverOptions.useTls ? tls : net).connect({
                    host: serverOptions.serverHostname,
                    port: serverOptions.serverPort,
                    rejectUnauthorized: false,
                    ...serverOptions.additionalServerOptions
                });

                // Server events
                serverConnection.on("data", i => writeProxyConnection(i));
                serverConnection.on("close", i => closeAll("serverConnection closed"));
                serverConnection.on("end", i => closeAll("serverConnection ended"));
                serverConnection.on("error", err => {
                    closeAll("serverConnection error");
                    logServerError(err);
                });
            }

            writeServerConnection(reconstructedData); // Write changed data if this buffer contains headers
        } else
            writeServerConnection(data); // Write unchanged data if this buffer does not contain headers
    });

    // Proxy events
    proxyConnection.on("close", i => closeAll("proxyConnection closed"));
    proxyConnection.on("end", i => closeAll("proxyConnection ended"));
    proxyConnection.on("error", err => {
        closeAll("proxyConnection error");
        logProxyError(err);
    });
    
    // Functions
    // TODO: very bad memory leak, for example if a server sends a 1gb file, the proxy will use up 1gb of memory even after the connection is closed
    function closeAll(reason) {
        log(4, "Closing all, reason:", reason);
        closeServerConnection();
        closeProxyConnection();
    }
    
    function closeServerConnection() {
        if (serverConnection && !serverConnection.ended && !proxyConnection.destroyed) {
            log(4, `Closing serverConnection`);
            serverConnection.end();
            // serverQueue = [];
        }
    }

    function closeProxyConnection() {
        if (proxyConnection && !proxyConnection.ended && !proxyConnection.destroyed) {
            log(4, `Closing proxyConnection`);
            proxyConnection.end();
            // proxyQueue = [];
        }
    }

    function writeServerConnection(data) {
        // log(4, `Writing ${data.length} bytes to serverConnection`);
        if (serverConnection && !serverConnection.ended && !serverConnection.destroyed) serverConnection.write(data);
        // NOTE: Attempt to fix memory leak (fail)
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
        // log(4, `Writing ${data.length} bytes to proxyConnection`);
        if (proxyConnection && !proxyConnection.ended && !proxyConnection.destroyed) proxyConnection.write(data);
        // NOTE: Attempt to fix memory leak (fail)
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

/**
 * Get JSON from file path
 * @param {string} filePath File path
 * @returns {object} JSON
 */
function readJson(filePath) {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

/**
 * Log
 * @param {number} level Logging level
 * @param  {...any} msg Message to log
 */
function log(level, ...msg) {
    if (config.loggingLevel >= level) console.log(`[${timestamp()}]`, ...msg);
}

/**
 * Log proxy error
 * @param {any} err Error to log
 */
function logProxyError(err) {
    if (!config.ignoreErrors && !config.ignoreProxyErrors) console.error(`[${timestamp()}]`, "[PROXY ERROR]", err);
}

/**
 * Log server error
 * @param {any} err Error to log
 */
function logServerError(err) {
    if (!config.ignoreErrors && !config.ignoreServerErrors) console.error(`[${timestamp()}]`, "[SERVER ERROR]", err);
}

/**
 * Matches IP
 * @param {string} ip IP to match
 * @param {object} matches Array of IP's or CIDR's to match with
 * @returns {string|boolean} IP/CIDR matched or false
 */
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
            if (maskedSubnet === maskedIp) matched = match;
        } else {
            if (ip === match) matched = match;
        }
    });
    return matched;
}

/**
 * Parses array of string headers
 * @param {object} splitHeaders Array of headers as string (Host: localhost)
 * @returns {object} Parsed headers
 */
function getHeaders(splitHeaders) {
    return Object.fromEntries(splitHeaders.map(i => {
        const match = i.match(headersRegex);
        if (!match) return null;
        return [match[1], match[2]];
    }).filter(i => i));
}

/**
 * Find server object using hostname
 * @param {string} hostname Hostname to search for
 * @returns {object} Server object
 */
function findServer(hostname) {
    if (typeof hostname != "string") return null;
    return servers.find(i => i?.proxyHostnames?.find(i =>
        i.startsWith(".") ? hostname.endsWith(i) :
        i.endsWith(".") ? hostname.startsWith(i) :
        hostname === i
    ));
}

/**
 * Formats strings with `%{}` syntax and dot notation (eg. `%{hello.world}` with options `{ hello: { world: "Hello, World!" } }`)
 * @param {string} string String to format
 * @param {object} options Object to use for formatting
 * @param {any} undef Value to use with undefined values
 * @returns {string} Formatted string
 */
function formatString(string, options, undef = "") {
    let formatted = string;
    // Object.entries(options).forEach(([key, value]) => formatted = formatted.replace(new RegExp(`%{${key}}`, "g"), value));
    formatted = formatted.replace(/%{(.*?)}/g, (string, match) => match.split(".").reduce((prev, curr) => prev[curr] ?? undef, options));
    return formatted;
}

/**
 * Parse string of cookies into object
 * @param {string} cookiesString String of cookies
 * @returns {object} Parsed cookies
 */
function parseCookies(cookiesString) {
    return Object.fromEntries(cookiesString.split(/; /).map(i => {
        const [name, value] = i.split("=");
        if (!name) return null;
        return [name, value];
    }).filter(i => i));
}

/**
 * Stringifies object of cookies
 * @param {object} cookies Object of cookies
 * @returns {string} Stringified cookies
 */
function stringifyCookies(cookies) {
    return Object.entries(cookies).map(i => `${i[0]}=${i[1]}`).join("; ");
}

/**
 * Merges objects
 * @param {object} obj Object
 * @param {object} def Object of defaults
 * @returns {object} Merged objects
 */
function objectDefaults(obj, def) {
    if (typeof obj !== "object") return def;

    return (function checkEntries(object = obj, defaultObj = def) {
        Object.entries(defaultObj).forEach(([key, value]) => {
            if (object[key] === undefined) object[key] = value;
            else if (value !== null && typeof value === "object") checkEntries(object[key], defaultObj[key]);
        });
        return object;
    })();
}

/**
 * Watches for file change
 * @param {string} file File path to watch for
 * @param {boolean} json If file should be parsed when changed
 * @param {function} callback Callback for when file is changed
 */
function watch(file, json, callback) {
    fs.watchFile(file, () => {
        if (!json) return callback(fs.readFileSync(file, "utf-8"));
        try {
            callback(readJson(file));
        } catch (err) {
            console.error(`Failed to read '${file}', error:`, err);
        }
    });
}

/**
 * Finds specific header case-insensitive
 * @param {object} headers Headers
 * @param {string} name Header to look for
 * @returns {string} Header value
 */
function getHeader(headers, name) {
    const key = Object.keys(headers).find(i => i.toLowerCase() === name.toLowerCase());
    return headers[key];
}

/**
 * Sets or deletes header case-insensitive
 * @param {object} headers Headers
 * @param {string} name Header to change
 * @param {string} value New header value
 */
function setHeader(headers, name, value) {
    const key = Object.keys(headers).find(i => i.toLowerCase() === name.toLowerCase());
    value ?
        headers[key || name] = value :
        delete headers[key || name];
}

/**
 * Timestamp for logs
 * @returns {string} Timestamp
 */
function timestamp() {
    const date = new Date();
    
    const day = date.getDate().toString().padStart(2, "0");
    const month = date.getMonth().toString().padStart(2, "0");
    const year = date.getFullYear().toString().padStart(2, "0");

    const hour = date.getHours().toString().padStart(2, "0");
    const minute = date.getMinutes().toString().padStart(2, "0");
    const second = date.getSeconds().toString().padStart(2, "0");

    return `${day}/${month}/${year} ${hour}:${minute}:${second}`;
}