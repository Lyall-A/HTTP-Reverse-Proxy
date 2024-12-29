#!/usr/bin/env node
const net = require("net");
const tls = require("tls");
const path = require('path');
const fs = require("fs");
const {
    LogFlag,
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
    defaults,
    copyRecursiveSync,
} = require("./utils");

const CLINAME = 'proxy-cli';

// Global variables
let proxyServer;
let proxyConfig = {};
let serviceDefaults = {};
let services = new Map();
let globalWhitelist;
let globalBlacklist;

const EXAMPLE_DIR = path.join(__dirname, "example");

global.LOG = LogFlag();

function main() {
    const args = process.argv.slice(2);
    const command = args[0];

    if (args.length === 0 || args.includes("--help")) {
        displayHelp();
        process.exit(0);
    }
    else if (command === "create") {
        scaffoldServer();
    }
    else if (command === "start") {
        startProxy();
    }
    else {
        console.error("Unknown command:", command);
        displayHelp();
        process.exit(1);
    }
}

function displayHelp() {
    console.log(`
        Usage: ${CLINAME} <command>

        Commands:
            start   Start the proxy server
            create  Scaffolds a new server setup in an empty folder
            --help  Show this help message
    `);
}

function scaffoldServer() {
    console.log("Scaffolding new server...");

    if (!fs.existsSync(EXAMPLE_DIR)) {
        console.error("Example directory not found:", EXAMPLE_DIR);
        process.exit(1);
    }

    let conflict = false;
    fs.readdirSync(EXAMPLE_DIR).forEach(file => {
        const src = path.join(EXAMPLE_DIR, file);
        const dest = path.join(process.cwd(), file);

        if (['.DS_Store'].includes(file)) return;
        if (fs.existsSync(dest) && !fs.statSync(dest).isDirectory()) {
            console.warn(`File already exists and would be overwritten: ${file}`);
            conflict = true;
        }
    });

    if (conflict) {
        console.log(`Aborted. Resolve conflicts before running init.`);
        return;
    }

    fs.readdirSync(EXAMPLE_DIR).forEach(file => {
        const src = path.join(EXAMPLE_DIR, file);
        const dest = path.join(process.cwd(), file);
        copyRecursiveSync(src, dest);
        console.log(`Copied: ${file}`);
    });

    console.log("Server scaffolding complete.\n");
    console.log(" - Edit files, see readme file for instructions");
    console.log(` - To start the server run \`${CLINAME} start\``);
}


function startProxy() {
    console.log("Starting proxy server...");

    // Proxy Configuration
    watch("config.json", (json, filename) => {
        LOG.INFO && console.log(timestamp(), `Loaded Proxy Config (${filename})`);
        proxyConfig = json;
    });

    // Auth page html
    watch(path.join(__dirname, "authorization.html"), file => {
        defaultAuthorizationHtmlFile = file;
        LOG.INFO && console.log(timestamp(), "Loaded authorization HTML");
    });

    // Global black/white list
    if (proxyConfig.blacklist) watch(proxyConfig.blacklist, file => {
        globalBlacklist = parseTxtFile(file);
        LOG.INFO && console.log(timestamp(), "Loaded global blacklist", `(${globalBlacklist.length} entries)`);
    });
    if (proxyConfig.whitelist) watch(proxyConfig.whitelist, file => {
        globalWhitelist = parseTxtFile(file);
        LOG.INFO && console.log(timestamp(), "Loaded global whitelist", `(${globalWhitelist.length} entries)`);
    });

    // Defaults for services
    watch("./services/_defaults.json", (json, filename) => {
        LOG.INFO && console.log(timestamp(), `Loaded serviceDefaults config (${filename})`);
        serviceDefaults = json;
    });

    // Live load services
    services = createLiveFileMap('./services/*.json', (service, key, filename) => {
        LOG.INFO && console.log(timestamp(), "Loaded service:", key);
        return service;
    });
    services.watch();

    // Start proxy server
    proxyServer = (proxyConfig.tls ? tls : net).createServer({
        key: fs.existsSync(proxyConfig.key) ? fs.readFileSync(proxyConfig.key) : undefined,
        cert: fs.existsSync(proxyConfig.cert) ? fs.readFileSync(proxyConfig.cert) : undefined,
        ...proxyConfig.additionalProxyServerOptions
    });
    proxyServer.on("connection", connectionHandler);
    proxyServer.listen(proxyConfig.port, proxyConfig.hostname, () => {
        console.log(timestamp(), "Proxy server started.");
        displaySummary();
    });
    
    process.on("SIGINT", closeProxy);
    process.on("SIGTERM", closeProxy);
}

function displaySummary() {
    console.log('='.repeat(80));
    console.log("  REVERSE PROXY SERVER SUMMARY");
    console.log('='.repeat(80));
    console.log('');

    console.log(`Proxy Listening on:`);
    console.log(`  Hostname: ${proxyConfig.hostname || "0.0.0.0"}`);
    console.log(`  Port: ${proxyConfig.port || 80}`);
    console.log(`TLS: ${proxyConfig.tls ? "Enabled" : "Not enabled"}`);
    if (proxyConfig.tls) {
        console.log(`  - Key: ${proxyConfig.key || "Not Provided"}`);
        console.log(`  - Certificate: ${proxyConfig.cert || "Not Provided"}`);
    }
    console.log(`Logging Level: ${LOG.currentLevel}`);
    console.log(`Ignore Errors: ${proxyConfig.ignoreErrors ? "Yes" : "No"}\n`);

    if (globalWhitelist) {
        console.log(`Global Whitelist: ${globalWhitelist.length} entries`);
    } else {
        console.log(`Global Whitelist: Not Configured`);
    }

    if (globalBlacklist) {
        console.log(`Global Blacklist: ${globalBlacklist.length} entries`);
    } else {
        console.log(`Global Blacklist: Not Configured`);
    }

    console.log(`\n Registered Services: (${services.size} services)`);
    console.log('-'.repeat(80));
    services.forEach((service, key) => {
        console.log(`\n${key}:`);
        console.log(`  Hostnames: ${service.proxyHostnames.join(", ")}`);
        console.log(`  Target:    ${service.serverHostname}:${service.serverPort}`);
        console.log(`  TLS:       ${service.useTls ? "Yes" : "No"}`);
        console.log(`  Auth:      ${service.authorization ? service.authorizationType : "None"}`);
    });

    console.log(`\n${'='.repeat(80)}\n`);
    console.log(timestamp(), 'Proxy started...');
}


function connectionHandler(proxyConnection) {
    const ip = proxyConnection.remoteAddress?.split("::ffff:")[1] || proxyConnection.remoteAddress;

    if (!ip) {
        LOG.WARN && console.log(timestamp(), `[REFUSED] No IP?!`);
        return proxyConnection.destroy(); // Why does this happen sometimes?
    }

    // Global Blacklist
    if (globalBlacklist && ipMatch(ip, globalBlacklist)) {
        LOG.WARN && console.log(timestamp(), `[REFUSED] Blacklisted IP ${ip} attempted to connect!`);
        return proxyConnection.destroy();
    }
    // Global Whitelist
    if (globalWhitelist && !ipMatch(ip, globalWhitelist)) {
        LOG.WARN && console.log(timestamp(), `[REFUSED] Unwhitelisted IP ${ip} attempted to connect!`);
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
                LOG.DEBUG && console.log(timestamp(), `[NOHOST] IP ${ipFormatted} tried to reach unknown hostname ${hostname}`);
                return proxyConnection.destroy();
            }

            // Get default server options + found server options
            const serviceOptions = objectDefaults(service, serviceDefaults || {});

            // Get real IP (if using some sort of proxy like Cloudflare)
            realIp = serviceOptions.realIpHeader ? headers[serviceOptions.realIpHeader] : null;
            ipFormatted = `${ip}${realIp ? ` (${realIp})` : ""}`;

            // Make sure using supported version
            if (serviceOptions.supportedVersions && !serviceOptions.supportedVersions.includes(version)) {
                LOG.DEBUG && console.log(timestamp(), `[UNSUPPORTED] IP ${ipFormatted} using unsupported version ${version}`);
                return proxyConnection.destroy();
            }

            // Check whitelist/blacklist again with custom options
            // Whitelist
            const whitelist = serviceOptions.whitelist !== serviceDefaults.whitelist ? readJson(serviceOptions.whitelist) : null;
            if (whitelist && !ipMatch(ip, whitelist)) {
                LOG.WARN && console.log(timestamp(), `[REFUSED] Unwhitelisted IP ${ip} attempted to connect!`);
                return proxyConnection.destroy();
            }
            // Blacklist
            const blacklist = serviceOptions.blacklist !== serviceDefaults.blacklist ? readJson(serviceOptions.blacklist) : null;
            if (blacklist && ipMatch(ip, blacklist)) {
                LOG.WARN && console.log(timestamp(), `[REFUSED] Blacklisted IP ${ip} attempted to connect!`);
                return proxyConnection.destroy();
            }

            // Service requires authorization
            if (serviceOptions.authorization) {
                if (!serviceOptions.authorizationPassword) {
                    // No authorization password set
                    LOG.WARN && console.log(timestamp(), `[AUTH] IP ${ipFormatted} tried to reach ${hostname} which requires authorization, but no authorization password was set`);
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
                            LOG.DEBUG && console.log(timestamp(), `[AUTH] IP ${ipFormatted} tried to reach ${hostname} which requires authorization`);
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
                            LOG.DEBUG && console.log(timestamp(), `[AUTH] IP ${ipFormatted} tried to reach ${hostname} which requires authorization`);
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
                            LOG.DEBUG && console.log(timestamp(), `[AUTH] IP ${ipFormatted} tried to reach ${hostname} which requires authorization`);
                            proxyConnection.write(`${version} 401 Unauthorized\r\nContent-Length: 0\r\n\r\n`);
                            return;
                        }

                        authorized = true;
                    } else {
                        // Unknown authorization type
                        LOG.WARN && console.log(timestamp(), `[AUTH] IP ${ipFormatted} tried to reach ${hostname} which requires authorization, but an unknown authorization type was set`);
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

            // console.log(timestamp(), reconstructedData.toString());

            if (!serverConnection) {
                // Connect to server
                LOG.VERBOSE && console.log(timestamp(), `CONNECTING IP ${ipFormatted} connecting to ${hostname}`);

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
}

function closeProxy() {
    LOG.INFO && console.log(timestamp(), "Shutting down proxy...");
    proxyServer.close();
    services.unwatch();
    unwatchAll();
    LOG.INFO && console.log(timestamp(), "Stopped.");
    process.exit(0);
}

main();
