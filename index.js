#!/usr/bin/env node
const net = require("net");
const tls = require("tls");
const path = require('path');
const fs = require("fs");
const {
    requestLineRegex,
    hostnameRegex,
    LogFlag,
    readJson,
    parseTxtFile,
    ipMatch,
    getHeaders,
    findService,
    formatString,
    parseCookies,
    stringifyCookies,
    objectDefaults,
    FileWatcher,
    createLiveFileMap,
    getHeader,
    setHeader,
    timestamp,
    defaults,
    copyRecursiveSync,
    dedent,
} = require("./utils");

const CLINAME = 'proxy-cli';

// Global variables
let proxyServer;            // proxy server instance
let proxyConfig = {};       // Proxy global config (config.json)
let serviceDefaults = {};   // Services default config (services/_defaults.json)
let fw = new FileWatcher(); // used to watch global files (config, html, ip lists)
let services = new Map();   // used to watch services/*.json, but they are dynamically maped to this map (live reloaded, included, removed)
let globalWhitelist;
let globalBlacklist;
let rememberedIps = new Map(); // In-memory IP storage for "rememberIp" authentication

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
        process.exit(0);
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
        console.error("Error! The Example directory doesn't exist.", EXAMPLE_DIR);
        process.exit(1);
    }

    let conflict = false;
    fs.readdirSync(EXAMPLE_DIR).forEach(file => {
        const src = path.join(EXAMPLE_DIR, file);
        const dest = path.join(process.cwd(), file);
        if (['.DS_Store', 'Thumbs.db', 'desktop.ini'].includes(file)) return;
        if (fs.existsSync(dest) && !fs.statSync(dest).isDirectory()) {
            console.warn(`File already exists and would be overwritten: ${file}`);
            conflict = true;
        }
    });

    if (conflict) {
        console.log(`Aborted.`);
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
    fw.watch("config.json", (json, filename) => {
        LOG.INFO && console.log(timestamp(), `Loaded Proxy Config (${filename})`);
        proxyConfig = json;
    });

    // Auth page html
    fw.watch(path.join(__dirname, "authorization.html"), file => {
        defaultAuthorizationHtmlFile = file;
        LOG.INFO && console.log(timestamp(), "Loaded authorization HTML");
    });

    // Global black/white list
    if (proxyConfig.blacklist) fw.watch(proxyConfig.blacklist, file => {
        globalBlacklist = parseTxtFile(file);
        LOG.INFO && console.log(timestamp(), "Loaded global blacklist", `(${globalBlacklist.length} entries)`);
    });
    if (proxyConfig.whitelist) fw.watch(proxyConfig.whitelist, file => {
        globalWhitelist = parseTxtFile(file);
        LOG.INFO && console.log(timestamp(), "Loaded global whitelist", `(${globalWhitelist.length} entries)`);
    });

    // Defaults for services
    fw.watch("./services/_defaults.json", (json, filename) => {
        LOG.INFO && console.log(timestamp(), `Loaded serviceDefaults config (${filename})`);
        serviceDefaults = json;
    });

    // Dynamically load services into a map that is live reloaded
    // This map will include al json files into that folder,
    // the map will be modified automatically if files are added removed or the content changes
    // the file name is used as a key to that json (parsed) without extension
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
        displaySummary();
        LOG.INFO && console.log(timestamp(), 'Proxy started...');
    });
    
    process.on("SIGINT", closeProxy);
    process.on("SIGTERM", closeProxy);
}

function displaySummary() {
    console.log(dedent(`
        ================================================================================
          REVERSE PROXY SERVER SUMMARY
        ================================================================================

        Proxy Listening on:
          Hostname: ${proxyConfig.hostname || "0.0.0.0"}
          Port: ${proxyConfig.port || 80}
          
          TLS: ${proxyConfig.tls ? "Enabled" : "Not enabled"}
            - Key: ${proxyConfig.key || "Not Provided"}
            - Certificate: ${proxyConfig.cert || "Not Provided"}
        
        Logging Level: ${LOG.currentLevel}
        Ignore Errors: ${proxyConfig.ignoreErrors ? "Yes" : "No"}

        Global Whitelist: ${globalWhitelist?.length ?? 'Not Configured'} entries
        Global Blacklist: ${globalBlacklist?.length ?? 'Not Configured'} entries

        Registered Services: (${services.size} services)
        --------------------------------------------------------------------------------
    `));
    services.forEach((service, key) => {
        console.log(dedent(`
            ${key}:
              Hostnames: ${service.proxyHostnames.join(", ")}
              Target:    ${service.serverHostname}:${service.serverPort}
              TLS:       ${service.useTls ? "Yes" : "No"}
              Auth:      ${service.authorization ? service.authorizationType : "None"}
        `));
    });
    console.log('='.repeat(80));
}


function connectionHandler(proxyConnection) {
    const ip = proxyConnection.remoteAddress?.split("::ffff:")[1] || proxyConnection.remoteAddress;

    if (!ip) {
        LOG.WARN && console.log(timestamp(), `[REFUSED] No IP?!`);
        return proxyConnection.destroy(); // Why does this happen sometimes?
    }

    // Global Blacklist
    if (globalBlacklist && ipMatch(ip, globalBlacklist)) {
        LOG.WARN && console.log(timestamp(), `[CONNECTION_BLOCKED_BLACKLISTED] Blacklisted ${ip} attempted to connect!`);
        return proxyConnection.destroy();
    }
    // Global Whitelist
    if (globalWhitelist && !ipMatch(ip, globalWhitelist)) {
        LOG.WARN && console.log(timestamp(), `[CONNECTION_BLOCKED_UNWHITELISTED] Unwhitelisted ${ip} attempted to connect!`);
        return proxyConnection.destroy();
    }

    let connectionToService;

    proxyConnection.on("data", data => {
        // Proxy server on data
        const [rawHeaders, ...splitRawData] = data.toString().split("\r\n\r\n");
        const rawData = splitRawData.join("\r\n\r\n");
        const splitHeaders = rawHeaders.split("\r\n");

        const [requestLine, method, uri, version] = splitHeaders.splice(0, 1)[0].match(requestLineRegex) || []; // Get and remove request line from headers

        
        if (requestLine) {
            // Get headers
            const headers = getHeaders(splitHeaders);

            let realIp = serviceDefaults.realIpHeader ? headers[serviceDefaults.realIpHeader] : null;
            let ipFormatted = `${ip}${realIp ? ` (${realIp})` : ""}`;

            // Get hostname
            const [hostname] = getHeader(headers, "Host")?.match(hostnameRegex) || [];
            if (!hostname) {
                LOG.DEBUG && console.log(timestamp(), `[CONNECTION_NO_HOST] ${ipFormatted} tried to establish a connection without host header`);
                return proxyConnection.destroy();
            }

            // Find service to handle this request
            const service = findService(services, hostname);
            if (!service) {
                LOG.DEBUG && console.log(timestamp(), `[PROXY_SERVICE_NOT_FOUND] ${ipFormatted} tried to reach unknown hostname ${hostname}`);
                return proxyConnection.destroy();
            }

            // Make service options inherit default options
            const serviceOptions = objectDefaults(service, serviceDefaults || {});

            // Get real IP (if using some sort of proxy like Cloudflare)
            realIp = serviceOptions.realIpHeader ? headers[serviceOptions.realIpHeader] : null;
            ipFormatted = `${ip}${realIp ? ` (${realIp})` : ""}`;

            // Make sure using supported version
            if (serviceOptions.supportedVersions && !serviceOptions.supportedVersions.includes(version)) {
                LOG.DEBUG && console.log(timestamp(), `[CONNECTION_UNSUPPORTED_VERSION] ${ipFormatted} using unsupported version ${version}`);
                return proxyConnection.destroy();
            }

            // Check whitelist/blacklist again with custom options
            // Whitelist
            const whitelist = serviceOptions.whitelist !== serviceDefaults.whitelist ? readJson(serviceOptions.whitelist) : null;
            if (whitelist && !ipMatch(ip, whitelist)) {
                LOG.WARN && console.log(timestamp(), `[CONNECTION_REFUSED_UNWHITELISTED] Unwhitelisted ${ip} attempted to connect!`);
                return proxyConnection.destroy();
            }
            // Blacklist
            const blacklist = serviceOptions.blacklist !== serviceDefaults.blacklist ? readJson(serviceOptions.blacklist) : null;
            if (blacklist && ipMatch(ip, blacklist)) {
                LOG.WARN && console.log(timestamp(), `[CONNECTION_REFUSED_BLACKLISTED] Blacklisted ${ip} attempted to connect!`);
                return proxyConnection.destroy();
            }

            // Service requires authorization
            if (serviceOptions.authorization) {
                if (!serviceOptions.authorizationPassword) {
                    LOG.WARN && console.error(timestamp(), `[AUTH_REFUSED_MISSING_CONFIG] ${ipFormatted} tried to reach ${hostname}. Error Service misconfigured! Authorization is enabled but password is empty!`);
                    return proxyConnection.destroy();
                }

                let bypassAuth = false;
                if (serviceOptions.authorizationRemembersIp && realIp) {
                    const lastAuthorized = rememberedIps.get(realIp + hostname);
                    if (lastAuthorized && (Date.now() - lastAuthorized < serviceOptions.authorizationRemembersIpTtl)) {
                        bypassAuth = true;
                    }
                    // i dont remember this ip being authorized, just continue with check as normal
                }
                
                // Check authorization
                if (!bypassAuth) {

                    let authorized = false;
                    const authorizationTypes = Array.isArray(serviceOptions.authorizationType) ? serviceOptions.authorizationType : [serviceOptions.authorizationType];
                    for (let i = 0; i < authorizationTypes.length; i++) {
                        const isLast = i === authorizationTypes.length - 1;
                        authorized = checkAuthorization(authorizationTypes[i].toLowerCase(), isLast);
                        if (authorized) {
                            // successfuly authorized add to remembered ips
                            if (serviceOptions.authorizationRemembersIp && realIp) rememberedIps.set(realIp + hostname, Date.now());
                            break;
                        }
                    }
                    
                    // Authorization DENIED!
                    if (!authorized) {
                        LOG.DEBUG && console.log(timestamp(), `[AUTH_DENIED] ${ipFormatted} tried to reach ${hostname}`);
                        return;
                    }
                }

            }

            function checkAuthorization(authorizationType, shouldSendFailResp) {
                if (authorizationType === "cookies") {
                    const cookies = parseCookies(getHeader(headers, "Cookie") || "");
                    if (cookies[serviceOptions.authorizationCookie] === serviceOptions.authorizationPassword) {
                        // Remove cookie before sending to server
                        delete cookies[serviceOptions.authorizationCookie];
                        setHeader(headers, "Cookie", stringifyCookies(cookies));
                        return true;
                    }
                    if (shouldSendFailResp) {
                        // LOG.DEBUG && console.log(timestamp(), `[AUTH_DENIED_COOKIE] ${ipFormatted} tried to reach ${hostname} `);
                        const vars = {
                            config: proxyConfig,
                            serverOptions: serviceOptions,
                            cookieMaxAge: serviceDefaults.cookieMaxAge,
                            authorizationCookie: serviceOptions.authorizationCookie,
                            hostname,
                            ip: realIp || ip,
                        };
                        const authorizationHtml = formatString(defaultAuthorizationHtmlFile, vars);
                        proxyConnection.write(`${version} 401 Unauthorized\r\nContent-Type: text/html\r\nContent-Length: ${authorizationHtml.length}\r\n\r\n${authorizationHtml}`);
                    }
                    return false;
                }
                else if (authorizationType === "www-authenticate") {
                    // Authorize using WWW-Authenticate header
                    const password = Buffer.from((getHeader(headers, "Authorization") || "").split(" ")[1] || "", "base64").toString().split(":")[1];
                    if (password === serviceOptions.authorizationPassword) return true;
                    if (shouldSendFailResp) {
                        // LOG.DEBUG && console.log(timestamp(), `[AUTH_DENIED_WWW_AUTHENTICATE] ${ipFormatted} tried to reach ${hostname} `);
                        proxyConnection.write(`${version} 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n`);
                    }
                    return false;
                }
                else if (authorizationType === "custom-header") {
                    const header = getHeader(headers, serviceOptions.customAuthorizationHeader);
                    if (header === serviceOptions.authorizationPassword) return true;
                    if (shouldSendFailResp) {
                        // LOG.DEBUG && console.log(timestamp(), `[AUTH_DENIED_HEADER] ${ipFormatted} tried to reach ${hostname} `);
                        proxyConnection.write(`${version} 401 Unauthorized\r\nContent-Length: 0\r\n\r\n`);
                    }
                    return false;
                }
                
                LOG.ERROR && console.error(timestamp(), `[AUTH_REFUSED_INVALID_CONFIG] ${ipFormatted} tried to reach ${hostname}. Error Service misconfigured! "${authorizationType}" is not a valid authorizationType!`);
                proxyConnection.destroy();
                return false;
            }

            // Is redirect
            if (serviceOptions.redirect) {
                LOG.DEBUG && console.log(timestamp(), `[REQUEST_REDIRECTED] ${ipFormatted} redirected ${hostname} -> ${serviceOptions.redirect}`);
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

            if (!connectionToService) {
                // Connect to server
                LOG.VERBOSE && console.log(timestamp(), `[SERVICE_CONNECTION_STARTED] ${ipFormatted} connecting to ${hostname}`);

                connectionToService = (serviceOptions.useTls ? tls : net).connect({
                    host: serviceOptions.serverHostname,
                    port: serviceOptions.serverPort,
                    rejectUnauthorized: false,
                    ...serviceOptions.additionalServerOptions
                });

                // Server events
                connectionToService.on("data", i => writeProxyConnection(i));
                connectionToService.on("close", closeProxyConnection);
                connectionToService.on("end", i => closeProxyConnection);
                connectionToService.on("error", err => {
                    LOG.ERROR && console.error(timestamp(), "[SERVICE_CONNECTION_ERROR]", err);
                    closeProxyConnection();
                });

                connectionToService.on("drain", () => proxyConnection.resume());
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
        LOG.ERROR && console.error(timestamp(), "[PROXY_SERVER_ERROR]", err);
    });
    proxyConnection.on("drain", () => connectionToService?.resume());

    function closeServerConnection() { if (connectionToService && !connectionToService.ended) connectionToService.end() }
    function closeProxyConnection() { if (proxyConnection && !proxyConnection.ended) proxyConnection.end() }
    function writeServerConnection(data) { if (connectionToService && !connectionToService.ended) if (!connectionToService.write(data)) proxyConnection.pause() }
    function writeProxyConnection(data) { if (proxyConnection && !proxyConnection.ended) if (!proxyConnection.write(data)) connectionToService.pause() }
}

function closeProxy() {
    LOG.INFO && console.log(timestamp(), "Shutting down proxy...");
    proxyServer.close();
    services.unwatch();
    fw.unwatchAll();
    LOG.INFO && console.log(timestamp(), "[PROXY_SHUTDOWN] Stopped.");
    process.exit(0);
}

main();
