const net = require("net");
const tls = require("tls");
const fs = require("fs");

// Config
let config = readJson("config.json");
watch("config.json", true, file => {
    config = file;
    console.log("Updated config");
});

// Servers
let servers = readJson("servers.json").filter(i => !i?.disabled);
watch("servers.json", true, file => {
    servers = file.filter(i => !i?.disabled);
    console.log("Updated servers");
});

// Authorization HTML
let authorizationHtml = formatString(fs.readFileSync("authorization.html", "utf-8"), { authorizationCookie: config.authorizationCookie });
watch("authorization.html", false, file => {
    authorizationHtml = formatString(file, { authorizationCookie: config.authorizationCookie });
    console.log("Updated authorization HTML");
});

// Whitelist
let whitelist;
if (config.whitelist) {
    whitelist = readJson(config.whitelist);
    watch(config.whitelist, true, file => {
        whitelist = file;
        console.log("Updated whitelist");
    });
}

// Blacklist
let blacklist;
if (config.blacklist) {
    blacklist = readJson(config.blacklist);
    watch(config.blacklist, true, file => {
        blacklist = file;
        console.log("Updated blacklist");
    });
}

// Regex
const requestLineRegex = /^(.*) (.*) (HTTP\/\d*\.\d*)$/im; // GET /hello/world HTTP/1.1
// const statusLineRegex = /^(HTTP\/\d*\.\d*) (\d*) (.*)$/im; // HTTP/1.1 200 OK
const headersRegex = /^(.*?): ?(.*)$/m; // Host: localhost
const hostnameRegex = /[^:]*/; // localhost (excludes port)

// Log
if (whitelist) log(`\nWhitelist: ${whitelist.length}\n${whitelist.join("\n")}`);
if (blacklist) log(`\nBlacklist: ${blacklist.length}\n${blacklist.join("\n")}`);
log(`\nServers: ${servers.length}\n${servers.map(i => `${i.proxyHostnames.join(", ")} > ${i.serverHostname}:${i.serverPort}${i.tls ? " (TLS)" : ""}`).join("\n")}`);
log();

// Create proxy server
const proxyServer = (config.tls ? tls : net).createServer({
    key: fs.existsSync(config.key) ? fs.readFileSync(config.key) : undefined,
    cert: fs.existsSync(config.cert) ? fs.readFileSync(config.cert) : undefined,
    ...config.additionalProxyServerOptions
});

// Proxy server on connection
proxyServer.on("connection", proxyConnection => {
    // Get IP
    const ip = proxyConnection.remoteAddress.split("::ffff:")[1] || proxyConnection.remoteAddress;

    // Whitelist
    if (whitelist && !ipMatch(ip, whitelist)) {
        log(`Unwhitelisted IP ${ip} attempted to connect!`);
        return proxyConnection.destroy();
    }
    // Blacklist
    if (blacklist && ipMatch(ip, blacklist)) {
        log(`Blacklisted IP ${ip} attempted to connect!`);
        return proxyConnection.destroy();
    }

    logAdditional(`New connection from ${ip}`);

    let serverConnection;

    proxyConnection.on("data", data => {
        const [rawHeaders, rawData = ""] = data.toString().split("\r\n\r\n");
        const splitHeaders = rawHeaders.split("\r\n");

        const [requestLine, method, uri, version] = splitHeaders[0].match(requestLineRegex) || [];
        if (requestLine) {            
            const headers = getHeaders(splitHeaders); // Get headers
            
            const realIp = config.realIpHeader ? headers[config.realIpHeader] : null; // Get real IP (if using some sort of proxy like Cloudflare)
            
            // Make sure using supported version
            if (config.supportedVersions && !config.supportedVersions.includes(version)) {
                logAdditional(`IP ${ip}${realIp ? ` (${realIp})` : ""} using unsupported version ${version}`);
                return proxyConnection.destroy();
            }

            // Get hostname
            const [hostname] = getHeader(headers, "Host")?.match(hostnameRegex) || [];

            const foundServer = findServer(hostname);

            // Find server
            if (!foundServer) {
                logAdditional(`IP ${ip}${realIp ? ` (${realIp})` : ""} tried to reach unknown hostname ${hostname}`);
                return proxyConnection.destroy();
            }

            const foundServerOptions = objectDefaults(foundServer, config.defaultServerOptions || { }); // Get default server options + found server options

            // Server requires authorization
            if (foundServerOptions.authorization) {
                if (!foundServerOptions.authorizationPassword) {
                    // No authorization password set, destroy
                    log(`IP ${ip}${realIp ? ` (${realIp})` : ""} tried to reach ${hostname} which requires authorization, but no authorization password was set`);
                    return proxyConnection.destroy();
                }
                
                const cookies = parseCookies(getHeader(headers, "Cookie") || "");

                if (cookies[config.authorizationCookie] != foundServerOptions.authorizationPassword) {
                    // Incorrect or no authorization cookie
                    logAdditional(`IP ${ip}${realIp ? ` (${realIp})` : ""} tried to reach ${hostname} which requires authorization`);
                    proxyConnection.write(`HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nContent-Length: ${authorizationHtml.length}\r\n\r\n${authorizationHtml}`);
                    return;
                };

                // Remove cookie before sending to server
                delete cookies[config.authorizationCookie];
                setHeader(headers, "Cookie", stringifyCookies(cookies));
            }

            // Modify headers
            Object.entries(foundServerOptions.modifiedHeaders || { }).forEach(([header, value]) => {
                if (value === true) return;

                if (!value) {
                    setHeader(headers, header);
                } else
                    setHeader(headers, header, formatString(value, {
                        proxyHostname: hostname,
                        serverHostname: foundServerOptions.serverHostname,
                        serverPort: foundServerOptions.serverPort
                    }));
            });

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
                serverConnection = (foundServerOptions.useTls ? tls : net).connect({
                    host: foundServerOptions.serverHostname,
                    port: foundServerOptions.serverPort,
                    rejectUnauthorized: false,
                    ...foundServerOptions.additionalServerOptions
                });

                serverConnection.on("data", i => { if (!proxyConnection.ended) proxyConnection.write(i) });
                serverConnection.on("close", i => { if (!proxyConnection.ended) proxyConnection.end() });
                serverConnection.on("error", err => console.error("Server error:", err)); // This is usually fine
            }

            if (serverConnection && !serverConnection.ended) serverConnection.write(reconstructedData);
        } else
            if (serverConnection && !serverConnection.ended) serverConnection.write(data);
    });

    proxyConnection.on("close", () => { if (serverConnection && !serverConnection.ended) serverConnection.end() });
    proxyConnection.on("error", err => console.error("Proxy error:", err)); // This is usually fine
});

// Listen
proxyServer.listen(config.port, config.hostname, () => log(`Listening at :${config.port}`))

function readJson(filePath) {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

function log(...msg) {
    if (config.logging) console.log(...msg);
}

function logAdditional(...msg) {
    if (config.additionalLogging) console.log(...msg);
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
