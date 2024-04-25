const net = require("net");
const tls = require("tls");
const fs = require("fs");

// Config
let config = readJson("config.json");
fs.watchFile("config.json", () => config = readJson("config.json"));

// Servers
let servers = readJson("servers.json");
fs.watchFile("servers.json", () => servers = readJson("servers.json"));

// Whitelist
let whitelist;
if (config.whitelist) {
    whitelist = readJson(config.whitelist);
    fs.watchFile(config.whitelist, () => whitelist = readJson(config.whitelist));
}

// Blacklist
let blacklist;
if (config.blacklist) {
    blacklist = readJson(config.blacklist);
    fs.watchFile(config.blacklist, () => blacklist = readJson(config.blacklist));
}

// Regex
const requestLineRegex = /^(.*) (.*) (HTTP\/\d*\.\d*)$/im; // GET /hello/world HTTP/1.1
const statusLineRegex = /^(HTTP\/\d*\.\d*) (\d*) (.*)$/im; // HTTP/1.1 200 OK
const headersRegex = /^(.*?): ?(.*)$/m; // Host: localhost
const hostnameRegex = /[^:]*/; // localhost (excludes port)

// Create proxy server
const proxyServer = (config.tls ? tls : net).createServer({
    key: fs.existsSync(config.key) ? fs.readFileSync(config.key) : undefined,
    cert: fs.existsSync(config.cert) ? fs.readFileSync(config.cert) : undefined,
    ...config.additionalServerOptions
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

    log(`New connection from ${ip}`);

    let serverConnection;

    proxyConnection.on("data", data => {
        const splitData = data.toString().split("\r\n");
        
        const [requestLine, method, uri, version] = splitData[0].match(requestLineRegex) || [];
        const headers = getHeaders(splitData);

        const [hostname] = (headers["Host"] || headers["host"])?.match(hostnameRegex) || [];
        
        // TODO: EVERYTHING!!!!
        console.log(requestLine, method, uri, version, hostname);
    });
});

// Listen
proxyServer.listen(config.port, config.hostname, () => console.log(`Listening at :${config.port}`))

function readJson(filePath) {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}

function log(...msg) {
    if (config.logging) console.log(...msg);
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

function getHeaders(splitData) {
    return Object.fromEntries(splitData.map(i => {
        const match = i.match(headersRegex);
        if (!match) return null;
        return [match[1], match[2]];
    }).filter(i => i));
}