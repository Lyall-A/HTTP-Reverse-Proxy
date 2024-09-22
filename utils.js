const fs = require("fs");

const headersRegex = /^(.*?): ?(.*)$/m; // Host: localhost

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
    if (typeof obj !== "object" || obj === null) return def;

    return (function checkEntries(object = obj, defaultObj = def) {
        Object.entries(defaultObj).forEach(([key, value]) => {
            if (object[key] === undefined) object[key] = value;
            else if (typeof value === "object" && value !== null && typeof object[key] === "object" && object[key] !== null) checkEntries(object[key], value);
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
    const listener = fs.watchFile(file, () => {
        if (!json) return callback(fs.readFileSync(file, "utf-8"));
        try {
            callback(readJson(file));
        } catch (err) {
            console.error(`Failed to read '${file}', error:`, err);
        }
    });

    return () => fs.unwatchFile(file, listener);
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

module.exports = {
    readJson,
    log,
    logProxyError,
    logServerError,
    ipMatch,
    getHeaders,
    findServer,
    formatString,
    parseCookies,
    stringifyCookies,
    objectDefaults,
    watch,
    getHeader,
    setHeader,
    timestamp
};