const http = require('http');
const https = require('https');
const Agent = require('agentkeepalive');
const spAuth = require('node-sp-auth');
const AuthHeader = require('./AuthHeader');
const log = require('./log');

const PROXY_TARGET = (process.env.PROXY_TARGET || '').trim();
const DEFAULT_PROXY_PORT = 3000;
const SHAREPOINT_AUTH_URL = (process.env.SHAREPOINT_AUTH_URL || PROXY_TARGET).trim();
const AUTH_TYPE = (process.env.AUTH_TYPE || 'online').trim().toLowerCase();
const ADFS_DOMAIN = (process.env.ADFS_DOMAIN || '').trim();
const ADFS_RELYING_PARTY = (process.env.ADFS_RELYING_PARTY || '').trim();
const ADFS_URL = (process.env.ADFS_URL || '').trim();
const ADFS_COOKIE = (process.env.ADFS_COOKIE || '').trim();

let proxyTarget;
try {
    proxyTarget = new URL(PROXY_TARGET);
} catch (error) {
    log.e('%O', error);
    throw new Error(`PROXY_TARGET environment variable is missing or not a valid URL: ${PROXY_TARGET}`);
}
if (['http:', 'https:'].indexOf(proxyTarget.protocol) === -1) {
    throw new Error("PROXY_TARGET environment variable must be an URL with protocol 'http:' or 'https:'."
        + ` Actual value: ${proxyTarget.protocol}`);
}

let proxyPort;
try {
    proxyPort = parseInt((process.env.PROXY_PORT || DEFAULT_PROXY_PORT), 10);
} catch (error) {
    log.e('%O', error);
    throw new Error(`PROXY_PORT environment variable has an invalid value: ${process.env.PROXY_PORT}`);
}
const PROXY_PORT = proxyPort;

try {
    // eslint-disable-next-line no-new
    new URL(SHAREPOINT_AUTH_URL);
} catch (error) {
    log.e('%O', error);
    throw new Error(`SHAREPOINT_AUTH_URL environment variable is not a valid URL: ${SHAREPOINT_AUTH_URL}`);
}

if (['online', 'fba', 'tmg', 'adfs'].indexOf(AUTH_TYPE) === -1) {
    throw new Error('AUTH_TYPE environment variable must be one of online, fba, tmg or adfs.'
        + ` Actual value: ${AUTH_TYPE}`);
}

if (AUTH_TYPE === 'adfs') {
    if (!ADFS_RELYING_PARTY) {
        throw new Error('AUTH_TYPE is adfs, but ADFS_RELYING_PARTY environment variable is empty.');
    }

    if (!ADFS_URL) {
        throw new Error('AUTH_TYPE is adfs, but ADFS_URL environment variable is empty.');
    }
}

/**
 * Save script start time to shorten timestamps in debug messages.
 * @type {number}
 */
const scriptStart = Date.now();

/**
 * Use keep-alive agent.
 */
const agent = proxyTarget.protocol === 'https:' ? new Agent.HttpsAgent() : new Agent();
const httpRequest = proxyTarget.protocol === 'https:' ? https.request : http.request;

/**
 * Make HTTP(s) request.
 * @param options
 * @returns {http.ClientRequest | ClientRequest}
 */
function request(options) {
    const defaults = { agent };
    return httpRequest(Object.assign(defaults, options));
}

/**
 * Mask credentials in HTTP header values.
 * @param name
 * @param value
 * @returns {*}
 */
function maskHeaderValue(name, value) {
    name = name.toLowerCase();

    if (name === 'authorization') {
        value = value.replace(/^(Basic\s+)(.*)$/i, '$1[masked-auth-param]');
    }

    if (name === 'cookie' || name === 'set-cookie') {
        value = value.replace(/((?:^|;| )(?:FedAuth=))([^;,]+)/ig, '$1[masked-cookie-value]');
        value = value.replace(/((?:^|;| )(?:rtFa=))([^;,]+)/ig, '$1[masked-cookie-value]');
    }

    return value;
}

/**
 * Prettify header names.
 * @param name
 * @returns {*}
 */
function prettifyHeaderName(name) {
    return name.replace(/(?:^|-|[0-9])[a-z]/g, c => c.toUpperCase());
}

/**
 * Log client requests.
 * @param rId
 * @param req
 */
function logClientRequest(rId, req) {
    log.d(`[${rId}] Client request: ${req.method} ${req.url}`);

    if (log.t.enabled) {
        log.t(`[${rId}]    ${req.method} ${req.url} HTTP/${req.httpVersion}`);
        for (let i = 0; i < req.rawHeaders.length - 1; i += 2) {
            const maskedValue = maskHeaderValue(req.rawHeaders[i], req.rawHeaders[i + 1]);
            log.t(`[${rId}]    ${req.rawHeaders[i]}: ${maskedValue}`);
        }
    }
}

/**
 * Log proxy requests.
 * @param rId
 * @param proxyReq
 */
function logProxyRequest(rId, proxyReq) {
    log.d(`[${rId}] Proxy request: ${proxyReq.method} ${proxyReq.path}`);

    if (log.t.enabled) {
        log.t(`[${rId}]    ${proxyReq.method} ${proxyReq.path} HTTP/1.1 (HTTP version is hardcoded)`);
        proxyReq.getHeaderNames().forEach((name) => {
            const maskedValue = maskHeaderValue(name, proxyReq.getHeader(name));
            log.t(`[${rId}]    ${prettifyHeaderName(name)}: ${maskedValue}`);
        });
    }
}

/**
 * Log proxy responses.
 * @param rId
 * @param proxyRes
 */
function logProxyResponse(rId, proxyRes) {
    log.d(`[${rId}] Server response: ${proxyRes.statusCode} ${proxyRes.statusMessage}`);

    if (log.t.enabled) {
        log.t(`[${rId}]    HTTP/${proxyRes.httpVersion} ${proxyRes.statusCode} ${proxyRes.statusMessage}`);
        for (let i = 0; i < proxyRes.rawHeaders.length - 1; i += 2) {
            const maskedValue = maskHeaderValue(proxyRes.rawHeaders[i], proxyRes.rawHeaders[i + 1]);
            log.t(`[${rId}]    ${proxyRes.rawHeaders[i]}: ${maskedValue}`);
        }
    }
}

/**
 * Log client responses.
 * @param rId
 * @param res
 */
function logClientResponse(rId, res) {
    log.d(`[${rId}] Proxy response: ${res.statusCode} ${res.statusMessage}`);

    if (log.t.enabled) {
        log.t(`[${rId}]    HTTP/1.1 ${res.statusCode} ${res.statusMessage} (HTTP version is hardcoded)`);
        res.getHeaderNames().forEach((name) => {
            const maskedValue = maskHeaderValue(name, res.getHeader(name));
            log.t(`[${rId}]    ${prettifyHeaderName(name)}: ${maskedValue}`);
        });
    }
}

/**
 * Send HTTP error response.
 * @param rId
 * @param res
 * @param httpStatusCode
 * @param message
 */
function sendError(rId, res, httpStatusCode, message) {
    if (httpStatusCode === 401) {
        res.setHeader('WWW-Authenticate', `Basic realm="${proxyTarget.toString()}"`);
    }
    res.setHeader('Content-Type', 'text/plain');
    res.writeHead(httpStatusCode);

    const body = message || (httpStatusCode === 401 ? 'Authentication required.' : '');
    res.end(body);

    logClientResponse(rId, res);
}

/**
 * Get SharePoint authentication data for current username and password.
 * @param rId
 * @param res
 * @param username
 * @param password
 * @returns {Promise<IAuthResponse>}
 */
async function getSharePointAuth(rId, res, username, password) {
    const options = {
        username,
        password,
        online: AUTH_TYPE === 'online',
        fba: AUTH_TYPE === 'fba',
        tmg: AUTH_TYPE === 'tmg',
        ...(AUTH_TYPE === 'adfs' ? {
            domain: ADFS_DOMAIN || undefined,
            relyingParty: ADFS_RELYING_PARTY,
            adfsUrl: ADFS_URL,
            adfsCookie: ADFS_COOKIE || undefined,
        } : {}),
    };

    log.d(`[${rId}] Trying to get SharePoint authentication with user credentials from Basic HTTP auth.`);

    if (log.t.enabled) {
        const maskedOptions = Object.assign({}, options);
        if (maskedOptions.password) maskedOptions.password = '[masked-password]';
        log.t(`[${rId}] SharePoint authentication options:\n%O`, maskedOptions);
    }

    let authRes;
    try {
        authRes = await spAuth.getAuth(SHAREPOINT_AUTH_URL, options);

        log.d(`[${rId}] SharePoint authentication was successful.`);

        if (log.t.enabled) {
            const maskedAuthRes = Object.assign({}, authRes);
            if (maskedAuthRes.headers && maskedAuthRes.headers.Cookie) {
                maskedAuthRes.headers = Object.assign({}, authRes.headers);
                maskedAuthRes.headers.Cookie = maskHeaderValue('cookie', maskedAuthRes.headers.Cookie);
            }
            log.t(`[${rId}] SharePoint authentication response: %o`, maskedAuthRes);
        }
    } catch (error) {
        // getAuth does not throw a specific error for failed authentication, but all errors from node-sp-auth will be
        // instances of Error without error.code. This might still capture errors which are not a failed authentication,
        // but for now it's the best we can do.
        if (error.name === 'Error' && !error.code) {
            log.d(`[${rId}] Sharepoint user authentication failed: %O`, error);
            sendError(rId, res, 401, error.message);
        } else {
            log.e(`[${rId}] An error occurred during user authentication: %O`, error);
            sendError(rId, res, 500, error.message);
        }

        authRes = null;
    }

    return authRes;
}

/**
 * Test if given ports are semantically equal respecting the protocols default port.
 * @param protocol
 * @param port1
 * @param port2
 * @returns {boolean}
 */
function portsEqual(protocol, port1, port2) {
    const defaultPort = protocol === 'http:' ? '80' : '443';
    return (port1 || defaultPort) === (port2 || defaultPort);
}

/**
 * Trim one trailing slash from given path, except if the path has only one char.
 * @param path
 * @returns {*}
 */
function trimTrailingSlash(path) {
    if (path.length === 1) return path;
    if (path[path.length - 1] === '/') return path.slice(0, -1);
    return path;
}

/**
 * Check if the given url object points to a resource at the proxied SharePoint server.
 * @param url
 * @returns {boolean}
 */
function isProxyResource(url) {
    if (url.protocol !== proxyTarget.protocol) return false;
    if (url.hostname !== proxyTarget.hostname) return false;
    if (!portsEqual(url.port, proxyTarget.port)) return false;
    if (proxyTarget.pathname === '/') return true;

    const trimmedProxyPath = trimTrailingSlash(proxyTarget.pathname);
    return (url.pathname.length === trimmedProxyPath.length || url.pathname[trimmedProxyPath.length] === '/')
        && url.pathname.substr(0, trimmedProxyPath.length) === trimmedProxyPath;
}

/**
 * Join two URL paths.
 * @param path1
 * @param path2
 * @returns {string|*}
 */
function joinPaths(path1, path2) {
    if (path1[path1.length - 1] === '/' && path2[0] === '/') {
        return path1.slice(0, -1) + path2;
    }

    if (path1[path1.length - 1] !== '/' && path2[0] !== '/') {
        return path1 + '/' + path2;
    }

    return path1 + path2;
}

/**
 * Rebase an actual path on the SharePoint server to an URL as the proxy client expects it. Does not check if the path
 * actually belongs the the SharePoint server, use isProxyResource(...) first!
 * @param serverPath
 * @returns {string | string}
 */
function rebaseServerPath(serverPath) {
    const trimmedProxyPath = trimTrailingSlash(proxyTarget.pathname);
    return serverPath.substr(trimmedProxyPath.length) || '/';
}

/**
 * User same letter case as in given rawHeaders or use prettifyHeaderName(...) function. HTTP header names should be
 * case insensitive, but unfortunately some clients / servers do not stick to this.
 * @param headers
 * @param rawHeaders
 */
function fixHeaderCase(headers, rawHeaders) {
    const originalHeaderNames = {};
    for (let i = 0; i < rawHeaders.length; i += 2) {
        originalHeaderNames[rawHeaders[i].toLowerCase()] = rawHeaders[i];
    }

    Object.keys(headers).forEach((name) => {
        const prettyName = originalHeaderNames[name] || prettifyHeaderName(name);
        if (prettyName !== name) {
            headers[prettyName] = headers[name];
            delete headers[name];
        }
    });
}

/**
 * Create HTTP server with request listener.
 * @type {Server}
 */
const server = http.createServer(async (req, res) => {
    // Generate a request id for debug messages - timestamp + random nr from 1000 to 9999 should do for this purpose
    const rId = '' + (Date.now() - scriptStart) + '/' + (Math.floor(Math.random() * 8999) + 1000);

    logClientRequest(rId, req);

    const authHeader = new AuthHeader(req.headers.authorization);

    if (!authHeader.isBasic) {
        log.d(`[${rId}] No Authorization HTTP header found in client request, sending 401 response.`);
        sendError(rId, res, 401);
        return;
    }

    const { username, password } = authHeader.credentials;
    const authRes = await getSharePointAuth(rId, res, username, password);
    if (!authRes) return;

    const proxyReqHeaders = Object.assign({}, req.headers);

    delete proxyReqHeaders.host;
    delete proxyReqHeaders.authorization;
    delete proxyReqHeaders.connection;

    if (!proxyReqHeaders.cookie) {
        proxyReqHeaders.cookie = authRes.headers.Cookie;
    } else {
        proxyReqHeaders.cookie = `${authRes.headers.Cookie}; ${proxyReqHeaders.cookie}`;
    }

    if (proxyReqHeaders.referer) {
        try {
            const url = new URL(proxyReqHeaders.referer);
            url.protocol = proxyTarget.protocol;
            url.port = '';
            url.host = proxyTarget.host;
            url.pathname = joinPaths(proxyTarget.pathname, url.pathname);
            const newReferer = url.toString();
            log.d(`[${rId}] Rewriting Referer header: ${proxyReqHeaders.referer} -> ${newReferer}`);
            proxyReqHeaders.referer = newReferer;
        } catch (error) {
            log.d(`[${rId}] Ignoring invalid Referer header URL in client request: ${proxyReqHeaders.referer}`);
        }
    }

    fixHeaderCase(proxyReqHeaders, req.rawHeaders);

    const proxyReq = request({
        host: proxyTarget.hostname,
        port: proxyTarget.port || undefined,
        method: req.method,
        path: joinPaths(proxyTarget.pathname, req.url),
        headers: proxyReqHeaders,
    });

    logProxyRequest(rId, proxyReq);

    proxyReq.once('response', (proxyRes) => {
        logProxyResponse(rId, proxyRes);

        const resHeaders = Object.assign({}, proxyRes.headers);
        delete resHeaders.connection;

        if (resHeaders.location) {
            try {
                const url = new URL(resHeaders.location);
                if (isProxyResource(url)) {
                    url.protocol = 'http:';
                    url.port = '';
                    url.host = req.headers.host;
                    url.pathname = rebaseServerPath(url.pathname);
                    const newLocation = url.toString();
                    log.d(`[${rId}] Rewriting Location header: ${resHeaders.location} -> ${newLocation}`);
                    resHeaders.location = newLocation;
                }
            } catch (error) {
                log.d(`[${rId}] Ignoring invalid Location header URL in proxy response: ${resHeaders.location}`);
            }
        }

        fixHeaderCase(resHeaders, proxyRes.rawHeaders);

        res.writeHead(proxyRes.statusCode, proxyRes.statusMessage, resHeaders);

        logClientResponse(rId, res);

        if (!res.finished) {
            log.t(`[${rId}] Piping proxy response to client response.`);
            proxyRes.pipe(res);
        } else if (!proxyRes.complete) {
            proxyReq.abort();
        }
    });

    proxyReq.on('error', (error) => {
        /* if (error.code === 'ECONNRESET') {
            // TODO: Retry request? How often?
        } */
        log.d(`[${rId}] Proxy request errored, ending client response. Error:\n%O`, error);
        res.end();
    });

    req.on('aborted', () => {
        log.d(`[${rId}] Client request aborted, aborting proxy request.`);
        proxyReq.abort();
    });

    req.on('error', (error) => {
        log.d(`[${rId}] Client request errored, aborting proxy request. Error:\n%O`, error);
        proxyReq.abort();
    });

    res.on('error', (error) => {
        log.d(`[${rId}] Client response errored, aborting proxy request. Error:\n%O`, error);
        proxyReq.abort();
    });

    if (!req.aborted) {
        log.t(`[${rId}] Piping client request to proxy request.`);
        req.pipe(proxyReq);
    }
});

server.on('listening', () => {
    log('Proxy server listening: %o', server.address());
});

server.listen(PROXY_PORT);
