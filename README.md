# basic-to-sharepoint-auth-http-proxy

HTTP proxy server that can access resources which use SharePoint HTTP authentication with credentials supplied by Basic
HTTP authentication.

This proxy was primarily built to access Microsoft OneDrive for Business over WebDAV with WebDAV clients that can only
do HTTP Basic authentication. If you want to access OneDrive personal over WebDAV with Basic authentication, have a look
at [basic-to-passport-auth-http-proxy](https://github.com/skleeschulte/basic-to-passport-auth-http-proxy).

## Running the proxy

The proxy server is written in Node.js. You can either run the Docker container or run it directly with node.

Options are set with environment variables:

- `PROXY_TARGET` *required* The proxy server target URL, e.g.: `https://example-my.sharepoint.com/`
- `PROXY_PORT` *optional* The port where the proxy server listens for client requests. Defaults to `3000`.
- `SHAREPOINT_AUTH_URL` *optional* Separate URL to use for SharePoint authentication. Defaults to `PROXY_TARGET`.
- `AUTH_TYPE` *optional* The type of SharePoint authentication to use. Must be one of: `online`, `fba`, `tmg`, `adfs`.
  Defaults to `online`.
- `DEBUG` *optional* See below.

The following additional environment variables are only relevant if `AUTH_TYPE` is set to `adfs` and ignored otherwise:

- `ADFS_DOMAIN` *optional*
- `ADFS_RELYING_PARTY` *required*
- `ADFS_URL` *required*
- `ADFS_COOKIE` *optional*

The proxy uses the [node-sp-auth](https://www.npmjs.com/package/node-sp-auth) module for SharePoint authentication. The
`AUTH_TYPE` options correspond to the following authentication options of node-sp-auth:

- `online`: "SharePoint Online: SAML based with user credentials" ([Wiki article](https://github.com/s-KaiNet/node-sp-auth/wiki/SharePoint%20Online%20user%20credentials%20authentication))
- `fba`: "SharePoint on premise (2013, 2016): Form-based authentication (FBA)" ([Wiki article](https://github.com/s-KaiNet/node-sp-auth/wiki/SharePoint%20on-premise%20FBA%20authentication))
- `tmg`: "SharePoint on premise (2013, 2016): Forefront TMG (reverse proxy) authentication"
- `adfs`: "ADFS user credentials" ([Wiki article](https://github.com/s-KaiNet/node-sp-auth/wiki/ADFS%20user%20credentials%20authentication))

If `SHAREPOINT_AUTH_URL` is set, it is passed to node-sp-auth's
[`getAuth(...)`](https://github.com/s-KaiNet/node-sp-auth#getauthurl-credentialoptions) function instead of
`PROXY_TARGET`.

### Running with Docker

- Find the latest Docker image tag at Docker Hub:  
  https://hub.docker.com/r/skleeschulte/basic-to-sharepoint-auth-http-proxy
- Pull the image:  
  `docker pull skleeschulte/basic-to-sharepoint-auth-http-proxy:TAG`  
  (Replace TAG with an actual tag from the Docker Hub.)
- Run the image:  
  `docker run --name sharepoint-proxy -d -p 3000:3000 -e PROXY_TARGET=https://example-my.sharepoint.net/ --restart always skleeschulte/basic-to-sharepoint-auth-http-proxy:TAG`  
  (Again, replace TAG with the one you just pulled.)
- Check if it started successfully:  
  `docker logs sharepoint-proxy`  
  (The output should be something like `proxy:info Proxy server listening: { address: '::', family: 'IPv6', port: 3000 }`.)

Or use your favourite Docker UI for these steps.

### Running with Node.js

Make sure you have a suitable Node.js installed (the proxy server was developed with Node.js version 10 (version
10.16.0, to be precise).

- Get a copy of this repository (choose a version tag on the top left, then choose "Clone or download" in the same
  line).
- Extract the files and change to the directory.
- Install the dependencies:  
  `npm ci --only=production`
- Set the environment variables (see above).  
  On Linux: `export PROXY_TARGET=https://example-my.sharepoint.net/`  
  On Windows: `set PROXY_TARGET=https://example-my.sharepoint.net/`
- Run the server:  
  `node lib/server.js`

## Usage

In your client software, configure hostname and port of the proxy server. If you can choose an authentication scheme,
choose HTTP Basic auth. You should be prompted for username and password.

### Accessing OneDrive for Business

When accessing OneDrive for Business over WebDAV, the `PROXY_TARGET` should not contain a path. If your SharePoint URL
is e.g. `https://example-my.sharepoint.com/personal/account_name/Documents`, then set `PROXY_TARGET` to
`https://example-my.sharepoint.com/` and configure the WebDAV client to access `/personal/account_name/Documents`,
e.g.:  
`http://localhost:3000/personal/account_name/Documents`  
Depending on the client you might have to omit the `http://` part or append a trailing slash.

## Security

Currently, the proxy only supports HTTP connections on the incoming side. In consequence, user credentials will be
transferred from the client to the proxy in clear-text for the majority of HTTP requests. The proxy should only be used
on trusted networks, e.g. localhost.

The proxy relies on [node-sp-auth](https://www.npmjs.com/package/node-sp-auth) for managing authentication data. It
should be safe to have multiple users access their resources over the same server instance in parallel.

## Logging / Debugging

The server uses the [debug](https://www.npmjs.com/package/debug) library for logging with the namespace `proxy` and the
following log levels:

- `proxy:error` *(logs to STDERR)* Log errors.
- `proxy:info` *(logs to STDOUT)* Log listening address and port.
- `proxy:debug` *(logs to STDOUT)* Log detailed information about request handling.
- `proxy:trace` *(logs to STDOUT)* Log the raw HTTP messages. This prints sensible authorization information to STDOUT.

By default, only `proxy:error` and `proxy:info` are enabled. This can be changed with the `DEBUG` environment variable.
To log everything from the proxy server use `DEBUG=proxy:*`, to log everything including messages from third party
libraries that also use the debug library use `DEBUG=*`.
