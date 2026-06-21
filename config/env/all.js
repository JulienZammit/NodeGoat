// default app configuration
const port = process.env.PORT || 4000;
let db = process.env.MONGODB_URI || "mongodb://localhost:27017/nodegoat";

module.exports = {
    port,
    db,
    // Secrets are sourced from the environment. The fallbacks below are only
    // non-functional placeholders for first-run local development.
    cookieSecret: process.env.COOKIE_SECRET || "change_me_in_env_cookie_secret",
    cryptoKey: process.env.CRYPTO_KEY || "change_me_in_env_crypto_key",
    cryptoAlgo: "aes256",
    hostName: "localhost",
    // Optional TLS material for HTTPS (never committed to the repo).
    httpsKeyPath: process.env.HTTPS_KEY_PATH || "",
    httpsCertPath: process.env.HTTPS_CERT_PATH || "",
    environmentalScripts: []
};

