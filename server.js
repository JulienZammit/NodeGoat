"use strict";

const express = require("express");
const favicon = require("serve-favicon");
const bodyParser = require("body-parser");
const session = require("express-session");
const csrf = require("csurf");
const consolidate = require("consolidate"); // Templating library adapter for Express
const swig = require("swig");
const helmet = require("helmet");
const MongoClient = require("mongodb").MongoClient; // Driver for connecting to MongoDB
const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const marked = require("marked");
const sanitizeHtml = require("sanitize-html");
const nosniff = require("dont-sniff-mimetype");
const app = express(); // Web framework to handle routing requests
const routes = require("./app/routes");
const { port, db, cookieSecret, httpsKeyPath, httpsCertPath } = require("./config/config"); // Application config properties

// Fix for A6 - Sensitive Data Exposure.
// Load TLS material for an HTTPS connection when provided. Private keys and
// certificates are NEVER committed to the repository: supply them at deploy
// time via the HTTPS_KEY_PATH / HTTPS_CERT_PATH environment variables.
let httpsOptions = null;
if (httpsKeyPath && httpsCertPath && fs.existsSync(httpsKeyPath) && fs.existsSync(httpsCertPath)) {
    httpsOptions = {
        key: fs.readFileSync(path.resolve(httpsKeyPath)),
        cert: fs.readFileSync(path.resolve(httpsCertPath))
    };
}
const useHttps = Boolean(httpsOptions);

MongoClient.connect(db, { useNewUrlParser: true, useUnifiedTopology: true }, (err, client) => {
    if (err) {
        console.log("Error: DB: connect");
        console.log(err);
        process.exit(1);
    }
    console.log(`Connected to the database`);

    // mongodb v3+: connect yields a client; obtain the db from the connection string
    const db = client.db();

    // Fix for A5 - Security Misconfiguration: security response headers via helmet.
    // Remove default x-powered-by response header
    app.disable("x-powered-by");

    // Prevent opening page in frame or iframe to protect from clickjacking
    app.use(helmet.frameguard());

    // Allow communication only on HTTPS
    app.use(helmet.hsts());

    // Allow loading resources only from white-listed domains (defence-in-depth against XSS)
    app.use(helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            objectSrc: ["'none'"]
        }
    }));

    // Forces browser to only use the Content-Type set in the response header instead of sniffing or guessing it
    app.use(nosniff());

    app.use(favicon(__dirname + "/app/assets/favicon.ico"));

    // Express middleware to populate "req.body" so we can access POST variables
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({
        // Mandatory in Express v4
        extended: false
    }));

    // Enable session management using express middleware.
    // Fix for A2/A3/A5 - secure session cookie configuration.
    app.use(session({
        // Use a generic cookie name to avoid leaking the framework fingerprint
        name: "sessionId",
        secret: cookieSecret,
        saveUninitialized: false,
        resave: false,
        cookie: {
            httpOnly: true,            // not readable from client-side JavaScript (XSS hardening)
            secure: useHttps,          // only transmit the cookie over HTTPS when TLS is active
            sameSite: "lax",           // mitigates CSRF
            path: "/",
            maxAge: 60 * 60 * 1000     // expire the session after 1 hour
        }
    }));

    // Fix for A8 - CSRF: enable Express csrf protection
    app.use(csrf());
    // Make csrf token available in templates
    app.use((req, res, next) => {
        res.locals.csrftoken = req.csrfToken();
        next();
    });

    // Register templating engine
    app.engine(".html", consolidate.swig);
    app.set("view engine", "html");
    app.set("views", `${__dirname}/app/views`);
    // Fix for A5 - Security MisConfig
    app.use(express.static(`${__dirname}/app/assets`));

    // Fix for A9/A3 - marked v4 removed the built-in sanitizer, so render the
    // markdown to HTML and then sanitize the result before exposing it to views.
    app.locals.marked = (md) => sanitizeHtml(marked.parse(md || ""));

    // Application routes
    routes(app, db);

    // Template system setup
    // Fix for A3 - XSS: enable auto escaping of template variables
    swig.setDefaults({
        autoescape: true
    });

    if (useHttps) {
        // Fix for A6 - Sensitive Data Exposure: use secure HTTPS protocol
        https.createServer(httpsOptions, app).listen(port, () => {
            console.log(`Express https server listening on port ${port}`);
        });
    } else {
        console.log("WARNING: TLS material not found - starting plain HTTP. " +
            "Set HTTPS_KEY_PATH and HTTPS_CERT_PATH to enable HTTPS.");
        http.createServer(app).listen(port, () => {
            console.log(`Express http server listening on port ${port}`);
        });
    }

});
