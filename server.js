require("dotenv").config();

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const bcrypt = require("bcryptjs");
const express = require("express");
const nodemailer = require("nodemailer");

const app = express();

const ROOT = __dirname;
const IS_VERCEL = Boolean(process.env.VERCEL);
const RUNTIME_BASE = IS_VERCEL ? path.join("/tmp", "pranaveda-runtime") : ROOT;
const DATA_DIR = path.join(RUNTIME_BASE, "data");
const EMAIL_DIR = path.join(RUNTIME_BASE, "email_previews");
const STORE_PATH = path.join(DATA_DIR, "store.json");
const INDEX_PATH = path.join(ROOT, "index.html");
const DASHBOARD_PATH = path.join(ROOT, "dashboard.html");
const COOKIE_NAME = "pranaveda_session";
const SESSION_SECRET = process.env.SESSION_SECRET || "pranaveda-dev-secret";
const PORT = Number(process.env.PORT || 3010);

app.disable("x-powered-by");

const allowedLocalOrigins = new Set([
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:3000",
  "http://127.0.0.1:3000"
]);

// CORS middleware must run before body parsers
app.use((req, res, next) => {
  const origin = req.headers.origin;
  // Allow localhost/127.0.0.1 on any port for local development
  const isLocalhost = origin && (origin.includes("localhost") || origin.includes("127.0.0.1"));
  
  if (isLocalhost) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS");
    res.setHeader("Access-Control-Max-Age", "86400");
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  return next();
});

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Log all requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function ensureRuntime() {
  ensureDir(DATA_DIR);
  ensureDir(EMAIL_DIR);
  if (!fs.existsSync(STORE_PATH)) {
    fs.writeFileSync(STORE_PATH, JSON.stringify(defaultStore(), null, 2));
  }
}

function defaultStore() {
  return {
    counters: {
      users: 0,
      assessments: 0,
      bookings: 0,
      emailLogs: 0
    },
    users: [],
    assessments: [],
    bookings: [],
    emailLogs: []
  };
}

function loadStore() {
  ensureRuntime();
  try {
    return JSON.parse(fs.readFileSync(STORE_PATH, "utf8"));
  } catch (error) {
    const store = defaultStore();
    fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
    return store;
  }
}

function saveStore(store) {
  ensureRuntime();
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
}

function nextId(store, key) {
  store.counters[key] = (store.counters[key] || 0) + 1;
  return store.counters[key];
}

function nowIso() {
  return new Date().toISOString();
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(value));
}

function safeUser(user) {
  return {
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    createdAt: user.createdAt
  };
}

function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${value}`];
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  if (options.httpOnly !== false) parts.push("HttpOnly");
  if (options.path) parts.push(`Path=${options.path}`);
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.secure) parts.push("Secure");
  if (options.expires) parts.push(`Expires=${options.expires.toUTCString()}`);
  return parts.join("; ");
}

function parseCookies(req) {
  const raw = req.headers.cookie || "";
  return raw.split(";").reduce((acc, pair) => {
    const [key, ...rest] = pair.trim().split("=");
    if (!key) return acc;
    acc[key] = decodeURIComponent(rest.join("=") || "");
    return acc;
  }, {});
}

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function verifyToken(token) {
  if (!token || !token.includes(".")) {
    return null;
  }

  const [body, sig] = token.split(".");
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  if (sig !== expected) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!payload.exp || Date.now() > payload.exp) {
      return null;
    }
    return payload;
  } catch (error) {
    return null;
  }
}

function setAuthCookie(res, userId) {
  const payload = {
    userId,
    exp: Date.now() + 1000 * 60 * 60 * 24 * 14
  };
  res.setHeader("Set-Cookie", serializeCookie(COOKIE_NAME, signToken(payload), {
    maxAge: 60 * 60 * 24 * 14,
    path: "/",
    sameSite: "Lax",
    secure: IS_VERCEL
  }));
}

function clearAuthCookie(res) {
  res.setHeader("Set-Cookie", serializeCookie(COOKIE_NAME, "", {
    maxAge: 0,
    path: "/",
    sameSite: "Lax",
    secure: IS_VERCEL,
    expires: new Date(0)
  }));
}

function getCurrentUser(req) {
  const cookies = parseCookies(req);
  const payload = verifyToken(cookies[COOKIE_NAME]);
  if (!payload) {
    return null;
  }
  const store = loadStore();
  return store.users.find((user) => user.id === payload.userId) || null;
}

function requireUser(req, res) {
  const user = getCurrentUser(req);
  if (!user) {
    res.status(401).json({ error: "Please sign in to continue." });
    return null;
  }
  return user;
}

function buildLatestMetrics(assessments) {
  if (!assessments.length) {
    return {
      overall: 84,
      physical: 78,
      mental: 82,
      emotional: 91,
      energy: 76,
      summary: "Your dashboard will update here as you complete assessments and attend sessions.",
      updatedAt: null
    };
  }

  const latest = [...assessments].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0];
  return {
    overall: latest.overall,
    physical: latest.physical,
    mental: latest.mental,
    emotional: latest.emotional,
    energy: latest.energy,
    summary: latest.summary,
    updatedAt: latest.createdAt
  };
}

function formatDashboard(store, user) {
  const assessments = store.assessments
    .filter((item) => item.userId === user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const bookings = store.bookings
    .filter((item) => item.userId === user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  return {
    user: {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      memberSince: user.createdAt
    },
    latestMetrics: buildLatestMetrics(assessments),
    assessments,
    bookings
  };
}

function randomCode(prefix) {
  return `${prefix}-${Math.floor(1000 + Math.random() * 9000)}`;
}

function pickSubject(service) {
  return service === "Organizational Wellness Index"
    ? "PranaVeda Organizational Consultation Confirmed"
    : "PranaVeda Booking Confirmed";
}

function createTransport() {
  if (process.env.SMTP_HOST) {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: Number(process.env.SMTP_PORT || 587) === 465,
      auth: process.env.SMTP_USER && process.env.SMTP_PASS ? {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      } : undefined
    });
  }

  if (process.env.SMTP_SERVICE && process.env.SMTP_USER && process.env.SMTP_PASS) {
    return nodemailer.createTransport({
      service: process.env.SMTP_SERVICE,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }

  return null;
}

async function sendConfirmationEmail({ booking, firstName, email }) {
  ensureRuntime();
  const subject = `${pickSubject(booking.service)} • ${booking.confirmationCode}`;
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.6;color:#2b180d">
      <h2 style="margin-bottom:8px;">PranaVeda Session Confirmed</h2>
      <p>Hello ${firstName},</p>
      <p>Your booking has been confirmed for <strong>${booking.service}</strong>.</p>
      <p>
        <strong>Reference:</strong> ${booking.confirmationCode}<br>
        <strong>Date:</strong> ${booking.preferredDate || "Next available date"}<br>
        <strong>Slot:</strong> ${booking.slot}<br>
        <strong>Practitioner:</strong> ${booking.practitioner}
      </p>
      <p>Please arrive 15 minutes early for your in-person wellness assessment.</p>
    </div>
  `;

  const transport = createTransport();
  if (transport) {
    await transport.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER || "hello@pranaveda.local",
      to: email,
      subject,
      html
    });
    return { subject, previewPath: null };
  }

  const previewPath = path.join(EMAIL_DIR, `${booking.confirmationCode}.json`);
  fs.writeFileSync(previewPath, JSON.stringify({
    to: email,
    subject,
    html,
    createdAt: nowIso()
  }, null, 2));

  return {
    subject,
    previewPath: `/email_previews/${booking.confirmationCode}.json`
  };
}

function addWelcomeAssessment(store, userId) {
  const assessment = {
    id: nextId(store, "assessments"),
    userId,
    physical: 76,
    mental: 80,
    emotional: 84,
    energy: 74,
    overall: 79,
    summary: "Welcome assessment baseline created for your new PranaVeda profile.",
    createdAt: nowIso()
  };
  store.assessments.push(assessment);
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, runtime: IS_VERCEL ? "vercel" : "local" });
});

app.get("/api/auth/me", (req, res) => {
  const user = getCurrentUser(req);
  res.json({ user: user ? safeUser(user) : null });
});

app.post("/api/auth/signup", async (req, res) => {
  const firstName = String(req.body.firstName || "").trim();
  const lastName = String(req.body.lastName || "").trim();
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ error: "Please complete all sign-up fields." });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "Please enter a valid email address." });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters long." });
  }

  const store = loadStore();
  const existing = store.users.find((user) => user.email === email);
  if (existing) {
    return res.status(409).json({ error: "An account already exists for this email address." });
  }

  const user = {
    id: nextId(store, "users"),
    firstName,
    lastName,
    email,
    passwordHash: await bcrypt.hash(password, 10),
    createdAt: nowIso()
  };

  store.users.push(user);
  addWelcomeAssessment(store, user.id);
  saveStore(store);
  setAuthCookie(res, user.id);

  return res.status(201).json({ ok: true, user: safeUser(user) });
});

app.post("/api/auth/signin", async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");

  if (!email || !password) {
    return res.status(400).json({ error: "Please enter both your email address and password." });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "Please enter a valid email address." });
  }

  const store = loadStore();
  const user = store.users.find((item) => item.email === email);
  if (!user) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  const matches = await bcrypt.compare(password, user.passwordHash);
  if (!matches) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  setAuthCookie(res, user.id);
  return res.json({ ok: true, user: safeUser(user) });
});

app.post("/api/auth/signout", (req, res) => {
  clearAuthCookie(res);
  res.json({ ok: true });
});

app.get("/api/dashboard", (req, res) => {
  const user = requireUser(req, res);
  if (!user) return;

  const store = loadStore();
  res.json(formatDashboard(store, user));
});

app.post("/api/assessments", (req, res) => {
  const user = requireUser(req, res);
  if (!user) return;

  const physical = Number(req.body.physical);
  const mental = Number(req.body.mental);
  const emotional = Number(req.body.emotional);
  const energy = Number(req.body.energy);
  const overall = Number(req.body.overall);
  const summary = String(req.body.summary || "").trim();

  const values = [physical, mental, emotional, energy, overall];
  if (values.some((value) => Number.isNaN(value) || value < 0 || value > 100)) {
    return res.status(400).json({ error: "Assessment scores must be between 0 and 100." });
  }

  const store = loadStore();
  const assessment = {
    id: nextId(store, "assessments"),
    userId: user.id,
    physical,
    mental,
    emotional,
    energy,
    overall,
    summary: summary || "Assessment saved.",
    createdAt: nowIso()
  };
  store.assessments.push(assessment);
  saveStore(store);

  res.status(201).json({ ok: true, assessment });
});

app.get("/api/bookings", (req, res) => {
  const user = requireUser(req, res);
  if (!user) return;

  const store = loadStore();
  const bookings = store.bookings
    .filter((item) => item.userId === user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ bookings });
});

app.post("/api/bookings", async (req, res) => {
  const firstName = String(req.body.firstName || "").trim();
  const lastName = String(req.body.lastName || "").trim();
  const email = normalizeEmail(req.body.email);
  const phone = String(req.body.phone || "").trim();
  const service = String(req.body.service || "").trim();
  const preferredDate = String(req.body.preferredDate || "").trim();
  const notes = String(req.body.notes || "").trim();
  const slot = String(req.body.slot || "").trim();
  const practitioner = String(req.body.practitioner || "").trim();

  if (!firstName || !lastName || !email) {
    return res.status(400).json({ error: "Please complete the required booking fields." });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "Please enter a valid email address." });
  }
  if (!service || !slot || !practitioner) {
    return res.status(400).json({ error: "Please choose an available slot before booking." });
  }

  const authUser = getCurrentUser(req);
  const store = loadStore();
  const booking = {
    id: nextId(store, "bookings"),
    userId: authUser ? authUser.id : null,
    firstName,
    lastName,
    email,
    phone,
    service,
    preferredDate,
    slot,
    practitioner,
    notes,
    status: "Confirmed",
    confirmationCode: randomCode("PV"),
    createdAt: nowIso()
  };

  const emailResult = await sendConfirmationEmail({
    booking,
    firstName,
    email
  });

  store.bookings.push(booking);
  store.emailLogs.push({
    id: nextId(store, "emailLogs"),
    bookingId: booking.id,
    recipient: email,
    subject: emailResult.subject,
    previewPath: emailResult.previewPath,
    createdAt: nowIso()
  });
  saveStore(store);

  res.status(201).json({
    ok: true,
    booking: {
      id: booking.id,
      confirmationCode: booking.confirmationCode,
      service: booking.service,
      preferredDate: booking.preferredDate,
      slot: booking.slot,
      practitioner: booking.practitioner,
      status: booking.status,
      previewPath: emailResult.previewPath
    }
  });
});

app.get("/email_previews/:file", (req, res) => {
  const filePath = path.join(EMAIL_DIR, path.basename(req.params.file));
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "Preview not found." });
  }
  res.sendFile(filePath);
});

app.get("/dashboard", (req, res) => {
  res.redirect(302, "/dashboard.html");
});

app.get("/dashboard.html", (req, res) => {
  res.sendFile(DASHBOARD_PATH);
});

app.get("/", (req, res) => {
  res.sendFile(INDEX_PATH);
});

app.get("/:path", (req, res, next) => {
  if (req.params.path.startsWith("api")) {
    return next();
  }
  const filePath = path.join(ROOT, path.basename(req.params.path));
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    return res.sendFile(filePath);
  }
  return res.sendFile(INDEX_PATH);
});

const ready = Promise.resolve().then(() => {
  ensureRuntime();
});

if (require.main === module) {
  ready.then(() => {
    app.listen(PORT, () => {
      console.log(`PranaVeda server running on http://localhost:${PORT}`);
    });
  }).catch((error) => {
    console.error("Failed to start server", error);
    process.exit(1);
  });
}

module.exports = { app, ready };
