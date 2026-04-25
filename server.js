const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const EMAIL_DIR = path.join(ROOT, "email_previews");
const DB_PATH = path.join(DATA_DIR, "pranaveda.db");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(EMAIL_DIR, { recursive: true });

const db = new sqlite3.Database(DB_PATH);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) {
        reject(err);
        return;
      }
      resolve({ id: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(rows);
    });
  });
}

async function initDb() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS assessments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      physical_score INTEGER NOT NULL,
      mental_score INTEGER NOT NULL,
      emotional_score INTEGER NOT NULL,
      energy_score INTEGER NOT NULL,
      overall_score INTEGER NOT NULL,
      summary TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT,
      service TEXT NOT NULL,
      preferred_date TEXT,
      slot TEXT NOT NULL,
      practitioner TEXT NOT NULL,
      notes TEXT,
      status TEXT NOT NULL,
      confirmation_code TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS email_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      booking_id INTEGER,
      recipient TEXT NOT NULL,
      subject TEXT NOT NULL,
      preview_path TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (booking_id) REFERENCES bookings(id)
    )
  `);
}

function buildTransporter() {
  if (process.env.SMTP_SERVICE && process.env.SMTP_USER && process.env.SMTP_PASS) {
    return nodemailer.createTransport({
      service: process.env.SMTP_SERVICE,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }

  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }

  return nodemailer.createTransport({
    jsonTransport: true
  });
}

const transporter = buildTransporter();

async function sendBookingEmail({ booking, userName }) {
  const html = `
    <div style="font-family:Arial,sans-serif;padding:24px;color:#2b180d">
      <h2 style="margin-bottom:8px;">PranaVeda Booking Confirmation</h2>
      <p>Hello ${userName},</p>
      <p>Your wellness appointment has been confirmed.</p>
      <ul>
        <li><strong>Booking ID:</strong> ${booking.confirmation_code}</li>
        <li><strong>Service:</strong> ${booking.service}</li>
        <li><strong>Date:</strong> ${booking.preferred_date || "Next available date"}</li>
        <li><strong>Slot:</strong> ${booking.slot}</li>
        <li><strong>Practitioner:</strong> ${booking.practitioner}</li>
        <li><strong>Status:</strong> ${booking.status}</li>
      </ul>
      <p>Please arrive 15 minutes early for your in-person assessment.</p>
      <p>Warm regards,<br>PranaVeda Wellness Team</p>
    </div>
  `;

  const info = await transporter.sendMail({
    from: process.env.EMAIL_FROM || "hello@pranaveda.in",
    to: booking.email,
    subject: `PranaVeda Booking Confirmed • ${booking.confirmation_code}`,
    html
  });

  let previewPath = null;
  if (!process.env.SMTP_HOST) {
    previewPath = path.join(EMAIL_DIR, `${booking.confirmation_code}.json`);
    fs.writeFileSync(previewPath, JSON.stringify(info.message, null, 2));
  }

  await run(
    `INSERT INTO email_logs (booking_id, recipient, subject, preview_path) VALUES (?, ?, ?, ?)`,
    [booking.id, booking.email, `PranaVeda Booking Confirmed • ${booking.confirmation_code}`, previewPath]
  );

  return previewPath;
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    res.status(401).json({ error: "Please sign in first." });
    return;
  }
  next();
}

function buildDashboardPayload(user, assessments, bookings) {
  const latest = assessments[0];
  const latestMetrics = latest
    ? {
        overall: latest.overall_score,
        physical: latest.physical_score,
        mental: latest.mental_score,
        emotional: latest.emotional_score,
        energy: latest.energy_score,
        summary: latest.summary,
        updatedAt: latest.created_at
      }
    : {
        overall: 0,
        physical: 0,
        mental: 0,
        emotional: 0,
        energy: 0,
        summary: "No assessment recorded yet.",
        updatedAt: null
      };

  return {
    user: {
      id: user.id,
      firstName: user.first_name,
      lastName: user.last_name,
      email: user.email,
      memberSince: user.created_at
    },
    latestMetrics,
    assessments: assessments.map((item) => ({
      id: item.id,
      overall: item.overall_score,
      physical: item.physical_score,
      mental: item.mental_score,
      emotional: item.emotional_score,
      energy: item.energy_score,
      summary: item.summary,
      createdAt: item.created_at
    })),
    bookings: bookings.map((item) => ({
      id: item.id,
      service: item.service,
      date: item.preferred_date,
      slot: item.slot,
      practitioner: item.practitioner,
      status: item.status,
      confirmationCode: item.confirmation_code,
      createdAt: item.created_at
    }))
  };
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "pranaveda-local-demo-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

app.use("/email_previews", express.static(EMAIL_DIR));
app.use(express.static(ROOT));

app.get("/", (req, res) => {
  res.sendFile(path.join(ROOT, "index.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(ROOT, "dashboard.html"));
});

app.get("/api/health", async (req, res) => {
  res.json({ ok: true, port: PORT });
});

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    if (!firstName || !lastName || !email || !password) {
      res.status(400).json({ error: "All sign-up fields are required." });
      return;
    }

    const existing = await get(`SELECT id FROM users WHERE email = ?`, [email.toLowerCase()]);
    if (existing) {
      res.status(409).json({ error: "An account with this email already exists." });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await run(
      `INSERT INTO users (first_name, last_name, email, password_hash) VALUES (?, ?, ?, ?)`,
      [firstName, lastName, email.toLowerCase(), passwordHash]
    );

    await run(
      `INSERT INTO assessments (user_id, physical_score, mental_score, emotional_score, energy_score, overall_score, summary)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        result.id,
        76,
        81,
        84,
        73,
        79,
        "Welcome assessment baseline created for your new PranaVeda profile."
      ]
    );

    req.session.userId = result.id;
    const user = await get(`SELECT id, first_name, last_name, email, created_at FROM users WHERE id = ?`, [result.id]);
    res.json({
      ok: true,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Unable to create account right now." });
  }
});

app.post("/api/auth/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(400).json({ error: "Email and password are required." });
      return;
    }

    const user = await get(`SELECT * FROM users WHERE email = ?`, [email.toLowerCase()]);
    if (!user) {
      res.status(401).json({ error: "Invalid email or password." });
      return;
    }

    const matches = await bcrypt.compare(password, user.password_hash);
    if (!matches) {
      res.status(401).json({ error: "Invalid email or password." });
      return;
    }

    req.session.userId = user.id;
    res.json({
      ok: true,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Unable to sign in right now." });
  }
});

app.post("/api/auth/signout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get("/api/auth/me", async (req, res) => {
  if (!req.session.userId) {
    res.json({ user: null });
    return;
  }

  const user = await get(`SELECT id, first_name, last_name, email, created_at FROM users WHERE id = ?`, [req.session.userId]);
  res.json({
    user: user
      ? {
          id: user.id,
          firstName: user.first_name,
          lastName: user.last_name,
          email: user.email,
          createdAt: user.created_at
        }
      : null
  });
});

app.get("/api/dashboard", requireAuth, async (req, res) => {
  try {
    const user = await get(`SELECT id, first_name, last_name, email, created_at FROM users WHERE id = ?`, [req.session.userId]);
    const assessments = await all(
      `SELECT * FROM assessments WHERE user_id = ? ORDER BY datetime(created_at) DESC`,
      [req.session.userId]
    );
    const bookings = await all(
      `SELECT * FROM bookings WHERE user_id = ? ORDER BY datetime(created_at) DESC`,
      [req.session.userId]
    );
    res.json(buildDashboardPayload(user, assessments, bookings));
  } catch (error) {
    res.status(500).json({ error: "Unable to load dashboard." });
  }
});

app.post("/api/assessments", requireAuth, async (req, res) => {
  try {
    const { physical, mental, emotional, energy, overall, summary } = req.body;
    if ([physical, mental, emotional, energy, overall].some((value) => Number.isNaN(Number(value)))) {
      res.status(400).json({ error: "Assessment scores are required." });
      return;
    }

    const result = await run(
      `INSERT INTO assessments (user_id, physical_score, mental_score, emotional_score, energy_score, overall_score, summary)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [req.session.userId, physical, mental, emotional, energy, overall, summary || null]
    );

    const assessment = await get(`SELECT * FROM assessments WHERE id = ?`, [result.id]);
    res.json({ ok: true, assessment });
  } catch (error) {
    res.status(500).json({ error: "Unable to save assessment." });
  }
});

app.post("/api/bookings", async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      phone,
      service,
      preferredDate,
      notes,
      slot,
      practitioner
    } = req.body;

    if (!firstName || !lastName || !email || !service || !slot || !practitioner) {
      res.status(400).json({ error: "Please complete all required booking fields." });
      return;
    }

    const confirmationCode = `PV-${crypto.randomInt(1000, 9999)}`;
    const status = "Confirmed";

    const result = await run(
      `INSERT INTO bookings
       (user_id, first_name, last_name, email, phone, service, preferred_date, slot, practitioner, notes, status, confirmation_code)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.session.userId || null,
        firstName,
        lastName,
        email.toLowerCase(),
        phone || "",
        service,
        preferredDate || "",
        slot,
        practitioner,
        notes || "",
        status,
        confirmationCode
      ]
    );

    const booking = await get(`SELECT * FROM bookings WHERE id = ?`, [result.id]);
    const previewPath = await sendBookingEmail({
      booking,
      userName: `${booking.first_name} ${booking.last_name}`.trim()
    });

    res.json({
      ok: true,
      booking: {
        id: booking.id,
        confirmationCode: booking.confirmation_code,
        service: booking.service,
        preferredDate: booking.preferred_date,
        slot: booking.slot,
        practitioner: booking.practitioner,
        status: booking.status,
        previewPath: previewPath ? `/email_previews/${path.basename(previewPath)}` : null
      }
    });
  } catch (error) {
    res.status(500).json({ error: "Unable to create booking right now." });
  }
});

app.get("/api/bookings", requireAuth, async (req, res) => {
  try {
    const bookings = await all(
      `SELECT id, service, preferred_date, slot, practitioner, status, confirmation_code, created_at
       FROM bookings WHERE user_id = ? ORDER BY datetime(created_at) DESC`,
      [req.session.userId]
    );
    res.json({ bookings });
  } catch (error) {
    res.status(500).json({ error: "Unable to load bookings." });
  }
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(ROOT, "index.html"));
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`PranaVeda app running on http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Failed to initialize app", error);
    process.exit(1);
  });
