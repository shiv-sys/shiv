require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: false }
});

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

if (!process.env.DATABASE_URL) {
  console.warn("DATABASE_URL is not set. The app cannot persist users/messages until PostgreSQL is configured.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

async function db(query, params = []) {
  const result = await pool.query(query, params);
  return result.rows;
}

async function initDb() {
  if (!process.env.DATABASE_URL) return;
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(40) NOT NULL UNIQUE,
      display_name VARCHAR(80) NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 4000),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_messages_pair_time
      ON messages(sender_id, receiver_id, created_at);

    CREATE INDEX IF NOT EXISTS idx_messages_receiver
      ON messages(receiver_id, created_at);
  `);
}

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

function makeToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, displayName: user.display_name },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  try {
    const token = req.cookies.chat_token;
    if (!token) return res.status(401).json({ error: "Not authenticated" });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Session expired" });
  }
}

function cleanUser(row) {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name
  };
}

app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const displayName = String(req.body.displayName || "").trim();
    const password = String(req.body.password || "");

    if (!/^[a-z0-9_]{3,40}$/.test(username))
      return res.status(400).json({ error: "Username must be 3-40 characters: letters, numbers or underscore." });
    if (displayName.length < 2 || displayName.length > 80)
      return res.status(400).json({ error: "Display name must be 2-80 characters." });
    if (password.length < 6)
      return res.status(400).json({ error: "Password must be at least 6 characters." });

    const existing = await db("SELECT id FROM users WHERE username=$1", [username]);
    if (existing.length) return res.status(409).json({ error: "Username already exists." });

    const hash = await bcrypt.hash(password, 12);
    const rows = await db(
      "INSERT INTO users(username, display_name, password_hash) VALUES($1,$2,$3) RETURNING id,username,display_name",
      [username, displayName, hash]
    );

    const token = makeToken(rows[0]);
    res.cookie("chat_token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ user: cleanUser(rows[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Registration failed." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const rows = await db("SELECT * FROM users WHERE username=$1", [username]);

    if (!rows.length || !(await bcrypt.compare(password, rows[0].password_hash)))
      return res.status(401).json({ error: "Invalid username or password." });

    const token = makeToken(rows[0]);
    res.cookie("chat_token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ user: cleanUser(rows[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Login failed." });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("chat_token");
  res.json({ ok: true });
});

app.get("/api/me", auth, async (req, res) => {
  const rows = await db("SELECT id,username,display_name FROM users WHERE id=$1", [req.user.id]);
  if (!rows.length) return res.status(401).json({ error: "User not found." });
  res.json({ user: cleanUser(rows[0]) });
});

app.get("/api/users", auth, async (req, res) => {
  const q = String(req.query.q || "").trim().toLowerCase();
  const rows = q
    ? await db(
        `SELECT id,username,display_name FROM users
         WHERE id<>$1 AND (username ILIKE $2 OR display_name ILIKE $2)
         ORDER BY display_name LIMIT 50`,
        [req.user.id, `%${q}%`]
      )
    : await db(
        `SELECT id,username,display_name FROM users WHERE id<>$1
         ORDER BY display_name LIMIT 50`,
        [req.user.id]
      );
  res.json({ users: rows.map(cleanUser) });
});

app.get("/api/conversations", auth, async (req, res) => {
  const rows = await db(`
    SELECT
      u.id, u.username, u.display_name,
      m.body AS last_message, m.created_at AS last_message_at
    FROM users u
    LEFT JOIN LATERAL (
      SELECT body, created_at
      FROM messages
      WHERE (sender_id=$1 AND receiver_id=u.id)
         OR (sender_id=u.id AND receiver_id=$1)
      ORDER BY created_at DESC LIMIT 1
    ) m ON true
    WHERE u.id<>$1
    ORDER BY m.created_at DESC NULLS LAST, u.display_name
    LIMIT 100
  `, [req.user.id]);

  res.json({
    conversations: rows.map(r => ({
      ...cleanUser(r),
      lastMessage: r.last_message || "",
      lastMessageAt: r.last_message_at
    }))
  });
});

app.get("/api/messages/:userId", auth, async (req, res) => {
  const otherId = Number(req.params.userId);
  if (!Number.isInteger(otherId)) return res.status(400).json({ error: "Invalid user." });

  const rows = await db(`
    SELECT m.id, m.sender_id, m.receiver_id, m.body, m.created_at,
           u.display_name AS sender_name
    FROM messages m
    JOIN users u ON u.id=m.sender_id
    WHERE (m.sender_id=$1 AND m.receiver_id=$2)
       OR (m.sender_id=$2 AND m.receiver_id=$1)
    ORDER BY m.created_at ASC
    LIMIT 500
  `, [req.user.id, otherId]);

  res.json({ messages: rows });
});

function socketUser(socket) {
  return socket.user;
}

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token || socket.request.headers.cookie?.match(/chat_token=([^;]+)/)?.[1];
    if (!token) return next(new Error("Unauthorized"));
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error("Unauthorized"));
  }
});

const online = new Map();

io.on("connection", socket => {
  const user = socketUser(socket);
  online.set(user.id, (online.get(user.id) || 0) + 1);

  io.emit("presence", { userId: user.id, online: true });

  socket.on("send_message", async (payload, callback) => {
    try {
      const receiverId = Number(payload.receiverId);
      const body = String(payload.body || "").trim();

      if (!Number.isInteger(receiverId) || receiverId === user.id)
        throw new Error("Invalid recipient.");
      if (!body || body.length > 4000)
        throw new Error("Message must be 1-4000 characters.");

      const receiver = await db("SELECT id FROM users WHERE id=$1", [receiverId]);
      if (!receiver.length) throw new Error("Recipient not found.");

      const rows = await db(
        `INSERT INTO messages(sender_id,receiver_id,body)
         VALUES($1,$2,$3)
         RETURNING id,sender_id,receiver_id,body,created_at`,
        [user.id, receiverId, body]
      );

      const message = rows[0];
      io.to(`user:${receiverId}`).emit("new_message", message);
      socket.emit("new_message", message);
      if (callback) callback({ ok: true, message });
    } catch (e) {
      if (callback) callback({ ok: false, error: e.message || "Could not send message." });
    }
  });

  socket.join(`user:${user.id}`);

  socket.on("typing", ({ receiverId, typing }) => {
    if (Number.isInteger(Number(receiverId))) {
      io.to(`user:${Number(receiverId)}`).emit("typing", {
        userId: user.id,
        typing: !!typing
      });
    }
  });

  socket.on("disconnect", () => {
    const count = (online.get(user.id) || 1) - 1;
    if (count <= 0) {
      online.delete(user.id);
      io.emit("presence", { userId: user.id, online: false });
    } else {
      online.set(user.id, count);
    }
  });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDb()
  .then(() => {
    server.listen(PORT, () => console.log(`Chat app running on port ${PORT}`));
  })
  .catch(err => {
    console.error("Database initialization failed:", err);
    process.exit(1);
  });
