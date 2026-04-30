import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import pkg from "pg";
import dotenv from "dotenv";

const { Pool } = pkg;
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));

// ── DB ────────────────────────────────────────────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

pool.connect((err, client, release) => {
  if (err) {
  console.error("❌ DB connection failed:", err.message);
}
  console.log("✅ Database connected");
  release();
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS records (
      id SERIAL PRIMARY KEY,
      entity TEXT NOT NULL,
      data JSONB NOT NULL DEFAULT '{}',
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_records_entity_user ON records (entity, user_id);
  `);
  console.log("✅ Tables ready");
}
initDB();

// ── Helpers ───────────────────────────────────────────────────────────────────
const isValidEntity = (name: string) => /^[a-zA-Z0-9_]{1,64}$/.test(name);

const sanitizeData = (obj: any): Record<string, any> => {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return {};
  const cleaned: Record<string, any> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined && v !== null && String(k).trim() !== "") {
      cleaned[k.trim()] = typeof v === "string" ? v.trim() : v;
    }
  }
  return cleaned;
};

// ── Auth Middleware ───────────────────────────────────────────────────────────
const authMiddleware = (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded: any = jwt.verify(token, process.env.JWT_SECRET!);
    req.user = decoded;
    next();
  } catch (err: any) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expired. Please login again." });
    }
    return res.status(401).json({ error: "Invalid token" });
  }
};

// ── Auth Routes ───────────────────────────────────────────────────────────────
app.post("/auth/signup", async (req, res) => {
  const { email, password } = req.body ?? {};

  if (!email || typeof email !== "string" || !email.includes("@"))
    return res.status(400).json({ error: "Valid email is required" });
  if (!password || typeof password !== "string" || password.length < 6)
    return res.status(400).json({ error: "Password must be at least 6 characters" });

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
      [email.toLowerCase().trim(), hash]
    );
    const token = jwt.sign(
      { id: result.rows[0].id, email: result.rows[0].email },
      process.env.JWT_SECRET!,
      { expiresIn: "7d" }
    );
    res.status(201).json({ token });
  } catch (err: any) {
    if (err.code === "23505")
      return res.status(409).json({ error: "An account with this email already exists" });
    console.error("Signup error:", err.message);
    res.status(500).json({ error: "Signup failed. Please try again." });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password)
    return res.status(400).json({ error: "Email and password are required" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email.toLowerCase().trim(),
    ]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: "Invalid email or password" });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET!,
      { expiresIn: "7d" }
    );
    res.json({ token });
  } catch (err: any) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Login failed. Please try again." });
  }
});

// ── CRUD ──────────────────────────────────────────────────────────────────────
app.post("/api/:entity", authMiddleware, async (req: any, res) => {
  const { entity } = req.params;
  if (!isValidEntity(entity)) return res.status(400).json({ error: "Invalid entity name" });

  try {
    const result = await pool.query(
      "INSERT INTO records (entity, data, user_id) VALUES ($1, $2, $3) RETURNING *",
      [entity, JSON.stringify(sanitizeData(req.body)), req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err: any) {
    console.error("Create error:", err.message);
    res.status(500).json({ error: "Failed to create record" });
  }
});

app.get("/api/:entity", authMiddleware, async (req: any, res) => {
  const { entity } = req.params;
  if (!isValidEntity(entity)) return res.status(400).json({ error: "Invalid entity name" });

  const limit = Math.min(parseInt(String(req.query.limit ?? "100")), 500);
  const offset = parseInt(String(req.query.offset ?? "0"));
  if (isNaN(limit) || isNaN(offset))
    return res.status(400).json({ error: "Invalid pagination parameters" });

  try {
    const result = await pool.query(
      "SELECT * FROM records WHERE entity=$1 AND user_id=$2 ORDER BY id DESC LIMIT $3 OFFSET $4",
      [entity, req.user.id, limit, offset]
    );
    res.json(result.rows);
  } catch (err: any) {
    console.error("Read error:", err.message);
    res.status(500).json({ error: "Failed to fetch records" });
  }
});

app.put("/api/:entity/:id", authMiddleware, async (req: any, res) => {
  const { entity, id } = req.params;
  if (!isValidEntity(entity)) return res.status(400).json({ error: "Invalid entity name" });
  const numId = parseInt(id);
  if (isNaN(numId)) return res.status(400).json({ error: "Invalid record ID" });

  try {
    const result = await pool.query(
      "UPDATE records SET data=$1 WHERE id=$2 AND entity=$3 AND user_id=$4 RETURNING *",
      [JSON.stringify(sanitizeData(req.body)), numId, entity, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: "Record not found or access denied" });
    res.json(result.rows[0]);
  } catch (err: any) {
    console.error("Update error:", err.message);
    res.status(500).json({ error: "Failed to update record" });
  }
});

app.delete("/api/:entity/:id", authMiddleware, async (req: any, res) => {
  const { entity, id } = req.params;
  if (!isValidEntity(entity)) return res.status(400).json({ error: "Invalid entity name" });
  const numId = parseInt(id);
  if (isNaN(numId)) return res.status(400).json({ error: "Invalid record ID" });

  try {
    const result = await pool.query(
      "DELETE FROM records WHERE id=$1 AND entity=$2 AND user_id=$3 RETURNING id",
      [numId, entity, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: "Record not found or access denied" });
    res.json({ success: true, deleted: numId });
  } catch (err: any) {
    console.error("Delete error:", err.message);
    res.status(500).json({ error: "Failed to delete record" });
  }
});

// ── CSV Bulk Import ───────────────────────────────────────────────────────────
app.post("/api/:entity/import", authMiddleware, async (req: any, res) => {
  const { entity } = req.params;
  if (!isValidEntity(entity)) return res.status(400).json({ error: "Invalid entity name" });

  const { records } = req.body ?? {};
  if (!Array.isArray(records) || records.length === 0)
    return res.status(400).json({ error: "No records provided" });

  const safeRecords = records
    .slice(0, 1000)
    .map(sanitizeData)
    .filter((r) => Object.keys(r).length > 0);

  if (safeRecords.length === 0)
    return res.status(400).json({ error: "All records were empty after mapping" });

  try {
    const values: any[] = [];
    const placeholders = safeRecords.map((record, i) => {
      const base = i * 3;
      values.push(entity, JSON.stringify(record), req.user.id);
      return `($${base + 1}, $${base + 2}, $${base + 3})`;
    });
    await pool.query(
      `INSERT INTO records (entity, data, user_id) VALUES ${placeholders.join(", ")}`,
      values
    );
    res.json({ success: true, inserted: safeRecords.length, skipped: records.length - safeRecords.length });
  } catch (err: any) {
    console.error("Import error:", err.message);
    res.status(500).json({ error: "Bulk import failed. Please try again." });
  }
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err: any, req: any, res: any, next: any) => {
  if (err.type === "entity.parse.failed")
    return res.status(400).json({ error: "Invalid JSON in request body" });
  console.error("Unhandled error:", err.message);
  res.status(500).json({ error: "Internal server error" });
});

// ── Health check ──────────────────────────────────────────────────────────────
app.get("/", async (_, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", db: "connected" });
  } catch {
    res.status(500).json({ status: "error", db: "disconnected" });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));