import express from "express";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();

const app = express();

// ⚡️ Config
const SECRET = process.env.SECRET || "DEV_SECRET_CHANGE_ME";
const PORT = process.env.PORT || 3000;
const TOKEN_EXPIRES = "48h";

// ⚡️ Domain frontend (GitHub Pages của bạn)
const FRONTEND = "https://sigma-nowgg.github.io";

// ✅ Cho phép frontend gọi API kèm cookie
app.use(cors({
  origin: FRONTEND,
  credentials: true
}));

app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(rateLimit({ windowMs: 60 * 1000, max: 60 }));

// ---------------- ROUTES ----------------

// Cấp token khi user quay lại từ link4m
app.post("/issue", (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "Thiếu code" });

  // TODO: validate code với link4m nếu muốn
  // Demo: chấp nhận mọi code != rỗng
  const payload = {
    role: "user",
    sub: "user-" + Math.random().toString(36).slice(2, 8)
  };

  const token = jwt.sign(payload, SECRET, { expiresIn: TOKEN_EXPIRES });

  res.cookie("session_token", token, {
    httpOnly: true,
    secure: true, // ⚠️ khi chạy HTTPS, Render tự có SSL
    sameSite: "lax",
    maxAge: 48 * 3600 * 1000
  });

  return res.json({ ok: true });
});

// Dashboard/app (chỉ mở được nếu cookie hợp lệ)
app.get("/app", (req, res) => {
  const token = req.cookies.session_token;
  if (!token) return res.status(401).send("Unauthorized");

  try {
    const payload = jwt.verify(token, SECRET);
    return res.send(`
      <html>
        <body style="background:#0f172a;color:#fff;font-family:sans-serif;text-align:center;padding:40px">
          <h1>✅ Welcome ${payload.sub}</h1>
          <p>Bạn đã đăng nhập thành công!</p>
        </body>
      </html>
    `);
  } catch (e) {
    return res.status(401).send("Token không hợp lệ hoặc đã hết hạn");
  }
});

// Logout → xóa cookie
app.post("/logout", (req, res) => {
  res.clearCookie("session_token");
  return res.json({ ok: true });
});

// ---------------- START ----------------
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
