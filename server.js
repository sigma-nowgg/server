import express from "express";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// Config
const SECRET = process.env.SECRET || "DEV_SECRET_CHANGE_ME";
const PORT = process.env.PORT || 3000;
const TOKEN_EXPIRES = "48h"; // thời hạn token

// Rate limiting (giảm tấn công brute force)
app.use(rateLimit({ windowMs: 60 * 1000, max: 60 }));

// Endpoint: cấp token sau khi vượt link
app.post("/issue", (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "Thiếu code" });

  // TODO: ở đây bạn có thể validate code thật sự với link4m
  // demo: chấp nhận mọi code != rỗng
  const payload = { role: "user", sub: "user-" + Math.random().toString(36).slice(2, 8) };

  const token = jwt.sign(payload, SECRET, { expiresIn: TOKEN_EXPIRES });

  res.cookie("session_token", token, {
    httpOnly: true,
    secure: true, // Bật khi deploy HTTPS
    sameSite: "lax",
    maxAge: 48 * 3600 * 1000
  });

  return res.json({ ok: true });
});

// Endpoint: dashboard/app bảo vệ
app.get("/app", (req, res) => {
  const token = req.cookies.session_token;
  if (!token) return res.status(401).send("Unauthorized");

  try {
    const payload = jwt.verify(token, SECRET);
    return res.send(`<html><body><h1>Xin chào ${payload.sub}</h1><p>Đây là nội dung bảo vệ.</p></body></html>`);
  } catch (e) {
    return res.status(401).send("Token không hợp lệ hoặc đã hết hạn");
  }
});

// Logout
app.post("/logout", (req, res) => {
  res.clearCookie("session_token");
  return res.json({ ok: true });
});

app.listen(PORT, () => console.log(`✅ Server chạy tại http://localhost:${PORT}`));
