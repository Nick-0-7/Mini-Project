
require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const bodyParser = require("body-parser");
const cors = require("cors");
const nodemailer = require("nodemailer");

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

const PORT = process.env.PORT || 4000;

// MySQL connection pool
let pool;
async function initDB() {
  pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10
  });
}
initDB().catch(err => {
  console.error("DB connection failed:", err);
  process.exit(1);
});

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Generate 6-digit OTP
function genOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// Send email OTP
async function sendEmailOtp(toEmail, otp) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: toEmail,
    subject: "Your OTP Code",
    text: `Your OTP is ${otp}. It is valid for 5 minutes.`
  };
  await transporter.sendMail(mailOptions);
}

// Send OTP Endpoint
app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });

    const otp = genOtp();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await pool.query(
      "INSERT INTO otps (email, otp, expires_at, used) VALUES (?,?,?,false)",
      [email, otp, expiresAt]
    );

    await sendEmailOtp(email, otp);
    res.json({ success: true, message: "OTP sent to email" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Verify OTP + register
app.post("/verify-otp", async (req, res) => {
  try {
    const { name, email, otp, profession } = req.body;
    if (!name || !email || !otp || !profession)
      return res.status(400).json({ error: "Missing fields" });

    const [rows] = await pool.query(
      "SELECT * FROM otps WHERE email=? AND otp=? AND used=false AND expires_at>NOW() ORDER BY id DESC LIMIT 1",
      [email, otp]
    );

    if (!rows.length) return res.status(400).json({ error: "Invalid OTP" });

    await pool.query("UPDATE otps SET used=true WHERE id=?", [rows[0].id]);

    await pool.query(
      "INSERT INTO users (name, email, profession) VALUES (?,?,?)",
      [name, email, profession]
    );

    res.json({ success: true, message: "Verified and registered" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
