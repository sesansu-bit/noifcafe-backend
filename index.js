import express from "express";
import mongoose from "mongoose";
import { Userdata, Otpdata, ResetTokendata, Productdata, Paymentdata } from "./models/Data.js";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import nodemailer from "nodemailer";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";
import { OAuth2Client } from "google-auth-library";
import Razorpay from "razorpay";
import fs from "fs/promises";


dotenv.config();
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(helmet());
app.set("trust proxy", 1);

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);


mongoose
  .connect(process.env.MONGO_URI, {
    dbName: "cafedata",
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log("MongoDB connection error:", err));





app.get("/", (req, res) => {
  res.send("Server Running!");
});

async function seed() {
  await mongoose.connect(process.env.MONGO_URI);
  const data = JSON.parse(await fs.readFile("./itemdata.json", "utf8"));
  await Productdata.deleteMany();
  await Productdata.insertMany(data);
  console.log("Seed complete!");
  process.exit();
}



const createAccessToken = (user) =>
  jwt.sign({ id: user._id, email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });

const createRefreshToken = (user) =>
  jwt.sign({ id: user._id, email: user.email }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "30d" });













app.get("/products", async (req, res) => {
  const { category } = req.query;
  const filter = category ? { category } : {};
  const products = await Productdata.find(filter);
  res.json(products);
});

// ====================== AUTH ROUTES =======================

app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ success: false, message: "All fields required" });

    const existing = await Userdata.findOne({ email });
    if (existing)
      return res.status(409).json({ success: false, message: "Email already registered" });

    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);
    const userdata = await Userdata.create({ name, email, password: hashed });

    const accessToken = createAccessToken(userdata);
    const refreshToken = createRefreshToken(userdata);

    userdata.refreshToken = refreshToken;
    await userdata.save();


    res.status(201).json({
      success: true,
      message: "Signup successful 🎉",
      user: { id: userdata._id, name: userdata.name, email: userdata.email },
      accessToken,
      refreshToken, 
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ success: false, message: "Server error during signup" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, message: "Email and password are required" });

    const userdata = await Userdata.findOne({ email });
    if (!userdata)
      return res.status(401).json({ success: false, message: "Invalid email or password" });

    const match = await bcrypt.compare(password, userdata.password);
    if (!match)
      return res.status(401).json({ success: false, message: "Invalid email or password" });

    const accessToken = createAccessToken(userdata);
    const refreshToken = createRefreshToken(userdata);

    userdata.refreshToken = refreshToken;
    await userdata.save();

    res.json({
      success: true,
      message: "Login successful 🎉",
      user: { id: userdata._id, name: userdata.name, email: userdata.email },
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error during login" });
  }
});


app.post("/refresh", async (req, res) => {
  try {
    // For mobile, refresh token can be sent in body or header
    const token = req.body.refreshToken || req.headers["x-refresh-token"];
    if (!token)
      return res
        .status(401)
        .json({ success: false, message: "Refresh token missing" });

    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
      if (err)
        return res
          .status(403)
          .json({ success: false, message: "Invalid refresh token" });

      const user = await Userdata.findById(decoded.id);
      if (!user || !user.refreshToken)
        return res
          .status(403)
          .json({ success: false, message: "Not recognized" });

      if (user.refreshToken !== token) {
        user.refreshToken = null;
        await user.save();
        return res
          .status(403)
          .json({ success: false, message: "Refresh token mismatch" });
      }

      const newAccessToken = createAccessToken(user);
      const newRefreshToken = createRefreshToken(user);

      user.refreshToken = newRefreshToken;
      await user.save();

      // For mobile, just send tokens in JSON (no cookies)
      return res.json({
        success: true,
        message: "Tokens refreshed",
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });
    });
  } catch (err) {
    console.error("refresh error:", err);
    res
      .status(500)
      .json({ success: false, message: "Server error during token refresh" });
  }
});
app.post("/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body; // client sends refresh token

    if (refreshToken) {
      try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await Userdata.findById(decoded.id);
        if (user && user.refreshToken === refreshToken) {
          user.refreshToken = null;
          await user.save();
        }
      } catch (e) {
        console.log("Invalid token on logout, ignoring");
      }
    }

    res.json({ success: true, message: "Logged out successfully" });
  } catch (err) {
    console.error("logout error:", err);
    res.status(500).json({ success: false, message: "Server error during logout" });
  }
});

// ====================== MIDDLEWARE =======================
const verifyAccessToken = (req, res, next) => {
  try {
    // Try getting token from headers (Bearer token)
    const token = req.headers.authorization?.split(" ")[1];
    if (!token)
      return res
        .status(401)
        .json({ success: false, message: "Access token required" });

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) {
        if (err.name === "TokenExpiredError")
          return res
            .status(401)
            .json({ success: false, message: "Access token expired" });
        return res
          .status(403)
          .json({ success: false, message: "Invalid access token" });
      }

      req.user = decoded; // attach user info to request
      next();
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// ====================== PROFILE =======================
app.get("/profile", verifyAccessToken, async (req, res) => {
  try {
    const user = await Userdata.findById(req.user.id).select("-password -refreshToken");
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    res.json({ success: true, user });
  } catch (err) {
    console.error("getMe error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/verify-token", verifyAccessToken, (req, res) => {
  res.json({ success: true, message: "Token valid", user: req.user });
});

// ====================== MAIL SERVICE =======================
let transporter;
try {
 transporter = nodemailer.createTransport({
  host:process.env.SMTP_HOST,
  port:  Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: {
   user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});
  await transporter.verify();
  console.log("Mail service ready");
} catch (err) {
  console.error("Mail service failed:", err.message);
}


// ====================== OTP & RESET =======================
const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();
const OTP_TTL_MS = 5 * 60 * 1000;
const TOKEN_TTL_MS = 10 * 60 * 1000;

const otpLimiter = rateLimit({ windowMs: 20 * 60 * 1000, max: 20, message: { ok: false, message: "Too many OTP requests, try later" } });

// -------------------- SEND OTP --------------------
app.post("/api/send-otp", otpLimiter, body("email").isEmail().withMessage("Valid email required"), async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });

    const { email } = req.body;
    const otp = generateOtp();
    const otpHash = await bcrypt.hash(otp, 10);
    const expiresAt = new Date(Date.now() + OTP_TTL_MS);

    await Otpdata.deleteMany({ email });
    await Otpdata.create({ email, otpHash, expiresAt });

    await transporter.sendMail({ 
      from: process.env.FROM_EMAIL,
      to: email,
       subject: "Password Reset OTP from Noir Cafe",
       text: `Your OTP is ${otp} send by seshansu(noircafe). Valid for 5 minutes.`,
       });

    res.json({ ok: true, message: "OTP sent successfully" });
  } catch (err) {
    console.error("Send OTP Error:", err);
    res.status(500).json({ message: "Server error" });
  }
});



// -------------------- 2️⃣ Verify OTP --------------------
app.post(
  "/api/verify-otp",
  body("email").isEmail(),
  body("otp").isLength({ min: 6, max: 6 }),
  async (req, res) => {
    try {
      const { email, otp } = req.body;
      const record = await Otpdata.findOne({ email });
      if (!record) return res.status(400).json({ message: "OTP not found" });

      if (record.expiresAt < new Date()) {
        await Otpdata.deleteOne({ email });
        return res.status(400).json({ message: "OTP expired" });
      }

      const isMatch = await bcrypt.compare(otp, record.otpHash);
      if (!isMatch) return res.status(400).json({ message: "Invalid OTP" });

      await Otpdata.deleteOne({ email });

      // Create a reset token
      const rawToken = crypto.randomBytes(32).toString("hex");
      const tokenHash = await bcrypt.hash(rawToken, 10);
      const expiresAt = new Date(Date.now() + TOKEN_TTL_MS);

      await ResetTokendata.deleteMany({ email });
      await ResetTokendata.create({ email, tokenHash, expiresAt });

      // Send token in response instead of cookie (React Native friendly)
      res.json({
        ok: true,
        message: "OTP verified successfully",
        resetToken: rawToken,  // frontend will store this in AsyncStorage
      });
    } catch (err) {
      console.error("Verify OTP Error:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// -------------------- 3️⃣ Reset Password --------------------
app.post(
  "/api/reset-password",
  body("email").isEmail(),
  body("newPassword").isLength({ min: 6 }),
  async (req, res) => {
    try {
      const { email, newPassword } = req.body;
      const rawToken = req.headers["x-reset-token"]; 

      if (!rawToken)
        return res.status(400).json({ message: "No reset token provided" });

      const record = await ResetTokendata.findOne({ email });
      if (!record)
        return res.status(400).json({ message: "Reset token not found" });

      if (record.expiresAt < new Date()) {
        await ResetTokendata.deleteOne({ email });
        return res.status(400).json({ message: "Token expired" });
      }

      const isValid = await bcrypt.compare(rawToken, record.tokenHash);
      if (!isValid)
        return res.status(400).json({ message: "Invalid or tampered token" });

      const user = await Userdata.findOne({ email });
      if (!user)
        return res.status(400).json({ message: "Email not registered" });

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      user.password = hashedPassword;
      await user.save();

      await ResetTokendata.deleteOne({ email });

      console.log("✅ Password updated for:", email);
      res.json({ ok: true, message: "Password reset successful" });
    } catch (err) {
      console.error("Reset Password Error:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);


// -------------------- Google Login --------------------
app.post("/api/auth/google", async (req, res) => {
  const { tokenId } = req.body;
  try {
    const ticket = await client.verifyIdToken({
      idToken: tokenId,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, name, sub: googleId } = payload;

    let user = await Userdata.findOne({ email });
    if (!user) {
      user = new Userdata({ name, email, googleId });
      await user.save();
    }

    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken(user);

    user.refreshToken = refreshToken;
    await user.save();

    // send tokens in JSON response (mobile friendly)
    res.status(200).json({
      success: true,
      message: "Google login successful🎉",
      user: { name, email },
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.log(err);
    res.status(400).json({ success: false, message: "Google login failed" });
  }
});

// -------------------- Razorpay Setup --------------------
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

app.get("/api/get-razorpay-key", (req, res) => {
  res.json({ key: process.env.RAZORPAY_KEY_ID });
});

app.post("/api/create-order", async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount)
      return res
        .status(400)
        .json({ success: false, message: "Amount required" });

    const options = {
      amount: Number(amount) * 100,
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
    };

    const order = await razorpay.orders.create(options);
    if (!order)
      return res
        .status(500)
        .json({ success: false, message: "Order creation failed" });

    res.json({ success: true, order });
  } catch (error) {
    console.error("Order Error:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

app.post("/api/verify-payment", async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, amount } =
      req.body;

    const sign = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSign = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(sign)
      .digest("hex");

    if (razorpay_signature === expectedSign) {
      await Paymentdata.create({
        orderId: razorpay_order_id,
        paymentId: razorpay_payment_id,
        signature: razorpay_signature,
        amount,
        status: "success",
      });
      return res.json({ success: true, message: "Payment verified successfully" });
    } else {
      return res
        .status(400)
        .json({ success: false, message: "Invalid signature" });
    }
  } catch (error) {
    console.error("Verify Error:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});










// -------------------- Search --------------------
app.get("/search", async (req, res) => {
  try {
    const query = req.query.q?.trim().toLowerCase();
    if (!query) return res.json({ suggestions: [] });

    const items = await Productdata.find({
      $or: [
        { item_name: { $regex: query, $options: "i" } },
        { category: { $regex: query, $options: "i" } },
      ],
    }).limit(10);

    const uniqueSuggestions = Array.from(
      new Set(
        items.map((p) =>
          JSON.stringify({ name: p.company, category: p.category })
        )
      )
    ).map((p) => JSON.parse(p));

    res.json({ suggestions: uniqueSuggestions });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// -------------------- Cart --------------------
app.get("/cartfetch", verifyAccessToken, async (req, res) => {
  try {
    const user = await Userdata.findById(req.user.id);
    if (!user.cart || user.cart.length === 0) {
      return res.json({ success: true, items: [] });
    }

    const productIds = user.cart;
    const products = await Productdata.find({ id: { $in: productIds } });

    res.json({ success: true, items: products });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/bagstore", verifyAccessToken,  async (req, res) => {
  try {
    const { productId } = req.body;
    if (!productId)
      return res
        .status(400)
        .json({ success: false, message: "Product ID is required" });

    const user = await Userdata.findById(req.user.id);
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    if (user.wishlist.includes(productId))
      return res.status(400).json({
        success: false,
        isDuplicate: true,
        message: "Product exists in wishlist, cannot add to wishlist",
      });

    if (user.cart.includes(productId))
      return res.status(200).json({
        success: true,
        message: "Product already in cart",
        isDuplicate: true,
      });

    if (!user.wishlist.includes(productId)) user.cart.push(productId);
    await user.save();

    const product = await Productdata.findOne({ id: productId });
    res.json({
      success: true,
      message: "Product added to cart",
      item: product,
      isDuplicate: false,
    });
  } catch (err) {
    console.error("Add to cart error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/bagremove",  verifyAccessToken,async (req, res) => {
  try {
    const { productId } = req.body;
    if (!productId)
      return res
        .status(400)
        .json({ success: false, message: "Product ID is required" });

    const user = await Userdata.findById(req.user.id);
    if (!user)
      return res.status(404).json({ success: false, message: "User not found" });

    user.cart = user.cart.filter((id) => id !== productId);
    await user.save();

    res.json({ success: true, message: "Product removed from cart" });
  } catch (err) {
    console.error("Remove from cart error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// -------------------- Wishlist --------------------
app.get("/wishlistfetch",  verifyAccessToken, async (req, res) => {
  try {
    const user = await Userdata.findById(req.user.id);
    if (!user.wishlist || user.wishlist.length === 0)
      return res.json({ success: true, items: [] });

    const products = await Productdata.find({ id: { $in: user.wishlist } });
    res.json({ success: true, items: products });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/wishliststore", verifyAccessToken, async (req, res) => {
  try {
    const { productId } = req.body;
    if (!productId)
      return res
        .status(400)
        .json({ success: false, message: "Product ID is required" });

    const user = await Userdata.findById(req.user.id);
    if (!user)
      return res.status(404).json({ success: false, message: "User not found" });

    if (user.cart.includes(productId))
      return res.status(400).json({
        success: false,
        isDuplicate: true,
        message: "Product exists in cart, cannot add to wishlist",
      });

    if (user.wishlist.includes(productId)) {
      const existingItem = await Productdata.findOne({ id: productId });
      return res.status(200).json({
        success: true,
        message: "Product already in wishlist",
        item: existingItem,
        isDuplicate: true,
      });
    }

    user.wishlist.push(productId);
    await user.save();

    const newItem = await Productdata.findOne({ id: productId });
    return res.json({
      success: true,
      message: "Added to wishlist",
      item: newItem,
      isDuplicate: false,
    });
  } catch (err) {
    console.error("Add to wishlist error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/wishlistremove", verifyAccessToken, async (req, res) => {
  try {
    const { productId } = req.body;
    if (!productId)
      return res
        .status(400)
        .json({ success: false, message: "Product ID is required" });

    const user = await Userdata.findById(req.user.id);
    if (!user)
      return res.status(404).json({ success: false, message: "User not found" });

    let addedToCartProduct = null;

    if (!user.cart.includes(productId)) {
      user.cart.push(productId);
      addedToCartProduct = await Productdata.findOne({ id: productId });
    }

    user.wishlist = user.wishlist.filter((id) => id !== productId);
    await user.save();

    res.json({
      success: true,
      message: "Wishlist updated and moved to cart if needed",
      addedToCart: addedToCartProduct,
    });
  } catch (err) {
    console.error("Wishlist remove error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});








app.listen(3000, () => {
  console.log("Server started on port 3000");
});
