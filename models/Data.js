import mongoose from "mongoose";

// -------- User Data Schema --------
const userDataSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  refreshToken: String,
  googleId: String,
  cart: { type: [String], default: [] },
  wishlist: { type: [String], default: [] },
});

const otpDataSchema = new mongoose.Schema({
  email: { type: String, required: true },
  otpHash: String,
  expiresAt: Date,
});

const resetTokenDataSchema = new mongoose.Schema({
  email: { type: String, required: true },
  tokenHash: String,
  expiresAt: Date,
});

const paymentDataSchema = new mongoose.Schema({
  orderId: String,
  paymentId: String,
  signature: String,
  amount: Number,
  status: { type: String, default: "pending" },
  createdAt: { type: Date, default: Date.now },
});

const productDataSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  image: String,
  company: String,
  item_name: String,                     
  original_price: mongoose.Schema.Types.Mixed,   // number or string
  return_period: mongoose.Schema.Types.Mixed,    // number or string
  delivery_date: String,
  category: String,
  rating: {
    stars: mongoose.Schema.Types.Mixed,   // 4.5 or "4.5"
    count: mongoose.Schema.Types.Mixed,   // "57k" or number
  },
});


export const Paymentdata = mongoose.model("Paymentdata", paymentDataSchema);
export const ResetTokendata = mongoose.model("ResetTokendata", resetTokenDataSchema);
export const Otpdata = mongoose.model("Otpdata", otpDataSchema);
export const Userdata = mongoose.model("Userdata", userDataSchema);
export const Productdata = mongoose.model("Productdata", productDataSchema);
