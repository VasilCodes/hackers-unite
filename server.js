require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("✅ Connected to MongoDB Atlas"))
.catch(err => console.log("❌ MongoDB Error: ", err));

// User schema
const UserSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String
});

const User = mongoose.model("User", UserSchema);

// Admin credentials (hashed password for security)
const adminUsername = "VasilTyulev";
const adminPassword = "$2a$10$XhLhGBmU0hI95cUvJotFb.GE9EAYdJl0pt3u8b2OE1x3Tn13mBg/q"; // bcrypt hash of "Vaskoto1231"

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ message: "❌ Access Denied!" });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(403).json({ message: "❌ Invalid Token!" });
    }
};

// Signup API
app.post("/signup", async (req, res) => {
    const { username, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.json({ message: "❌ Email already registered!" });

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    
    res.json({ message: "✅ Signup successful! You can now log in." });
});

// Login API
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    if (username === adminUsername) {
        // Check admin password
        const isMatch = await bcrypt.compare(password, adminPassword);

        if (isMatch) {
            // Generate JWT Token for Admin
            const token = jwt.sign({ username, role: "admin" }, process.env.JWT_SECRET, { expiresIn: "2h" });

            return res.json({ message: "✅ Admin Login Successful!", token, isAdmin: true });
        } else {
            return res.json({ message: "❌ Incorrect password!" });
        }
    }

    // Check if user exists
    const user = await User.findOne({ username });
    if (!user) return res.json({ message: "❌ User not found!" });

    // Check user password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.json({ message: "❌ Incorrect password!" });

    // Generate JWT Token for User
    const token = jwt.sign({ username, role: "user" }, process.env.JWT_SECRET, { expiresIn: "2h" });

    res.json({ message: "✅ Login successful!", token });
});

// Admin Dashboard Route (Protected)
app.get("/admin", authenticateToken, (req, res) => {
    if (req.user.role !== "admin") {
        return res.status(403).json({ message: "❌ Access Denied! Admins only." });
    }
    res.json({ message: "👑 Welcome to the Admin Dashboard!" });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
