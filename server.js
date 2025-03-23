require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = process.env.SECRET_KEY || "your-secret-key"; // Secret for JWT

// ✅ Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("✅ Connected to MongoDB Atlas"))
.catch(err => console.log("❌ MongoDB Error: ", err));

// ✅ User Schema
const UserSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String, // Hashed password
    role: { type: String, default: "user" } // "user" or "admin"
});

const User = mongoose.model("User", UserSchema);

// ✅ Signup API
app.post("/signup", async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.json({ message: "❌ Email already registered!" });

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Check if this user should be an admin
        const role = (username === "VasilTyulev" && password === "Vaskoto1231") ? "admin" : "user";

        // Create user
        const user = new User({ username, email, password: hashedPassword, role });
        await user.save();

        res.json({ message: "✅ Signup successful! You can now log in." });
    } catch (error) {
        res.status(500).json({ message: "❌ Internal server error!" });
    }
});

// ✅ Login API
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        // Check if user exists
        const user = await User.findOne({ username });
        if (!user) return res.json({ message: "❌ User not found!" });

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.json({ message: "❌ Incorrect password!" });

        // Create JWT Token
        const token = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: "1h" });

        res.json({ 
            message: "✅ Login successful!", 
            token, 
            role: user.role 
        });
    } catch (error) {
        res.status(500).json({ message: "❌ Internal server error!" });
    }
});

// ✅ Admin Dashboard API (Protected)
app.get("/admin", verifyToken, (req, res) => {
    if (req.user.role !== "admin") {
        return res.status(403).json({ message: "❌ Access Denied! Admins only." });
    }
    
    res.json({ message: "✅ Welcome to the Admin Dashboard!", admin: req.user.username });
});

// ✅ Middleware: Verify Token
function verifyToken(req, res, next) {
    const token = req.headers["authorization"];
    if (!token) return res.status(401).json({ message: "❌ Unauthorized! Token required." });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ message: "❌ Invalid Token!" });
        req.user = decoded;
        next();
    });
}

// ✅ Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
