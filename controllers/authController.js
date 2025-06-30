// controllers/authController.js
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// ✅ Signup Controller
exports.signupUser = async (req, res) => {
  try {
    const { fullName, username, email, mobile, password, referralCode } = req.body;

    // Check unique email/phone/username
    const existingUser = await User.findOne({
      $or: [{ email }, { mobile }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists with provided email, mobile or username" });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create referralCode for this user
    const newReferral = Math.random().toString(36).substring(2, 8).toUpperCase();

    // Default coins
    let coins = 0;

    // Referral logic
    if (referralCode) {
      const refUser = await User.findOne({ referralCode });
      if (refUser) {
        refUser.coins += 20; // bonus to referrer
        await refUser.save();
        coins = 10; // bonus to new user
      }
    }

    const newUser = new User({
      fullName,
      username,
      email,
      mobile,
      password: hashedPassword,
      referralCode: newReferral,
      coins
    });

    await newUser.save();

    res.status(201).json({ message: "Signup successful" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Signup failed" });
  }
};

// ✅ Login Controller
exports.loginUser = async (req, res) => {
  try {
    const { identifier, password } = req.body;

    // Allow login by username or email
    const user = await User.findOne({
      $or: [{ email: identifier }, { username: identifier }]
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Create token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d"
    });

    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        username: user.username,
        email: user.email,
        mobile: user.mobile,
        coins: user.coins,
        referralCode: user.referralCode,
        role: user.role
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed" });
  }
};
