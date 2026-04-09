require("dotenv").config();
const { encrypt, decrypt } = require("./utils/encryption");
const fs = require("fs");
const path = require("path");
const https = require("https");
const express = require("express");
const helmet = require("helmet");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const csrf = require("csurf");
const User = require("./models/User");
const ensureAuthenticated = require("./middleware/authMiddleware");
const authorizeRole = require("./middleware/roleMiddleware");
const verifyJWT = require("./middleware/jwtMiddleware");

const app = express();

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const csrfProtection = csrf({ cookie: true });

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 15 * 60 * 1000,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  res.locals.csrfToken = "";
  next();
});

// Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "img-src": ["'self'", "data:", "https:"],
        "script-src": ["'self'"],
        "style-src": ["'self'", "'unsafe-inline'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

app.use(
  helmet.hsts({
    maxAge: 15552000,
    includeSubDomains: true,
    preload: false,
  })
);

// Static files
app.use(
  express.static(path.join(__dirname, "public"), {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith(".html")) {
        res.setHeader("Cache-Control", "public, max-age=300, stale-while-revalidate=60");
        return;
      }

      if (/\.(css|js|png|jpg|jpeg|gif|svg|webp|ico)$/i.test(filePath)) {
        res.setHeader("Cache-Control", "public, max-age=86400, immutable");
        return;
      }

      res.setHeader("Cache-Control", "public, max-age=300");
    },
  })
);

function setCache(res, value) {
  res.setHeader("Cache-Control", value);
}

function generateAccessToken(user) {
  return jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: "15m" }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    {
      id: user._id,
    },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" }
  );
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many login attempts. Please try again after 15 minutes.",
  standardHeaders: true,
  legacyHeaders: false,
});

// Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
          user = await User.create({
            username: profile.displayName,
            email: profile.emails?.[0]?.value || `google-${profile.id}@example.com`,
            googleId: profile.id,
            password: null,
            role: "user",
          });
        }

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

app.get("/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Auth pages
app.get("/signup", (req, res) => {
  setCache(res, "no-store");
  res.sendFile(path.join(__dirname, "public", "signup.html"));
});

app.get("/login", (req, res) => {
  setCache(res, "no-store");
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Register
app.post("/auth/register", async (req, res) => {
  try {
    setCache(res, "no-store");

    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).send("All fields are required");
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });

    if (existingUser) {
      return res.status(400).send("User already exists");
    }

    const hashedPassword = await argon2.hash(password);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      role: "user",
    });

    await newUser.save();

    res.send("User registered successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Registration failed");
  }
});

// Browser login: creates session and redirects to dashboard
app.post("/auth/login", loginLimiter, async (req, res) => {
  try {
    setCache(res, "no-store");

    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !user.password) {
      return res.status(400).send("Invalid email or password");
    }

    const isMatch = await argon2.verify(user.password, password);

    if (!isMatch) {
      return res.status(400).send("Invalid email or password");
    }

    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).send("Session error");
      }

      req.login(user, (loginErr) => {
        if (loginErr) {
          return res.status(500).send("Login failed");
        }

        const refreshToken = generateRefreshToken(user);

        res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: true,
          sameSite: "lax",
          maxAge: 7 * 24 * 60 * 60 * 1000,
        });

        res.redirect("/dashboard");
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Login failed");
  }
});

// API login: returns JWT for Postman
app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    setCache(res, "no-store");

    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !user.password) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const isMatch = await argon2.verify(user.password, password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      message: "Login successful",
      accessToken,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Login failed" });
  }
});

// Refresh token
app.post("/auth/refresh", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token missing" });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    const newAccessToken = jwt.sign(
      {
        id: user._id,
        email: user.email,
        role: user.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.json({ accessToken: newAccessToken });
  } catch (error) {
    return res.status(403).json({ message: "Invalid or expired refresh token" });
  }
});

// Google routes
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/dashboard");
  }
);

// Logout
app.post("/logout", ensureAuthenticated, (req, res, next) => {
  res.clearCookie("refreshToken");

  req.logout((err) => {
    if (err) return next(err);

    req.session.destroy((destroyErr) => {
      if (destroyErr) {
        return res.status(500).json({ message: "Logout failed" });
      }

      res.clearCookie("connect.sid");
      res.json({ message: "Logged out successfully" });
    });
  });
});

// Protected routes for Part B
app.get("/profile", ensureAuthenticated, (req, res) => {
  return res.redirect("/dashboard");
});
app.get("/dashboard", ensureAuthenticated, (req, res) => {
  setCache(res, "no-store");
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/admin", ensureAuthenticated, authorizeRole("admin"), (req, res) => {
  setCache(res, "no-store");
  res.send(`
    <h1>Admin Panel</h1>
    <p>Welcome Admin: ${req.user.username}</p>
    <p>This route is restricted to admin users only.</p>
    <p><a href="/">Go Home</a></p>
    <p><a href="/dashboard">Go to Dashboard</a></p>
  `);
});

// JWT routes for Part C
app.get("/api/profile", ensureAuthenticated, async (req, res) => {
  try {
    setCache(res, "no-store");

    const user = await User.findById(req.user._id).select(
      "username email bioEncrypted bioIv role"
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const decryptedBio = decrypt(user.bioEncrypted, user.bioIv);

    res.json({
      user: {
        name: user.username || "",
        email: user.email || "",
        bio: decryptedBio || "",
        role: user.role || "user",
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to load profile" });
  }
});

app.post("/api/profile/update", ensureAuthenticated, async (req, res) => {
  try {
    setCache(res, "no-store");

    let { name, email, bio } = req.body;

    const errors = {};

    name = (name || "").trim();
    email = (email || "").trim().toLowerCase();
    bio = (bio || "").trim();

    const namePattern = /^[A-Za-z\s]{3,50}$/;
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const bioPattern = /^[A-Za-z0-9\s.,!?'"-]{0,500}$/;

    if (!namePattern.test(name)) {
      errors.name = "Name must be 3 to 50 alphabetic characters.";
    }

    if (!emailPattern.test(email)) {
      errors.email = "Please enter a valid email address.";
    }

    if (!bioPattern.test(bio)) {
      errors.bio =
        "Bio must be under 500 characters and must not contain HTML or unsafe special characters.";
    }

    if (Object.keys(errors).length > 0) {
      return res.status(400).json({
        message: "Please fix the form errors.",
        errors,
      });
    }

    const existingEmailUser = await User.findOne({
      email,
      _id: { $ne: req.user._id },
    });

    if (existingEmailUser) {
      return res.status(400).json({
        message: "That email is already in use.",
        errors: {
          email: "That email is already in use.",
        },
      });
    }

    const encryptedBioResult = encrypt(bio);

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      {
        username: name,
        email,
        bioEncrypted: encryptedBioResult.encryptedData,
        bioIv: encryptedBioResult.iv,
      },
      { new: true }
    ).select("username email bioEncrypted bioIv role");

    const decryptedBio = decrypt(updatedUser.bioEncrypted, updatedUser.bioIv);

    res.json({
      message: "Profile updated successfully.",
      user: {
        name: updatedUser.username || "",
        email: updatedUser.email || "",
        bio: decryptedBio || "",
        role: updatedUser.role || "user",
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Profile update failed" });
  }
});

app.get("/api/dashboard", verifyJWT, (req, res) => {
  if (req.jwtUser.role === "admin") {
    return res.json({
      message: "Admin dashboard via JWT",
      user: req.jwtUser,
    });
  }

  res.json({
    message: "User dashboard via JWT",
    user: req.jwtUser,
  });
});

app.get("/api/admin", verifyJWT, (req, res) => {
  if (req.jwtUser.role !== "admin") {
    return res.status(403).json({ message: "Access denied" });
  }

  res.json({
    message: "Admin-only JWT route",
    user: req.jwtUser,
  });
});

// Public routes
app.get("/", (req, res) => {
  setCache(res, "public, max-age=300, stale-while-revalidate=60");
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/about", (req, res) => {
  setCache(res, "public, max-age=600");
  res.sendFile(path.join(__dirname, "public", "about.html"));
});

app.get("/projects", (req, res) => {
  setCache(res, "public, max-age=300");
  res.sendFile(path.join(__dirname, "public", "projects.html"));
});

app.get("/contact", (req, res) => {
  setCache(res, "public, max-age=300");
  res.sendFile(path.join(__dirname, "public", "contact.html"));
});

app.post("/contact", csrfProtection, (req, res) => {
  setCache(res, "no-store");

  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ error: "All fields required" });
  }

  res.json({ status: "Message received (Phase 1 demo)" });
});

app.get("/skills", (req, res) => {
  setCache(res, "public, max-age=300, stale-while-revalidate=60");
  res.sendFile(path.join(__dirname, "public", "skills.html"));
});

app.get("/blog", (req, res) => {
  setCache(res, "public, max-age=600, stale-while-revalidate=120");
  res.sendFile(path.join(__dirname, "public", "blog.html"));
});

// HTTPS server
const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, "certs", "localhost.key")),
  cert: fs.readFileSync(path.join(__dirname, "certs", "localhost.crt")),
};

const PORT = process.env.PORT || 3000;

https.createServer(sslOptions, app).listen(PORT, () => {
  console.log(`🔐 Secure server running at https://localhost:${PORT}`);
});