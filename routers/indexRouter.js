const { Router } = require("express");
const indexRouter = Router();
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");
const db = require("../db/db");
const passport = require("passport");

const SECRET_PASSCODE = process.env.SECRET_PASSCODE || "secret";

indexRouter.get("/", (req, res) => {
  res.render("index", { user: req.user });
});

indexRouter.get("/sign-up", (req, res) => {
  res.render("sign-up", { errors: [] });
});

indexRouter.post(
  "/sign-up",
  [
    body("firstName").trim().notEmpty().withMessage("First name is required."),
    body("lastName").trim().notEmpty().withMessage("Last name is required."),
    body("username").isEmail().withMessage("Username must be a valid email."),
    body("password").isLength({ min: 6 }).withMessage("Password too short."),
    body("confirmPassword").custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Passwords do not match.");
      }
      return true;
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render("sign-up", {
        errors: errors.array(),
        data: req.body,
      });
    }

    const { firstName, lastName, username, password } = req.body;

    try {
      const existingUser = await db.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
      );
      if (existingUser.rows.length > 0) {
        return res.render("sign-up", {
          errors: [{ msg: "Email already registered." }],
          data: req.body,
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      await db.query(
        "INSERT INTO users (first_name, last_name, username, password, membership_status) VALUES ($1, $2, $3, $4, $5)",
        [firstName, lastName, username, hashedPassword, "basic"]
      );

      res.redirect("/join-club");
    } catch (err) {
      console.error(err);
      res.status(500).send("Server error.");
    }
  }
);

indexRouter.get("/log-in", (req, res) => {
  res.render("log-in", { error: [] });
});

indexRouter.post("/log-in", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res.render("log-in", { error: info?.message || "Login failed" });
    }
    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.redirect("/");
    });
  })(req, res, next);
});

indexRouter.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

indexRouter.get("/join-club", (req, res) => {
  res.render("join", { error: [] });
});

indexRouter.post("/join-club", async (req, res) => {
  const { passcode } = req.body;

  if (!req.user) {
    return res.status(401).send("You must be logged in to join the club.");
  }

  if (passcode !== SECRET_PASSCODE) {
    return res.render("join", { error: "Incorrect passcode." });
  }

  try {
    await db.query("UPDATE users SET membership_status = $1 WHERE id = $2", [
      "member",
      req.user.id,
    ]);
    res.redirect("/");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error.");
  }
});

indexRouter.get("/new-message", (req, res) => {
  res.render("new-message");
});

indexRouter.post("/new-message", (req, res) => {
  res.redirect("/");
});

module.exports = indexRouter;
