const { Router } = require("express");
const indexRouter = Router();
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");
const db = require("../db/db");
const passport = require("passport");

const SECRET_PASSCODE = process.env.SECRET_PASSCODE || "secret";
const SECRET_ADMIN_PASSCODE = process.env.SECRET_ADMIN_PASSCODE || "secret";

indexRouter.get("/", async (req, res) => {
  try {
    const result = await db.query(`
      SELECT messages.*, users.username AS author
      FROM messages
      JOIN users ON messages.author_id = users.id
      ORDER BY messages.timestamp DESC
    `);
    let membership = null;
    if (req.user) {
      const resultMembership = await db.query(
        "SELECT membership_status FROM users WHERE id = $1",
        [req.user.id]
      );
      membership = resultMembership.rows[0].membership_status;
    }
    res.render("index", {
      user: req.user,
      messages: result.rows,
      membership: membership,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error.");
  }
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

      const result = await db.query(
        "INSERT INTO users (first_name, last_name, username, password, membership_status) VALUES ($1, $2, $3, $4, $5) RETURNING *",
        [firstName, lastName, username, hashedPassword, "basic"]
      );

      const newUser = result.rows[0];

      req.login(newUser, (err) => {
        if (err) {
          return next(err);
        }
        return res.redirect("/join-club");
      });
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

indexRouter.get("/become-admin", (req, res) => {
  res.render("become-admin", { error: [] });
});

indexRouter.post("/become-admin", async (req, res) => {
  const { passcode } = req.body;

  if (!req.user) {
    return res.status(401).send("You must be logged in to become an admin.");
  }

  console.log(SECRET_ADMIN_PASSCODE)

  if (passcode !== SECRET_ADMIN_PASSCODE) {
    return res.render("become-admin", { error: "Incorrect passcode." });
  }

  try {
    await db.query("UPDATE users SET membership_status = $1 WHERE id = $2", [
      "admin",
      req.user.id,
    ]);
    res.redirect("/");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error.");
  }
});

indexRouter.get("/new-message", (req, res) => {
  res.render("new-message", { error: [] });
});

indexRouter.post("/new-message", async (req, res) => {
  const { title, text } = req.body;

  if (!req.user) {
    return res.render("new-message", {
      error: "You must be logged in to create a message.",
    });
  }

  if (title.length > 255) {
    return res.render("new-message", { error: "The title is too long." });
  }

  try {
    await db.query(
      "INSERT INTO messages (title, text, author_id) VALUES ($1, $2, $3)",
      [title, text, req.user.id]
    );
    res.redirect("/");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error.");
  }
});

module.exports = indexRouter;
