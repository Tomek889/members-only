const { Router } = require("express");
const indexRouter = Router();
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");
const db = require("../db/db");

indexRouter.get("/", (req, res) => {
  res.render("index");
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

      res.redirect("/log-in");
    } catch (err) {
      console.error(err);
      res.status(500).send("Server error.");
    }
  }
);

indexRouter.get("/log-in", (req, res) => {
  res.render("log-in");
});

indexRouter.post("/log-in", (req, res) => {
  res.redirect("/log-in");
});

module.exports = indexRouter;
