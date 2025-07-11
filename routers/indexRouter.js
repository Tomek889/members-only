const { Router } = require("express");
const indexRouter = Router();

indexRouter.get("/", (req, res) => {
  res.render("index");
});

indexRouter.get("/sign-up", (req, res) => {
  res.render("sign-up");
});

indexRouter.post("/sign-up", (req, res) => {
  res.redirect("/sign-up");
});

indexRouter.get("/log-in", (req, res) => {
  res.render("log-in");
});

indexRouter.post("/log-in", (req, res) => {
  res.redirect("/log-in");
});

module.exports = indexRouter;
