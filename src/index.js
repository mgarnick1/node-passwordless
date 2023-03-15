const express = require("express");
require("dotenv").config();
const bodyParser = require("body-parser");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const db = require("./queries");
const sessions = require("express-session");

const app = express();

app.use(helmet());

app.use(bodyParser.json());

app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

const oneDay = 1000 * 60 * 60 * 24;

app.use(
  sessions({
    secret: process.env.SESSIONSECRET,
    saveUninitialized: true,
    cookie: { maxAge: oneDay, secure: false, httpOnly: false },
    resave: true,
  })
);

app.use(cors());
app.use(morgan("combined"));

app.get("/", (req, res) => {
  res.json({ info: "Node.js, Express, and Postgres API" });
});

app.post("/users/add", db.registerUser);
app.post("/users/register", db.finishRegister);
app.post("/users/login", db.login);
app.post("/users/verify", db.verify);
app.post("/users/logout", db.logout);
app.get('/quote', db.getQuotes);

app.listen(3001, () => {
  console.log("listening on port 3001");
});
