const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
require("dotenv").config();

const app = express();

app.use(bodyParser.json());

const users = [];

class User {
  #password;

  constructor(username, password, role = "user") {
    this.username = username;
    this.#password = this.#encryptPassword(password);
    this.role = role;
  }

  #encryptPassword(password) {
    return password.split("").reverse().join("");
  }

  checkPassword(password) {
    return this.#encryptPassword(password) === this.#password;
  }
}

class Admin extends User {
  constructor(username, password) {
    super(username, password, "admin");
  }
}

const authenticationToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Access denied. No token provided." });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalied or expired token." });
    req.user = user;

    next();
  });
};

app.post("/register", (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and Password are required!" });
  }

  if (users.some((user) => user.username === username)) {
    return res.status(400).json({ error: "User already exists" });
  }

  const newUser = role === "admin" ? new Admin(username, password) : new User(username, password);

  users.push(newUser);

  res.json({ message: "User registered successfully", username, role });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find((user) => user.username === username);

  if (!user || !user.checkPassword(password)) {
    return res.status(401).json({ error: "Invalid password" });
  }

  const token = jwt.sign({ username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1H" });

  res.json({ message: "Login Successfully", token });
});

app.get("/users", authenticationToken, (req, res) => {
  const { username } = req.query;

  const admin = users.find((user) => user.username === username && user.role === "admin");

  if (!admin) {
    res.status(404).json({ error: "Access denied. Admins Only !" });
  }

  res.json(users.map((user) => ({ username: user.username, role: user.role })));
});
// Start server
app.listen(3000, () => console.log("🚀 Server running on http://localhost:3000"));
