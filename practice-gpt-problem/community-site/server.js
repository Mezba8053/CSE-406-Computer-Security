const express = require("express");
const crypto = require("crypto");
const { pool } = require("./db");

const app = express();
const PORT = 3101;
const sessions = new Map();

app.use(express.urlencoded({ extended: false }));

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function cookieValue(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;

  for (const item of header.split(";")) {
    const pieces = item.trim().split("=");
    if (pieces.shift() === name) return pieces.join("=");
  }

  return null;
}

function sessionUser(req) {
  const sid = cookieValue(req, "sid");
  return sid ? sessions.get(sid) || null : null;
}

function loginPage(error) {
  return [
    "<!DOCTYPE html><html><head><title>Study Community</title></head><body>",
    "<h1>Study Community</h1>",
    error ? "<p>" + escapeHtml(error) + "</p>" : "",
    '<form method="POST" action="/login">',
    '<p><label>Username: <input name="username"></label></p>',
    '<p><label>Password: <input type="password" name="password"></label></p>',
    '<button type="submit">Log in</button>',
    "</form></body></html>"
  ].join("");
}

app.get("/login", (req, res) => {
  res.send(loginPage(null));
});

app.post("/login", async (req, res) => {
  try {
    const username = req.body.username || "";
    const password = req.body.password || "";
    const queryResult = await pool.execute(
      "SELECT username, display_name FROM community_user WHERE username = ? AND password = ?",
      [username, password]
    );
    const rows = queryResult[0];
    const user = rows.length > 0 ? rows[0] : null;

    if (!user) {
      res.send(loginPage("Invalid username or password"));
      return;
    }

    const sid = crypto.randomUUID();
    sessions.set(sid, user);
    res.setHeader("Set-Cookie", "sid=" + sid + "; HttpOnly; Path=/");
    res.redirect("/");
  } catch (err) {
    console.log("An error occurred");
    res.status(500).send(loginPage("Please try again."));
  }
});

app.get("/", async (req, res) => {
  const user = sessionUser(req);
  if (!user) {
    res.redirect("/login");
    return;
  }

  try {
    const queryResult = await pool.query(
      "SELECT community_post.message, community_user.display_name " +
      "FROM community_post JOIN community_user ON community_post.username = community_user.username " +
      "ORDER BY community_post.id DESC"
    );
    const posts = queryResult[0];
    const postsHtml = posts.map((post) => {
      return "<p><strong>" + escapeHtml(post.display_name) + "</strong><br>" +
        escapeHtml(post.message) + "</p>";
    }).join("");

    res.send([
      "<!DOCTYPE html><html><head><title>Study Community</title></head><body>",
      "<p>Logged in as " + escapeHtml(user.display_name) + '. <a href="/logout">Log out</a></p>',
      '<form method="POST" action="/publish">',
      '<input name="message" size="90">',
      '<button type="submit">Publish</button>',
      "</form>",
      postsHtml,
      "</body></html>"
    ].join(""));
  } catch (err) {
    console.log("An error occurred");
    res.status(500).send("Please try again.");
  }
});

app.post("/publish", async (req, res) => {
  const user = sessionUser(req);
  if (!user) {
    res.redirect("/login");
    return;
  }

  const message = req.body.message;
  if (typeof message !== "string" || message.length === 0) {
    res.redirect("/");
    return;
  }

  try {
    await pool.execute(
      "INSERT INTO community_post (username, message) VALUES (?, ?)",
      [user.username, message]
    );
    res.redirect("/");
  } catch (err) {
    console.log("An error occurred");
    res.status(500).send("Please try again.");
  }
});

app.get("/logout", (req, res) => {
  const sid = cookieValue(req, "sid");
  if (sid) sessions.delete(sid);
  res.setHeader("Set-Cookie", "sid=; HttpOnly; Path=/; Max-Age=0");
  res.redirect("/login");
});

app.listen(PORT, () => {
  console.log("Community site listening on port " + PORT);
});
