const express = require("express");
const { pool } = require("./db");

const app = express();
const PORT = 3100;

process.on("unhandledRejection", () => {
  console.log("An error occurred");
});

function pageShell(content) {
  return [
    "<!DOCTYPE html>",
    "<html><head><title>Academy Progress Portal</title>",
    "<style>body{font-family:Arial;max-width:900px;margin:32px auto}input{width:520px}.note{border:1px solid #999;padding:12px;min-height:36px}table{border-collapse:collapse}td,th{padding:8px;border:1px solid #777}</style>",
    "</head><body>",
    "<h1>Academy Progress Portal</h1>",
    '<nav><a href="/">Progress record</a> | <a href="/helpdesk">Helpdesk lookup</a></nav>',
    content,
    "</body></html>"
  ].join("");
}

function loginForm() {
  return [
    '<form method="GET" action="/" autocomplete="off">',
    '<p><label>Portal ID: <input type="text" name="portal_id" size="100"></label></p>',
    '<p><label>Access key: <input type="text" name="access_key" size="100"></label></p>',
    '<button type="submit">View progress</button>',
    "</form>"
  ].join("");
}

function renderRecord(row) {
  const table = row
    ? [
        "<table>",
        "<tr><th>Learner</th><th>Program</th><th>GPA</th></tr>",
        "<tr><td>", row.display_name, "</td><td>", row.program,
        "</td><td>", row.gpa, "</td></tr>",
        "</table>"
      ].join("")
    : "<p>No record found.</p>";

  const note = row
    ? "<h2>Advisor note</h2><div class=\"note\">" + row.advisor_note + "</div>"
    : "";

  return pageShell("<p>Use your Portal ID and Access key.</p>" + loginForm() + table + note);
}

app.get("/", async (req, res) => {
  const portalId = req.query.portal_id;
  const accessKey = req.query.access_key;

  if (portalId === undefined || accessKey === undefined) {
    res.send(renderRecord(null));
    return;
  }

  let row = null;
  try {
    const sql =
      "SELECT record_id, display_name, program, gpa, advisor_note, access_key " +
      "FROM learner_records WHERE portal_id = '" + portalId +
      "' AND access_key = '" + accessKey + "'";

    const queryResult = await pool.query(sql);
    const results = queryResult[0];
    const rows = Array.isArray(results[0]) ? results[0] : results;
    row = rows.length > 0 ? rows[0] : null;
  } catch (err) {
    console.log("An error occurred");
  }

  res.send(renderRecord(row));
});

function helpdeskForm() {
  return [
    '<form method="GET" action="/helpdesk" autocomplete="off">',
    '<p><label>Portal ID: <input type="text" name="portal_id" size="100"></label></p>',
    '<p><label>Case reference: <input type="text" name="case_ref" size="100"></label></p>',
    '<button type="submit">Check case</button>',
    "</form>"
  ].join("");
}

app.get("/helpdesk", async (req, res) => {
  const portalId = req.query.portal_id;
  const caseRef = req.query.case_ref;

  if (portalId === undefined || caseRef === undefined) {
    res.send(pageShell("<h2>Helpdesk lookup</h2><p>This page intentionally reveals only whether a case exists.</p>" + helpdeskForm()));
    return;
  }

  let found = false;
  try {
    const sql =
      "SELECT case_id, case_ref, category, current_state FROM support_cases " +
      "WHERE owner_portal_id = '" + portalId +
      "' AND case_ref = '" + caseRef + "'";
    const queryResult = await pool.query(sql);
    const rows = queryResult[0];
    found = Array.isArray(rows) && rows.length > 0;
  } catch (err) {
    console.log("An error occurred");
  }

  const message = found
    ? "<p><strong>Case status is available.</strong></p>"
    : "<p><strong>No matching case.</strong></p>";

  res.send(pageShell("<h2>Helpdesk lookup</h2><p>The details are deliberately not displayed.</p>" + helpdeskForm() + message));
});

app.listen(PORT, () => {
  console.log("Academy site listening on port " + PORT);
});
