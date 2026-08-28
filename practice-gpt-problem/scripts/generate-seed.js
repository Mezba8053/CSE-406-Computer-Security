const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { learners } = require("../data/learners");

function sqlString(value) {
  return String(value).replace(/'/g, "''");
}

function randomScore(index) {
  const base = 62 + ((index * 7 + crypto.randomInt(0, 14)) % 34);
  return base.toFixed(2);
}

function recoveryCode() {
  return "vault-" + crypto.randomBytes(3).toString("hex");
}

const academyRows = learners.map((learner, index) => {
  const gpa = (2.25 + ((index * 19 + crypto.randomInt(0, 45)) / 100)).toFixed(2);
  const recovery = recoveryCode();
  return {
    portalId: learner[0],
    displayName: learner[1],
    program: learner[2],
    accessKey: learner[3],
    username: learner[4],
    gpa,
    recovery,
    score: randomScore(index),
    badge: "BADGE-" + String(701 + index)
  };
});

const academySql = [
  "CREATE DATABASE IF NOT EXISTS academy_lab;",
  "USE academy_lab;",
  "",
  "CREATE TABLE learner_records (",
  "  record_id INT AUTO_INCREMENT PRIMARY KEY,",
  "  portal_id VARCHAR(20) NOT NULL,",
  "  display_name VARCHAR(100) NOT NULL,",
  "  program VARCHAR(100) NOT NULL,",
  "  gpa DECIMAL(3,2) NOT NULL,",
  "  advisor_note VARCHAR(1000) NOT NULL,",
  "  access_key VARCHAR(100) NOT NULL,",
  "  recovery_code VARCHAR(100) NOT NULL",
  ");",
  "",
  "CREATE TABLE certification_awards (",
  "  award_id INT AUTO_INCREMENT PRIMARY KEY,",
  "  record_id INT NOT NULL,",
  "  badge_code VARCHAR(30) NOT NULL,",
  "  completion_score DECIMAL(5,2) NOT NULL,",
  "  verifier_note VARCHAR(100) NOT NULL",
  ");",
  "",
  "CREATE TABLE support_cases (",
  "  case_id INT AUTO_INCREMENT PRIMARY KEY,",
  "  owner_portal_id VARCHAR(20) NOT NULL,",
  "  case_ref VARCHAR(30) NOT NULL,",
  "  category VARCHAR(80) NOT NULL,",
  "  current_state VARCHAR(30) NOT NULL",
  ");",
  "",
  "INSERT INTO learner_records (portal_id, display_name, program, gpa, advisor_note, access_key, recovery_code) VALUES",
  academyRows.map((row) => {
    return "  ('" + sqlString(row.portalId) + "', '" + sqlString(row.displayName) + "', '" +
      sqlString(row.program) + "', " + row.gpa + ", 'Keep preparing one step at a time.', '" +
      sqlString(row.accessKey) + "', '" + sqlString(row.recovery) + "')";
  }).join(",\n") + ";",
  "",
  "INSERT INTO certification_awards (record_id, badge_code, completion_score, verifier_note) VALUES",
  academyRows.map((row, index) => {
    return "  (" + (index + 1) + ", '" + row.badge + "', " + row.score + ", 'Validated')";
  }).join(",\n") + ";",
  "",
  "INSERT INTO support_cases (owner_portal_id, case_ref, category, current_state) VALUES",
  academyRows.map((row, index) => {
    return "  ('" + row.portalId + "', 'CASE-" + (900 + index) + "', 'Portal access', 'open')";
  }).join(",\n") + ";",
  ""
].join("\n");

const communitySql = [
  "CREATE DATABASE IF NOT EXISTS community_lab;",
  "USE community_lab;",
  "",
  "CREATE TABLE community_user (",
  "  username VARCHAR(100) PRIMARY KEY,",
  "  password VARCHAR(100) NOT NULL,",
  "  display_name VARCHAR(100) NOT NULL",
  ");",
  "",
  "CREATE TABLE community_post (",
  "  id INT AUTO_INCREMENT PRIMARY KEY,",
  "  username VARCHAR(100) NOT NULL,",
  "  message TEXT NOT NULL",
  ");",
  "",
  "INSERT INTO community_user (username, password, display_name) VALUES",
  academyRows.map((row) => {
    return "  ('" + row.username + "', '" + sqlString(row.accessKey) + "', '" +
      sqlString(row.displayName) + "')";
  }).join(",\n") + ";",
  ""
].join("\n");

const initDir = path.join(__dirname, "..", "mysql-init");
fs.writeFileSync(path.join(initDir, "01-academy-schema.sql"), academySql);
fs.writeFileSync(path.join(initDir, "02-community-schema.sql"), communitySql);

console.log("Generated mysql-init/01-academy-schema.sql and mysql-init/02-community-schema.sql");
