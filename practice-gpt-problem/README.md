# Advanced Localhost Web-Security Practice Lab

This repository is a deliberately vulnerable Docker lab for university exam
practice. It keeps the same pipeline as the first practice problem:

~~~text
browser -> Node/Express application -> MySQL
~~~

The names, table layouts, column counts, routes, and task goals are different.
The lab deliberately includes multiple tables, a blind-only page, and a
cross-application stored-XSS-to-CSRF chain.

Only use it on the Docker instance you run yourself. Do not deploy it publicly
or use its techniques against a system without explicit authorization.

## Learning goals

- Determine query shape instead of assuming a column count.
- Find visible UNION output columns and respect data types.
- Enumerate and join multiple MySQL tables.
- Recognize a Boolean-blind SQL injection channel.
- Understand the difference between raw and escaped HTML output.
- Distinguish CORS, cookies, SameSite, and CSRF tokens.
- Build and explain a stored XSS -> CSRF chain.
- Recommend code-level defenses.

## Setup

Requirements:

- Docker and Docker Compose
- Node.js 20 or a recent Node version

From this directory:

~~~powershell
node scripts/generate-seed.js
docker compose up --build
~~~

If your Docker installation provides the standalone Compose command instead,
use:

~~~powershell
docker-compose up --build
~~~

Open:

~~~text
Academy Progress Portal: http://localhost:3100
Study Community:        http://localhost:3101
~~~

Authorized test identity:

| Use | Username / ID | Password |
|---|---|---|
| Academy Progress Portal | P-4102 | Saira#42 |
| Study Community | saira_khan | Saira#42 |

The generator creates new GPA values and recovery codes on every reset. Do not
read the generated SQL files before attempting the tasks if you want genuine
exam conditions.

Reset the lab:

~~~powershell
docker compose down
node scripts/generate-seed.js
docker compose up --build
~~~

Replace docker compose with docker-compose in all commands if that is the
Compose command installed on your computer.

## Rules

1. Conduct the graded path as P-4102 / Saira#42 and saira_khan / Saira#42.
2. Do not directly log into other Academy accounts.
3. You may use another listed Community account in a second browser profile only
   to verify whether a stored payload runs for a logged-in viewer.
4. Do not inspect generated seed SQL until you have attempted the exercise.
5. Use reset instead of trying to clean up database changes manually.

## Tasks

### Task 1 — Multi-table UNION extraction

Log in only as P-4102. Through the Progress Portal, retrieve a readable list
of every learner's:

~~~text
Portal ID | Display name | Badge code | Completion score
~~~

Requirements:

- use one injection entry point;
- discover the query column count yourself;
- discover which selected values are visible;
- find the relevant tables and columns rather than relying on names in this
  README;
- combine data from more than one table;
- handle output truncation if it occurs.

### Task 2 — Boolean-blind recovery code

The Helpdesk lookup returns only one of two messages:

~~~text
Case status is available.
No matching case.
~~~

No case details are printed. As P-4102, use this Boolean difference to infer:

1. the length of your own recovery code;
2. its first four characters.

Do not read the generated seed SQL. The point is to practice a blind inference
loop, not direct output extraction.

### Task 3 — Stored XSS to CSRF

Acting as P-4102 on the Academy Portal and saira_khan on Study Community, make
the normal act of viewing Saira's progress record publish this exact message on
Saira's Community feed:

~~~text
Checkpoint: <Saira's GPA>
~~~

No manual Community publish action may be used for the final proof.

Hints:

- identify a field that can be modified through the Academy injection;
- identify where that field is rendered;
- compare the Academy renderer with the Community renderer;
- inspect the Community publish request in DevTools;
- distinguish CORS response access from whether a simple request is sent.

### Task 4 — Defensive code review

Write a short remediation report with:

1. the vulnerable Academy SQL construction;
2. the dangerous HTML rendering sink;
3. why the Community publish endpoint is CSRF vulnerable;
4. a parameterized SQL fix;
5. an output-encoding fix;
6. a CSRF-token design;
7. two defense-in-depth improvements.

## Suggested exam workflow

~~~text
baseline -> identify input context -> prove a small hypothesis
-> map output -> obtain the minimum required data/action
-> independently verify -> explain impact -> give the fix
~~~

Read SOLUTION_GUIDE.md only after making your own attempt.
