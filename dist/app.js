"use strict";

const STORAGE_KEY = "owasp-a02a05-v2-state";
const stepNames = ["Mission", "Attack", "Evidence", "Root cause", "Defend", "Regression", "Knowledge check"];
const facilitatorPrompts = [
  ["Frame the risk", "Ask the team to name the asset, attacker-controlled entry point, trust boundary, and business impact before showing a payload."],
  ["Predict before running", "Ask what single input changes, which trusted component interprets it, and what response would prove the hypothesis."],
  ["Separate signal from proof", "Have one participant explain which evidence proves exploitability and which evidence only provides supporting context."],
  ["State the cause in one sentence", "Do not accept ‘bad input’ as the cause. Identify the unsafe configuration, API, query construction, or authorization decision."],
  ["Classify every control", "Label each control as prevention, blast-radius reduction, detection, or recovery—and identify the trusted enforcement point."],
  ["Place the gates", "Ask where each test belongs: unit test, pull request, admission gate, post-deploy smoke test, or runtime alert."],
  ["Defend the answer", "Ask why each distractor fails and what evidence the team would attach to the pull request or incident record."]
];

const labs = {
  "misconfig-debug": {
    topic: "A02 · SECURITY MISCONFIGURATION",
    number: "LAB 01",
    title: "Production Debug Leak",
    level: "Beginner",
    duration: "15 min",
    scenario: "OrderHub returns a framework exception directly to an unauthenticated client. The response discloses internal paths, component context, and security-relevant configuration.",
    mission: "Trigger a controlled error, distinguish useful internal evidence from unsafe external detail, then enforce a stable production error contract.",
    objectives: ["Recognize reconnaissance value in verbose errors", "Separate client response from internal telemetry", "Verify security headers as deployed behavior"],
    asset: "Service internals and deployment context",
    entry: "Malformed public API request",
    boundary: "Exception → HTTP response",
    impact: "Reconnaissance and follow-on attack precision",
    inputLabel: "Request path",
    normalInput: "/api/orders/100",
    attackInput: "/api/orders/not-a-number?debug=true",
    attackHint: "The simulated target intentionally exposes its development exception handler.",
    vulnerableCode: `app.set("env", "development");

app.get("/api/orders/:id", async (req, res) => {
  try {
    const order = await db.order(req.params.id);
    res.json(order);
  } catch (err) {
    res.status(500).json({
      error: err.stack,
      env: process.env
    });
  }
});`,
    secureCode: `app.disable("x-powered-by");
app.use(securityHeaders());

app.use((err, req, res, next) => {
  const errorId = crypto.randomUUID();
  logger.error({ errorId, err, route: req.route });
  res.status(500).json({
    code: "INTERNAL_ERROR",
    errorId
  });
});`,
    rootCause: "The deployment selected a development error handler and serialized process configuration into an external response. The response contract was not regression-tested in production mode.",
    controls: [
      ["Production-safe error handler", "Return a generic code and correlation ID; keep the exception in protected logs."],
      ["Disable debug and sample routes", "Build from an explicit production profile and remove unused surfaces."],
      ["Security header policy", "Set and test CSP, HSTS, nosniff, frame restrictions, and framework banners."],
      ["Deployment smoke test", "Probe the live response contract after every release, not only source configuration."]
    ],
    evidence: [
      ["HTTP 500", "The client receives an internal stack frame and absolute source path.", "DISCLOSURE"],
      ["ENV MAP", "Internal host naming and a simulated key identifier appear in the payload.", "CONTEXT"],
      ["HEADERS", "Framework banner is present; CSP and nosniff are absent.", "HARDENING"],
      ["PIPELINE", "No deployed-response security contract currently blocks this release.", "CONTROL GAP"]
    ],
    tests: [
      ["Malformed identifiers", "Return stable generic error with correlation ID"],
      ["Sensitive token scan", "Response contains no path, query, stack, key, or environment map"],
      ["Header contract", "Required browser directives are present and non-permissive"],
      ["Internal observability", "Protected log retains exception and matching correlation ID"]
    ],
    question: "Which error-handling design preserves operational evidence without helping an external attacker?",
    answers: [
      "Return the full stack trace only when the request has a secret debug query parameter",
      "Return a generic error and correlation ID; log the full exception internally",
      "Remove all error logging and always return HTTP 200",
      "Base64-encode the stack trace before returning it"
    ],
    correct: 1,
    explanation: "A stable generic response limits disclosure. A correlation ID lets operators connect the client event to protected internal evidence. Hidden flags and encoding do not create a trust boundary.",
    normalOutput(input) {
      return `<span class="good">HTTP/1.1 200 OK</span>\ncontent-type: application/json\n\n{ "orderId": "100", "status": "packed" }\n\n# Request remained on the expected code path.`;
    },
    attackOutput(input) {
      return `<span class="bad">HTTP/1.1 500 Internal Server Error</span>\nx-powered-by: Express\n\n{\n  "error": "TypeError: invalid order id\n    at /srv/orderhub/routes/orders.ts:84:17",\n  "DB_HOST": "orders-db.internal",\n  "PAYMENTS_API_KEY": "sk_demo_REDACTED"\n}\n\n<span class="warn">SIMULATION: sensitive context disclosed; no real secret was used.</span>`;
    },
    protectedOutput(input) {
      return `<span class="good">HTTP/1.1 500 Internal Server Error</span>\ncontent-security-policy: default-src 'self'\nx-content-type-options: nosniff\nstrict-transport-security: max-age=31536000\n\n{ "code": "INTERNAL_ERROR", "errorId": "err_demo_71f2" }\n\n<span class="good">PASS: external detail minimized; internal event correlated.</span>`;
    },
    isAttack(input) { return /not-a-number|debug|error|invalid/i.test(input); }
  },

  kubernetes: {
    topic: "A02 · SECURITY MISCONFIGURATION",
    number: "LAB 02",
    title: "Kubernetes Service Account Overreach",
    level: "Intermediate",
    duration: "20 min",
    scenario: "A public diagnostics pod automatically receives the default service-account token. A legacy ClusterRoleBinding grants that identity cluster-admin. Compromising one container now exposes the Kubernetes API trust boundary.",
    mission: "Trace pod identity to effective API permissions, use RBAC evidence to show the blast radius, then replace inherited privilege with a purpose-built service account and an enforcing policy.",
    objectives: ["Connect a pod to its mounted Kubernetes identity", "Read effective RBAC rather than only YAML intent", "Block default-service-account and cluster-admin drift in delivery"],
    asset: "Kubernetes Secrets, workloads, and cluster control plane",
    entry: "Compromised internet-facing container",
    boundary: "Pod token → Kubernetes API authorization",
    impact: "Cluster-wide secret access and workload takeover",
    inputLabel: "Workload identity and binding manifest",
    normalInput: `apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: diagnostics-reader\n  namespace: orderhub\nautomountServiceAccountToken: false\n---\nkind: Role\nrules:\n- apiGroups: [""]\n  resources: ["configmaps"]\n  verbs: ["get"]`,
    attackInput: `apiVersion: v1\nkind: Pod\nmetadata:\n  name: diagnostics\n  namespace: orderhub\nspec:\n  serviceAccountName: default\n  automountServiceAccountToken: true\n---\nkind: ClusterRoleBinding\nsubjects:\n- kind: ServiceAccount\n  name: default\n  namespace: orderhub\nroleRef:\n  kind: ClusterRole\n  name: cluster-admin`,
    attackHint: "The Kubernetes API, token, RBAC commands, and Secret responses are fixed simulations. Nothing is submitted to a real cluster.",
    vulnerableCode: `# Workload inherits a token
serviceAccountName: default
automountServiceAccountToken: true

# Legacy global binding
kind: ClusterRoleBinding
subjects:
- ServiceAccount: orderhub/default
roleRef:
  ClusterRole: cluster-admin

# CI reports this only as a warning`,
    secureCode: `# Identity is explicit and tokenless by default
serviceAccountName: diagnostics-reader
automountServiceAccountToken: false

# Namespace-scoped permission
kind: Role
resources: ["configmaps"]
verbs: ["get"]

# Admission rules
deny default SA · deny cluster-admin binding
# Regression: kubectl auth can-i matrix`,
    rootCause: "The workload inherited a mounted credential and a legacy cluster-wide authorization binding. Review focused on the Pod spec but never verified the service account's effective permissions.",
    controls: [
      ["Purpose-built service account", "Never rely on the namespace default identity; disable token automount when the app does not call the API."],
      ["Namespace-scoped least privilege", "Use Role and RoleBinding for exact resources and verbs; prohibit cluster-admin for workloads."],
      ["Enforcing admission policy", "Reject default service accounts, wildcard RBAC, cluster-admin bindings, and unapproved token mounts."],
      ["Permission regression and runtime audit", "Gate on kubectl auth can-i expectations and alert on Secret listing, exec, and RBAC changes."]
    ],
    evidence: [
      ["POD SPEC", "The default service-account token is automatically mounted into the container.", "CREDENTIAL"],
      ["RBAC GRAPH", "A ClusterRoleBinding connects orderhub/default to cluster-admin.", "EFFECTIVE ACCESS"],
      ["AUTH CHECK", "The compromised identity can list Secrets in every namespace.", "AUTHORIZED"],
      ["AUDIT", "No release gate failed when the high-impact binding was introduced.", "CONTROL GAP"]
    ],
    tests: [
      ["Default identity", "Admission rejects application pods using the default service account"],
      ["Secret permission", "diagnostics-reader cannot get, list, or watch Secrets"],
      ["Allowed operation", "diagnostics-reader may get only the approved ConfigMap"],
      ["Privilege drift", "Any workload binding to cluster-admin fails policy and alerts the platform owner"]
    ],
    question: "The Pod manifest looks ordinary, but its service account can list every Secret. What should the team verify first?",
    answers: [
      "Only the container image vulnerability count",
      "The service account's effective RBAC bindings and token mount",
      "Whether the Pod name contains the namespace",
      "Whether developers can hide the ServiceAccount YAML"
    ],
    correct: 1,
    explanation: "Kubernetes authorization is determined by effective RoleBindings and ClusterRoleBindings. The Pod spec names an identity, but the binding graph defines its power; token mounting determines whether that power is reachable from the container.",
    normalOutput(input) {
      return `<span class="good">IDENTITY REVIEW: PASS</span>\nserviceAccount=diagnostics-reader\nautomountServiceAccountToken=false\n\n$ kubectl auth can-i get configmap/orderhub-diagnostics\n<span class="good">yes</span>\n$ kubectl auth can-i list secrets --all-namespaces\n<span class="good">no</span>\n\nEffective permissions match the workload contract.`;
    },
    attackOutput(input) {
      return `<span class="bad">EFFECTIVE IDENTITY: system:serviceaccount:orderhub:default</span>\ntoken=/var/run/secrets/kubernetes.io/serviceaccount/token\n\n$ kubectl auth can-i --list\n*.*   [*]   [*]   <span class="bad">yes</span>\n$ kubectl get secrets -A\norderhub   payment-api-key\nplatform   registry-pull-secret\n\n<span class="warn">SIMULATION: Secret names are fictional; no cluster was contacted.</span>`;
    },
    protectedOutput(input) {
      return `<span class="good">ADMISSION DENIED</span>\npolicy/no-default-service-account: application pod must declare an approved identity\npolicy/no-workload-cluster-admin: cluster-admin binding is forbidden\n\naudit_id=adm_demo_204\n$ kubectl auth can-i list secrets --as=system:serviceaccount:orderhub:diagnostics-reader\n<span class="good">no</span>\n\n<span class="good">PASS: identity and effective permission both constrained.</span>`;
    },
    isAttack(input) { return /serviceAccountName:\s*default|cluster-admin|automountServiceAccountToken:\s*true|verbs:\s*\[?["']?\*/i.test(input); }
  },

  "sql-injection": {
    topic: "A05 · INJECTION",
    number: "LAB 03",
    title: "SQL Injection",
    level: "Intermediate",
    duration: "20 min",
    scenario: "A customer-support endpoint builds a SQL query by concatenating the customer ID from the request. The database identity can read every tenant record.",
    mission: "Change the predicate without changing application code, observe the data-scope failure, then prove that query structure and data travel separately.",
    objectives: ["Read how a payload changes SQL meaning", "Distinguish validation from parameterization", "Reduce database blast radius and verify negative cases"],
    asset: "Cross-customer account and order records",
    entry: "Customer ID query parameter",
    boundary: "HTTP data → SQL interpreter",
    impact: "Unauthorized data disclosure or modification",
    inputLabel: "Customer ID",
    normalInput: "CUST-100",
    attackInput: "' OR '1'='1",
    attackHint: "This is the classic OWASP learning payload. It is interpreted only by the simulator.",
    vulnerableCode: `const id = req.query.customerId;

const sql =
  "SELECT id, owner, balance " +
  "FROM accounts WHERE customer_id='" + id + "'";

const rows = await db.query(sql);
res.json(rows);`,
    secureCode: `const id = CustomerIdSchema.parse(
  req.query.customerId
);

const sql =
  "SELECT id, owner, balance " +
  "FROM accounts WHERE customer_id = $1";

const rows = await db.query(sql, [id]);
// DB role: SELECT only on approved view`,
    rootCause: "The application joins untrusted data and SQL syntax into one string. The database cannot distinguish developer-authored structure from attacker-authored structure.",
    controls: [
      ["Parameterized query", "Send fixed SQL and bound values separately through the database driver."],
      ["Typed allow-list validation", "Constrain the customer ID format and reject unexpected structure early."],
      ["Least-privilege database role", "Grant the service only required operations and data scope; separate admin functions."],
      ["Negative tests and safe errors", "Replay hostile values and ensure neither data nor database detail is exposed."]
    ],
    evidence: [
      ["SOURCE", "Request data is concatenated between SQL quote characters.", "TAINT PATH"],
      ["QUERY", "The payload closes the value and adds an always-true predicate.", "MEANING CHANGED"],
      ["RESPONSE", "The endpoint returns three simulated customers instead of one.", "DISCLOSURE"],
      ["DATABASE ROLE", "The application identity can read a wider data set than the endpoint needs.", "BLAST RADIUS"]
    ],
    tests: [
      ["Expected identifier", "CUST-100 returns only its authorized record"],
      ["Boolean payload", "Quote and operator sequence is rejected as data"],
      ["Encoded variant", "Equivalent encoded input does not alter query structure"],
      ["Database error", "Client receives no SQL text, driver, schema, or host detail"]
    ],
    question: "What is the strongest primary fix for a query that concatenates untrusted values?",
    answers: [
      "Block the word OR with a regular expression",
      "Hide database errors while keeping the dynamic query",
      "Use a prepared statement with bound parameters",
      "Base64-encode the customer ID before concatenation"
    ],
    correct: 2,
    explanation: "Prepared statements keep SQL structure separate from values. Validation and safe errors are important layers, but neither changes the unsafe query-construction interface by itself.",
    normalOutput(input) {
      const safe = escapeHTML(input);
      return `SQL&gt; SELECT id, owner, balance FROM accounts\n     WHERE customer_id='<span class="good">${safe}</span>'\n\n<span class="good">1 row returned</span>\nACC-100  alice  1250.00`;
    },
    attackOutput(input) {
      const safe = escapeHTML(input);
      return `SQL&gt; SELECT id, owner, balance FROM accounts\n     WHERE customer_id='<span class="bad">${safe}</span>'\n\nPARSER: WHERE customer_id='' OR '1'='1'\n<span class="bad">3 rows returned · expected maximum: 1</span>\nACC-100  alice  1250.00\nACC-101  bob     890.00\nACC-102  chandra 4400.00\n\n<span class="warn">SIMULATION: fictional records only.</span>`;
    },
    protectedOutput(input) {
      const safe = escapeHTML(input);
      return `SQL&gt; SELECT id, owner, balance FROM accounts\n     WHERE customer_id = $1\nBIND&gt; $1 = "<span class="good">${safe}</span>"\n\n<span class="good">0 rows returned · query structure unchanged</span>\napplication_event=input_validation_failed\nNo SQL detail returned to client.`;
    },
    isAttack(input) { return /['";]|\bOR\b|--|\/\*/i.test(input); }
  },

  "command-injection": {
    topic: "A05 · INJECTION",
    number: "LAB 04",
    title: "OS Command Injection",
    level: "Intermediate",
    duration: "20 min",
    scenario: "An internal diagnostics endpoint concatenates a domain name into an nslookup command and executes the string through a shell. The workload has unnecessary filesystem and network permissions.",
    mission: "Introduce a shell metacharacter, trace the second command, then replace shell interpretation with a safe operation and a constrained runtime identity.",
    objectives: ["See why escaping shell strings is fragile", "Prefer a library or argument-array interface", "Use runtime least privilege as impact reduction"],
    asset: "Application host, credentials, and connected services",
    entry: "Diagnostic domain parameter",
    boundary: "HTTP data → command shell",
    impact: "Commands executed as the workload identity",
    inputLabel: "Domain to resolve",
    normalInput: "example.com",
    attackInput: "example.com; cat /etc/passwd",
    attackHint: "No operating-system command is executed. The output is a fixed educational simulation.",
    vulnerableCode: `import { exec } from "node:child_process";

app.get("/diagnose", (req, res) => {
  const command = "nslookup " + req.query.domain;
  exec(command, (error, stdout) => {
    res.type("text").send(stdout);
  });
});`,
    secureCode: `import { resolve4 } from "node:dns/promises";

app.get("/diagnose", async (req, res) => {
  const domain = DomainSchema.parse(
    req.query.domain
  );
  const addresses = await resolve4(domain);
  res.json({ domain, addresses });
});
// no shell · unprivileged UID · restricted egress`,
    rootCause: "The application chooses a shell-string interface even though the business operation is DNS resolution. Shell metacharacters let input create a second command.",
    controls: [
      ["Eliminate shell interpretation", "Use the language DNS library. If an executable is unavoidable, use a fixed binary and argument array."],
      ["Strict domain allow-list", "Validate labels, total length, character set, and intended suffixes server-side."],
      ["Constrained workload identity", "Run as non-root with read-only filesystem, no extra capabilities, and narrow credentials."],
      ["Network and behavior monitoring", "Restrict egress and detect unexpected child processes or command patterns."]
    ],
    evidence: [
      ["INPUT", "A semicolon terminates the intended nslookup command.", "DELIMITER"],
      ["SHELL", "The text after the delimiter is parsed as a second command.", "INTERPRETED"],
      ["OUTPUT", "Simulated local account lines appear after DNS output.", "EXECUTION"],
      ["RUNTIME", "The service identity has more filesystem and network access than DNS resolution requires.", "BLAST RADIUS"]
    ],
    tests: [
      ["Valid FQDN", "Resolver library returns approved DNS result"],
      ["Shell delimiter", "Semicolon sequence fails domain validation"],
      ["Argument variant", "Spaces and command options cannot create new arguments"],
      ["Runtime posture", "No shell package, non-root UID, read-only rootfs, restricted egress"]
    ],
    question: "The endpoint only needs DNS resolution. Which design removes the primary injection risk?",
    answers: [
      "Escape semicolons and continue using exec with a shell string",
      "Call a DNS resolver library with a validated domain value",
      "Rename the /diagnose route",
      "Run the same shell command as root so it completes reliably"
    ],
    correct: 1,
    explanation: "A domain library performs the required operation without invoking a command interpreter. Validation then constrains the domain value, while runtime restrictions reduce residual impact.",
    normalOutput(input) {
      const safe = escapeHTML(input);
      return `$ nslookup <span class="good">${safe}</span>\nServer: 192.0.2.53\nName: ${safe}\nAddress: 192.0.2.80\n\n<span class="good">One intended process modeled.</span>`;
    },
    attackOutput(input) {
      const safe = escapeHTML(input);
      return `$ /bin/sh -c "nslookup <span class="bad">${safe}</span>"\nServer: 192.0.2.53\nName: example.com\nAddress: 192.0.2.80\n\nroot:x:0:0:root:/root:/bin/sh\napp:x:10001:10001:app:/app:/sbin/nologin\n\n<span class="bad">SIMULATED: shell parsed a second command.</span>`;
    },
    protectedOutput(input) {
      const safe = escapeHTML(input);
      return `dns.resolve4("<span class="good">${safe}</span>")\n\n<span class="good">VALIDATION ERROR</span>\ncode=DOMAIN_FORMAT_INVALID\nreason=character ';' is not permitted\nchild_processes=0\nshell_invoked=false\n\n<span class="good">PASS: input never reached a command interpreter.</span>`;
    },
    isAttack(input) { return /[;&|`$()\n\r]|\s-{1,2}\w/i.test(input); }
  },

  "nosql-injection": {
    topic: "A05 · INJECTION",
    number: "LAB 05",
    title: "NoSQL Operator Injection",
    level: "Intermediate",
    duration: "20 min",
    scenario: "OrderHub's JSON login endpoint passes the entire request body into a Mongo-style query. The API accepts objects where the contract requires strings, so an attacker supplies query operators instead of credential values.",
    mission: "Change a JSON value into an operator object, observe how the database filter broadens, then enforce a typed request contract and build the query from fixed fields.",
    objectives: ["Recognize operators hidden inside valid JSON", "Separate API input objects from database query objects", "Place schema, SAST, and negative tests in the pipeline"],
    asset: "Customer accounts and authenticated sessions",
    entry: "JSON login request body",
    boundary: "API object → NoSQL query engine",
    impact: "Authentication bypass and unintended record match",
    inputLabel: "Login JSON body",
    normalInput: `{"email":"alice@example.com","password":"correct-horse-demo"}`,
    attackInput: `{"email":{"$ne":null},"password":{"$ne":null}}`,
    attackHint: "The JSON is parsed only by the browser simulator. No database, account, or authentication service is contacted.",
    vulnerableCode: `app.post("/login", async (req, res) => {
  // req.body becomes the database predicate
  const user = await users.findOne(req.body);

  if (!user) return res.status(401).end();
  return issueSession(user);
});

// API accepts string OR object values`,
    secureCode: `app.post("/login", async (req, res) => {
  const input = LoginSchema.strict().parse(req.body);
  // email/password are required strings
  const user = await users.findOne({ email: input.email });

  if (!user || !verifyHash(input.password, user.hash))
    return genericUnauthorized();
  return issueSession(user);
});`,
    rootCause: "The API request object is reused as a database query object. Because the boundary accepts nested values and operator keys, an attacker can author part of the predicate evaluated by the NoSQL engine.",
    controls: [
      ["Strict typed request schema", "Require email and password to be strings, reject unknown keys, nested objects, and operator-shaped input."],
      ["Fixed query construction", "Build a query from server-selected fields; never pass a request body directly to a driver or ORM."],
      ["Separate password verification", "Fetch the user by normalized identity and compare the password with a dedicated hash-verification function."],
      ["Pipeline and runtime evidence", "Add operator-object regression cases, SAST rules for raw query objects, safe errors, and login anomaly alerts."]
    ],
    evidence: [
      ["REQUEST", "Both credential fields are JSON objects rather than contract-required strings.", "TYPE SHIFT"],
      ["DATA FLOW", "The complete request body becomes the database predicate.", "UNTRUSTED QUERY"],
      ["INTERPRETER", "$ne is evaluated as not-equal rather than stored as data.", "MEANING CHANGED"],
      ["RESPONSE", "The first account matching broad predicates receives a simulated session.", "AUTH BYPASS"]
    ],
    tests: [
      ["Valid credential shape", "Two known string fields reach the authentication service"],
      ["Operator object", "$ne object is rejected by schema before the database call"],
      ["Unknown and dotted keys", "$where, $regex, prototype, and dotted fields are rejected"],
      ["Authentication behavior", "Wrong password returns generic failure and creates no session"]
    ],
    question: "What is the strongest boundary between a JSON API request and a NoSQL query?",
    answers: [
      "Remove only the literal string $ne from the raw request",
      "Base64-encode the JSON before passing it to findOne",
      "Strictly parse typed fields, then construct a fixed query object server-side",
      "Accept every JSON type but hide database error messages"
    ],
    correct: 2,
    explanation: "A strict schema prevents type and key shifts. Building the database predicate from server-selected fields keeps the API object separate from executable query structure.",
    normalOutput(input) {
      const safe = escapeHTML(input);
      return `POST /login\nbody = <span class="good">${safe}</span>\n\nSCHEMA: email=string · password=string\nQUERY: { email: "alice@example.com" }\nPASSWORD HASH: verified\n<span class="good">HTTP 200 · fictional session issued</span>`;
    },
    attackOutput(input) {
      const safe = escapeHTML(input);
      return `POST /login\nbody = <span class="bad">${safe}</span>\n\nDRIVER PREDICATE:\n  email != null\n  password != null\n<span class="bad">MATCH: first record → alice@example.com</span>\nHTTP 200 · session=demo_only\n\n<span class="warn">SIMULATION: no database or real account was used.</span>`;
    },
    protectedOutput(input) {
      const safe = escapeHTML(input);
      return `POST /login\nbody = <span class="good">${safe}</span>\n\n<span class="good">HTTP 400 · REQUEST_SCHEMA_INVALID</span>\npath=email · expected=string · received=object\ndatabase_calls=0\nsessions_created=0\n\n<span class="good">PASS: operator object stopped at the API boundary.</span>`;
    },
    isAttack(input) { return /\$ne|\$gt|\$regex|\$where|__proto__|"[^"\n]+"\s*:\s*\{/i.test(input); }
  }
};

const defaultState = { completed: {}, defense: {}, regression: {}, quiz: {} };
let state = loadState();
let currentView = "overview";
let currentLabId = null;
let currentStep = 0;
const runtime = {};
let toastTimer = null;

function escapeHTML(value) {
  return String(value).replace(/[&<>'"]/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"})[char]);
}

function freshState() {
  return { completed: {}, defense: {}, regression: {}, quiz: {} };
}

function loadState() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
    return parsed && typeof parsed === "object" ? { ...freshState(), ...parsed } : freshState();
  } catch (_) {
    return freshState();
  }
}

function saveState() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch (_) {
    // Embedded or privacy-focused browsers may deny storage. The lab still works in memory.
  }
  updateProgress();
}

function showToast(message) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 2600);
}

function updateProgress() {
  const ids = Object.keys(labs);
  const completed = ids.filter(id => state.completed[id]).length;
  const percent = Math.round((completed / ids.length) * 100);
  document.getElementById("progressText").textContent = `${completed} / ${ids.length} labs complete`;
  document.getElementById("progressFill").style.width = `${percent}%`;
  const ring = document.getElementById("progressRing");
  ring.style.setProperty("--p", `${percent * 3.6}deg`);
  ring.querySelector("span").textContent = `${percent}%`;
  document.getElementById("completionScore").textContent = `${percent}%`;
  const title = document.getElementById("completionTitle");
  const copy = document.getElementById("completionCopy");
  if (completed === 0) {
    title.textContent = "Begin with any lab";
    copy.textContent = "A lab completes only after its hardened regression suite passes and the knowledge check is answered correctly.";
  } else if (completed < ids.length) {
    title.textContent = `${completed} lab${completed === 1 ? "" : "s"} verified — keep going`;
    copy.textContent = "Your attack observations, defense state, and completion status remain on this device.";
  } else {
    title.textContent = "Workshop complete — all controls verified";
    copy.textContent = "You completed five safe attack-and-defense loops across A02 and A05.";
  }
  document.querySelectorAll("[data-lab-card]").forEach(card => {
    const id = card.dataset.labCard;
    card.classList.toggle("complete", Boolean(state.completed[id]));
    card.querySelector("[data-lab-status]").textContent = state.completed[id] ? "VERIFIED ✓" : state.defense[id] ? "HARDENING APPLIED" : "NOT STARTED";
  });
}

function showView(name, updateHash = true) {
  currentView = name;
  document.querySelectorAll("[data-view-panel]").forEach(panel => panel.classList.toggle("active", panel.dataset.viewPanel === name));
  document.querySelectorAll(".nav-item").forEach(item => item.classList.toggle("active", item.dataset.view === name));
  document.getElementById("sidebar").classList.remove("open");
  document.getElementById("mobileMenu").setAttribute("aria-expanded", "false");
  if (updateHash && name !== "lab") history.replaceState(null, "", `#${name}`);
  window.scrollTo({ top: 0, behavior: "smooth" });
  document.getElementById("mainContent").focus({ preventScroll: true });
}

function ensureRuntime(id) {
  if (!runtime[id]) runtime[id] = { input: labs[id].normalInput, attackRun: false, attackWasMalicious: false, visited: {0:true}, checked: new Set(), testRunning: false };
  return runtime[id];
}

function openLab(id) {
  if (!labs[id]) return;
  currentLabId = id;
  currentStep = 0;
  ensureRuntime(id);
  renderLab();
  showView("lab-workspace", false);
  history.replaceState(null, "", `#lab/${id}`);
}

function stepComplete(id, step) {
  const rt = ensureRuntime(id);
  if (step <= 3) return Boolean(rt.visited[step]);
  if (step === 4) return Boolean(state.defense[id]);
  if (step === 5) return Boolean(state.regression[id]);
  return Boolean(state.quiz[id]);
}

function renderLab() {
  const lab = labs[currentLabId];
  const rt = ensureRuntime(currentLabId);
  rt.visited[currentStep] = true;
  const workspace = document.getElementById("labWorkspace");
  workspace.innerHTML = `
    <div class="workspace-shell">
      <header class="workspace-header">
        <button class="back-button" id="backToLabs" aria-label="Back to lab deck">←</button>
        <div class="workspace-title"><span>${lab.topic} · ${lab.number}</span><h1>${lab.title}</h1></div>
        <button class="reset-lab-button" id="resetLab">Reset this lab</button>
        <div class="workspace-meta">${lab.duration} · ${lab.level} · browser simulation</div>
      </header>
      <nav class="step-rail" aria-label="Lab steps">
        ${stepNames.map((name,index) => `<button data-step="${index}" class="${index === currentStep ? "active" : ""} ${stepComplete(currentLabId,index) ? "done" : ""}"><span>${stepComplete(currentLabId,index) ? "✓" : String(index+1).padStart(2,"0")}</span><b>${name}</b></button>`).join("")}
      </nav>
      <div class="workspace-content">
        <aside class="brief-panel">
          <span class="lab-kicker">${stepNames[currentStep].toUpperCase()}</span>
          <h2>${stepHeading(lab,currentStep)}</h2>
          <p>${stepBrief(lab,currentStep)}</p>
          ${currentStep === 0 ? `<ul class="objective-list">${lab.objectives.map(x=>`<li>${x}</li>`).join("")}</ul>` : rootCauseNote(lab,currentStep)}
          <div class="scope-card"><span>LAB BOUNDARY</span><p>${lab.attackHint}</p></div>
          <div class="facilitator-card"><span>FACILITATOR CUE</span><b>${facilitatorPrompts[currentStep][0]}</b><p>${facilitatorPrompts[currentStep][1]}</p></div>
        </aside>
        <section class="action-panel">
          <header><span>CONTROLLED RANGE / ${lab.number}</span><b>${currentStep === 1 ? "VULNERABLE" : state.defense[currentLabId] ? "HARDENED" : "LEARNING"}</b></header>
          <div class="action-body">${renderStepBody(lab,rt,currentStep)}</div>
        </section>
      </div>
      <footer class="workspace-footer">
        <button id="previousStep" ${currentStep === 0 ? "disabled" : ""}>← Previous</button>
        <span class="step-proof">${proofText(currentLabId,currentStep)}</span>
        <button id="nextStep">${currentStep === 6 ? "Return to lab deck" : "Next step →"}</button>
      </footer>
    </div>`;
  bindLabEvents();
}

function stepHeading(lab, step) {
  return [lab.mission,"Change one controlled input","Collect proof, not intuition","Find the trust-boundary failure","Apply layered controls","Replay the hostile cases","Choose the root-cause control"][step];
}

function stepBrief(lab, step) {
  return [lab.scenario,"Run the normal value first, then load the supplied attack value. The simulator models how the vulnerable implementation interprets both.","Use the response, data-flow, effective permissions, and missing gate to explain impact. A payload alone is not a complete finding.",lab.rootCause,"Select every control, then apply the hardened design. Primary prevention and blast-radius reduction belong together.","The same hostile values become regression cases. A release should fail if secure behavior changes or the protection disappears.",lab.question][step];
}

function rootCauseNote(lab, step) {
  if (step === 3) return `<div class="scope-card"><span>REVIEW QUESTION</span><p>At what point did untrusted data or unsafe deployment intent cross into a trusted execution decision?</p></div>`;
  if (step === 4) return `<ul class="objective-list"><li>Prevent the unsafe interpretation or deployment</li><li>Reduce the identity and network blast radius</li><li>Generate automated, reviewable evidence</li></ul>`;
  if (step === 5) return `<ul class="objective-list">${lab.tests.map(x=>`<li>${x[0]}</li>`).join("")}</ul>`;
  if (step === 6) return `<div class="scope-card"><span>COMPLETION RULE</span><p>Pass the hardened regression suite and answer correctly to mark this lab verified.</p></div>`;
  return "";
}

function renderStepBody(lab, rt, step) {
  if (step === 0) return `
    <div class="mission-map">
      <div class="mission-node"><span>ASSET</span><b>${lab.asset}</b><p>What the system must protect.</p></div><i>→</i>
      <div class="mission-node"><span>ENTRY / BOUNDARY</span><b>${lab.entry}</b><p>${lab.boundary}</p></div><i>→</i>
      <div class="mission-node"><span>IMPACT</span><b>${lab.impact}</b><p>What changes when the control fails.</p></div>
    </div>`;
  if (step === 1) return `
    <div class="input-group"><label for="payloadInput">${lab.inputLabel}</label><textarea class="payload-input" id="payloadInput" spellcheck="false">${escapeHTML(rt.input)}</textarea></div>
    <div class="payload-actions"><button class="lab-button" id="loadNormal">Load normal value</button><button class="lab-button attack" id="loadAttack">Load attack value</button><button class="lab-button attack" id="runAttack">Run on vulnerable simulator</button></div>
    <div class="terminal"><header><i></i><i></i><i></i><span>simulated-target.output</span></header><pre id="terminalOutput">${rt.attackRun ? rt.output : "Ready. Run the normal request, then change one input."}</pre></div>`;
  if (step === 2) return `<div class="evidence-timeline">${lab.evidence.map((row,index)=>`<div class="evidence-row"><span>0${index+1}</span><div><b>${row[0]}</b><p>${row[1]}</p></div><i>${row[2]}</i></div>`).join("")}</div>`;
  if (step === 3) return `<div class="code-diff"><article class="code-card bad"><header><span>VULNERABLE PATH</span><span>−</span></header><pre>${escapeHTML(lab.vulnerableCode)}</pre><footer>${escapeHTML(lab.rootCause)}</footer></article><article class="code-card good"><header><span>HARDENED PATH</span><span>+</span></header><pre>${escapeHTML(lab.secureCode)}</pre><footer>Move the security decision into a safe, repeatable interface and verify effective behavior.</footer></article></div>`;
  if (step === 4) return `
    <div class="control-checklist">${lab.controls.map((control,index)=>`<label class="control-option"><input type="checkbox" data-control="${index}" ${rt.checked.has(index) || state.defense[currentLabId] ? "checked" : ""} ${state.defense[currentLabId] ? "disabled" : ""}><span><b>${control[0]}</b><small>${control[1]}</small></span></label>`).join("")}</div>
    <div class="defense-status ${state.defense[currentLabId] ? "ready" : ""}"><span>${state.defense[currentLabId] ? "Hardened configuration applied to the simulator." : "Select all four controls to apply the hardened design."}</span><button class="lab-button secure" id="applyDefense" ${state.defense[currentLabId] ? "disabled" : ""}>${state.defense[currentLabId] ? "Applied ✓" : "Apply defense"}</button></div>
    ${state.defense[currentLabId] ? `<div class="terminal"><header><i></i><i></i><i></i><span>hardened-target.preview</span></header><pre>${lab.protectedOutput(rt.input || lab.attackInput)}</pre></div>` : ""}`;
  if (step === 5) return `
    <div class="test-suite" id="testSuite">${lab.tests.map((test,index)=>`<div class="test-row ${state.regression[currentLabId] ? "pass" : ""}" data-test="${index}"><i class="test-icon">${state.regression[currentLabId] ? "✓" : "·"}</i><div><b>${test[0]}</b><small>${test[1]}</small></div><span>${state.regression[currentLabId] ? "PASS" : "PENDING"}</span></div>`).join("")}</div>
    <div class="payload-actions"><button class="lab-button secure" id="runTests" ${rt.testRunning ? "disabled" : ""}>${state.regression[currentLabId] ? "Run suite again" : "Run hardened regression suite"}</button></div>
    ${!state.defense[currentLabId] ? `<div class="defense-status"><span>Defense is not applied. The negative security cases are expected to fail.</span></div>` : ""}`;
  if (step === 6) return `
    <div class="quiz-box"><div class="quiz-question">${lab.question}</div>${lab.answers.map((answer,index)=>`<button class="quiz-option ${state.quiz[currentLabId] && index === lab.correct ? "correct" : ""}" data-answer="${index}"><b>${String.fromCharCode(65+index)}.</b> ${answer}</button>`).join("")}<div class="quiz-explanation" id="quizExplanation">${state.quiz[currentLabId] ? lab.explanation : "Choose one answer. The explanation appears after your selection."}</div></div>`;
  return "";
}

function proofText(id, step) {
  if (step === 4) return state.defense[id] ? "Defense applied ✓" : "Defense not yet applied";
  if (step === 5) return state.regression[id] ? "Regression verified ✓" : "Regression pending";
  if (step === 6) return state.completed[id] ? "Lab complete ✓" : "Knowledge check pending";
  return `Step ${step + 1} of 7`;
}

function bindLabEvents() {
  document.getElementById("backToLabs").addEventListener("click", () => showView("labs"));
  document.getElementById("resetLab").addEventListener("click", () => {
    delete state.completed[currentLabId];
    delete state.defense[currentLabId];
    delete state.regression[currentLabId];
    delete state.quiz[currentLabId];
    delete runtime[currentLabId];
    currentStep = 0;
    saveState();
    renderLab();
    showToast("Lab reset. Begin again from the mission.");
  });
  document.querySelectorAll("[data-step]").forEach(button => button.addEventListener("click", () => { currentStep = Number(button.dataset.step); renderLab(); window.scrollTo(0,0); }));
  document.getElementById("previousStep").addEventListener("click", () => { if (currentStep > 0) { currentStep--; renderLab(); window.scrollTo(0,0); } });
  document.getElementById("nextStep").addEventListener("click", () => {
    if (currentStep < 6) { currentStep++; renderLab(); window.scrollTo(0,0); }
    else showView("labs");
  });
  if (currentStep === 1) bindAttackEvents();
  if (currentStep === 4) bindDefenseEvents();
  if (currentStep === 5) bindRegressionEvents();
  if (currentStep === 6) bindQuizEvents();
}

function bindAttackEvents() {
  const lab = labs[currentLabId];
  const rt = ensureRuntime(currentLabId);
  const input = document.getElementById("payloadInput");
  const output = document.getElementById("terminalOutput");
  const load = value => { input.value = value; rt.input = value; rt.attackRun = false; output.textContent = "Value loaded. Run it against the vulnerable simulator."; };
  document.getElementById("loadNormal").addEventListener("click", () => load(lab.normalInput));
  document.getElementById("loadAttack").addEventListener("click", () => load(lab.attackInput));
  input.addEventListener("input", () => { rt.input = input.value; });
  document.getElementById("runAttack").addEventListener("click", () => {
    rt.input = input.value;
    rt.attackWasMalicious = lab.isAttack(rt.input);
    rt.attackRun = true;
    rt.output = rt.attackWasMalicious ? lab.attackOutput(rt.input) : lab.normalOutput(rt.input);
    output.innerHTML = rt.output;
    showToast(rt.attackWasMalicious ? "Vulnerable behavior reproduced in the safe simulator." : "Normal behavior established. Now load the attack value.");
  });
}

function bindDefenseEvents() {
  const rt = ensureRuntime(currentLabId);
  document.querySelectorAll("[data-control]").forEach(box => box.addEventListener("change", () => {
    const index = Number(box.dataset.control);
    if (box.checked) rt.checked.add(index); else rt.checked.delete(index);
  }));
  const button = document.getElementById("applyDefense");
  if (!button || button.disabled) return;
  button.addEventListener("click", () => {
    if (rt.checked.size !== labs[currentLabId].controls.length) {
      showToast("Select all four layers before applying the hardened design.");
      return;
    }
    state.defense[currentLabId] = true;
    state.regression[currentLabId] = false;
    saveState();
    renderLab();
    showToast("Defense applied. Continue to regression and replay the hostile cases.");
  });
}

function bindRegressionEvents() {
  const button = document.getElementById("runTests");
  const rt = ensureRuntime(currentLabId);
  button.addEventListener("click", () => {
    if (rt.testRunning) return;
    rt.testRunning = true;
    button.disabled = true;
    button.textContent = "Running deterministic suite…";
    const rows = [...document.querySelectorAll(".test-row")];
    rows.forEach((row,index) => {
      row.className = "test-row";
      row.querySelector(".test-icon").textContent = "…";
      row.querySelector(":scope > span").textContent = "RUNNING";
      setTimeout(() => {
        const pass = Boolean(state.defense[currentLabId]);
        row.classList.add(pass ? "pass" : "fail");
        row.querySelector(".test-icon").textContent = pass ? "✓" : "×";
        row.querySelector(":scope > span").textContent = pass ? "PASS" : "FAIL";
      }, 250 + index * 180);
    });
    setTimeout(() => {
      rt.testRunning = false;
      if (state.defense[currentLabId]) {
        state.regression[currentLabId] = true;
        maybeComplete(currentLabId);
        saveState();
        renderLab();
        showToast("Regression suite passed. Hardened behavior is now verified.");
      } else {
        button.disabled = false;
        button.textContent = "Apply defense, then rerun";
        showToast("Expected failure: apply the defense before verifying the hardened target.");
      }
    }, 350 + rows.length * 180);
  });
}

function bindQuizEvents() {
  const lab = labs[currentLabId];
  document.querySelectorAll("[data-answer]").forEach(button => button.addEventListener("click", () => {
    const chosen = Number(button.dataset.answer);
    document.querySelectorAll("[data-answer]").forEach(x => x.classList.remove("correct","wrong"));
    if (chosen === lab.correct) {
      button.classList.add("correct");
      state.quiz[currentLabId] = true;
      document.getElementById("quizExplanation").textContent = lab.explanation;
      maybeComplete(currentLabId);
      saveState();
      showToast(state.completed[currentLabId] ? "Lab verified — regression and knowledge check complete." : "Correct. Pass regression to complete the lab.");
      setTimeout(renderLab, 650);
    } else {
      button.classList.add("wrong");
      document.getElementById("quizExplanation").textContent = "Not quite. Identify the control that changes the unsafe trust-boundary decision, then try again.";
    }
  }));
}

function maybeComplete(id) {
  state.completed[id] = Boolean(state.regression[id] && state.quiz[id]);
}

function initialRoute() {
  const hash = location.hash.replace(/^#/, "");
  if (hash.startsWith("lab/")) {
    const id = hash.split("/")[1];
    if (labs[id]) return openLab(id);
  }
  showView(document.querySelector(`[data-view-panel="${hash}"]`) ? hash : "overview", false);
}

document.querySelectorAll(".nav-item").forEach(button => button.addEventListener("click", () => showView(button.dataset.view)));
document.querySelectorAll("[data-view-jump]").forEach(button => button.addEventListener("click", () => {
  const labId = button.dataset.openLab;
  if (labId) openLab(labId); else showView(button.dataset.viewJump);
}));
document.querySelectorAll("[data-view-link]").forEach(link => link.addEventListener("click", event => { event.preventDefault(); showView(link.dataset.viewLink); }));
document.querySelectorAll("[data-launch-lab]").forEach(button => button.addEventListener("click", () => openLab(button.dataset.launchLab)));
document.getElementById("mobileMenu").addEventListener("click", event => {
  const sidebar = document.getElementById("sidebar");
  const open = sidebar.classList.toggle("open");
  event.currentTarget.setAttribute("aria-expanded", String(open));
});
document.getElementById("glossaryButton").addEventListener("click", () => document.getElementById("glossaryDialog").showModal());
document.getElementById("focusButton").addEventListener("click", () => document.body.classList.toggle("focus-mode"));
document.addEventListener("keydown", event => {
  const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "");
  if (typing) return;
  if (event.key.toLowerCase() === "g") document.getElementById("glossaryDialog").showModal();
  if (event.key.toLowerCase() === "l") showView("labs");
  if (event.key.toLowerCase() === "f") document.body.classList.toggle("focus-mode");
  if (event.key === "Escape") document.getElementById("sidebar").classList.remove("open");
});
window.addEventListener("hashchange", initialRoute);

updateProgress();
initialRoute();
