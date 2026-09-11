# OWASP 2025 DevSecOps Interactive Lab — A02 + A05

A browser-only security workshop covering **A02:2025 Security Misconfiguration** and **A05:2025 Injection** through five guided attack-and-defense labs.

## Live demo

- GitHub Pages: https://anhgrew.github.io/owasp-2025-devsecops-lab-a02-a05/

The five exercises use the same safe learning loop:

1. Mission
2. Attack
3. Evidence
4. Root cause
5. Defend
6. Regression
7. Knowledge check

Every exploit is deterministic and simulated in the browser. No request is sent to an external target.

## Labs

- L01 — Production debug leakage and missing security headers
- L02 — Kubernetes service-account and RBAC overreach
- L03 — SQL injection and parameterized queries
- L04 — OS command injection and safe process execution
- L05 — NoSQL operator injection and strict typed query construction

Progress is stored only in the visitor's browser under `owasp-a02a05-v2-state`.

## Run locally

Serve the `dist` directory with any static web server. For example:

```bash
python -m http.server 8080 --directory dist
```

Then open `http://localhost:8080`.

## Validate the lab contract

```bash
node test-contract.mjs
```

The contract verifies that all five labs can be opened by deep link and that every guided step renders.

## Deployment

GitHub Pages publishes the static entrypoint from `master / (root)`. The root files mirror the tested assets in `dist` so the project works without a build step or privileged workflow.

## Safety

This project is intentionally isolated and educational. Exploits are simulated locally; it does not scan, attack, or send payloads to external systems.
