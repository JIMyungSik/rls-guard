# 🛡 RLS Guard

**Free Supabase Row Level Security scanner — paste your migration SQL, get an instant audit with fix SQL.**

<p>
  <a href="https://rls-guard-rose.vercel.app"><img alt="Live demo" src="https://img.shields.io/badge/demo-live-3ecf8e"></a>
  <img alt="Client-side only" src="https://img.shields.io/badge/privacy-100%25%20client--side-blue">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-lightgrey">
</p>

### ▶ Try it now: **[rls-guard-rose.vercel.app](https://rls-guard-rose.vercel.app)**

Paste your `supabase/migrations/*.sql` and get findings in milliseconds — no signup, no upload:

![Scan results with severity badges and fix SQL](docs/demo-results.png)

Most Supabase data leaks come from the same handful of misconfigurations: tables exposed without RLS, `USING (true)` policies, INSERT policies without `WITH CHECK`, views that silently bypass RLS. RLS Guard statically scans for 10 of these classes and gives you the **exact fix SQL** for each finding, with a copy button.

## Why client-side matters

A security tool that uploads your schema is itself a security risk. RLS Guard runs **100% in your browser** — your SQL is never uploaded, stored, or logged (verify in the network tab). It even flags service keys or connection strings accidentally pasted into SQL, without storing them.

## Rules

| Rule | Detects | Severity |
|---|---|---|
| RLS-001 | Table in exposed schema without RLS enabled | Critical |
| RLS-002 | RLS enabled but zero policies (silent lockout) | Medium |
| RLS-003 | Always-true policy conditions (`USING (true)`) | High/Critical |
| RLS-004 | INSERT policy missing `WITH CHECK` | High |
| RLS-005 | Owner/tenant column never referenced by any policy | High |
| RLS-006 | Write policies applied to PUBLIC role | High |
| GRANT-001 | Write privileges granted to `anon`/`public` | High |
| FUNC-001 | `SECURITY DEFINER` functions with unpinned search_path | High |
| VIEW-001 | Views without `security_invoker` (RLS bypass) | High |
| SECRET-001 | Service keys / connection strings inside SQL | Critical |

## Run locally

Any static server works:

```bash
npx serve .
```

Or use the engine directly in Node:

```js
import { scanSql } from './scanner.js';
const report = scanSql(mySql);
console.log(report.score, report.findings);
```

## Limitations (honest ones)

Regex-based static analysis on a lightweight SQL splitter — it does not implement the full PostgreSQL grammar, does not reconstruct state across your whole migration history, and does not test live access. **A clean scan is not a security guarantee.** Treat it as a fast first pass, not an audit.

Found a false positive or a rule idea? [Open an issue](../../issues) — feedback directly shapes the ruleset.

## Roadmap

- [ ] GitHub Action — fail CI when a migration introduces a Critical finding
- [ ] Full-history state reconstruction across migration files
- [ ] Storage object policy checks

If any of these would be useful to you, a ⭐ and an issue telling me which one helps prioritize.

## License

MIT
