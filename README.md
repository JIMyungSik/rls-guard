# 🛡 RLS Guard

**Free Supabase Row Level Security scanner — paste your migration SQL, get an instant audit.**

**Try it: [rls-guard-rose.vercel.app](https://rls-guard-rose.vercel.app)**

Most Supabase data leaks come from the same handful of misconfigurations: tables exposed without RLS, `USING (true)` policies, INSERT policies without `WITH CHECK`, views that silently bypass RLS. RLS Guard statically scans your `supabase/migrations/*.sql` for 10 of these classes and gives you the exact fix SQL for each finding.

## Privacy

The scanner runs **100% client-side**. Your SQL is never uploaded, stored, or logged — verify in your browser's network tab. It also flags service keys or connection strings accidentally pasted into SQL (without storing them).

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

## Limitations

Regex-based static analysis on a lightweight SQL splitter — it does not implement the full PostgreSQL grammar, does not reconstruct state across your whole migration history, and does not test live access. **A clean scan is not a security guarantee.**

## License

MIT
