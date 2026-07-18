// RLS Guard — Supabase SQL security scanner (browser build, English)
// Ported from rls-guard 0.1 CLI. Runs 100% client-side.

const SEVERITY_WEIGHT = { critical: 30, high: 18, medium: 8, low: 3 };

function normalizeIdentifier(value) {
  return value.replaceAll('"', '').trim().toLowerCase();
}

function qualifyTable(raw) {
  const value = normalizeIdentifier(raw);
  return value.includes('.') ? value : `public.${value}`;
}

function splitStatements(sql) {
  const statements = [];
  let current = '';
  let quote = null;
  let dollarTag = null;

  for (let i = 0; i < sql.length; i += 1) {
    const char = sql[i];
    const rest = sql.slice(i);

    if (!quote && !dollarTag) {
      const tag = rest.match(/^\$[A-Za-z0-9_]*\$/)?.[0];
      if (tag) {
        dollarTag = tag;
        current += tag;
        i += tag.length - 1;
        continue;
      }
    } else if (dollarTag && rest.startsWith(dollarTag)) {
      current += dollarTag;
      i += dollarTag.length - 1;
      dollarTag = null;
      continue;
    }

    if (!dollarTag && (char === "'" || char === '"')) {
      if (quote === char && sql[i + 1] === char) {
        current += char + char;
        i += 1;
        continue;
      }
      quote = quote === char ? null : quote || char;
    }

    if (char === ';' && !quote && !dollarTag) {
      if (current.trim()) statements.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }

  if (current.trim()) statements.push(current.trim());
  return statements;
}

function extractModel(sql) {
  const statements = splitStatements(sql);
  const tables = new Map();
  const policies = [];
  const grants = [];
  const functions = [];
  const views = [];

  const ensureTable = (name) => {
    const qualified = qualifyTable(name);
    if (!tables.has(qualified)) {
      tables.set(qualified, {
        name: qualified,
        created: false,
        rlsEnabled: false,
        rlsForced: false,
        columns: [],
        source: null
      });
    }
    return tables.get(qualified);
  };

  for (const statement of statements) {
    const compact = statement.replace(/--.*$/gm, ' ').replace(/\s+/g, ' ').trim();
    const createTable = compact.match(/create\s+table\s+(?:if\s+not\s+exists\s+)?([\w".]+)\s*\(([^]*)\)$/i);
    if (createTable) {
      const table = ensureTable(createTable[1]);
      table.created = true;
      table.source = compact;
      table.columns = [...createTable[2].matchAll(/(?:^|,)\s*"?([a-zA-Z_][\w]*)"?\s+[a-zA-Z]/g)].map((m) => m[1].toLowerCase());
      continue;
    }

    const alterRls = compact.match(/alter\s+table\s+(?:only\s+)?([\w".]+)\s+(enable|disable|force|no\s+force)\s+row\s+level\s+security/i);
    if (alterRls) {
      const table = ensureTable(alterRls[1]);
      const operation = alterRls[2].toLowerCase();
      if (operation === 'enable') table.rlsEnabled = true;
      if (operation === 'disable') table.rlsEnabled = false;
      if (operation === 'force') table.rlsForced = true;
      if (operation === 'no force') table.rlsForced = false;
      continue;
    }

    const policy = compact.match(/create\s+policy\s+(?:"([^"]+)"|([\w-]+))\s+on\s+([\w".]+)([^]*)/i);
    if (policy) {
      const tail = policy[4];
      policies.push({
        name: policy[1] || policy[2],
        table: qualifyTable(policy[3]),
        command: tail.match(/\bfor\s+(select|insert|update|delete|all)\b/i)?.[1]?.toLowerCase() || 'all',
        roles: tail.match(/\bto\s+(.+?)(?=\s+using\b|\s+with\s+check\b|$)/i)?.[1]?.split(',').map(normalizeIdentifier) || ['public'],
        using: tail.match(/\busing\s*\(([^]*)\)(?=\s+with\s+check\b|$)/i)?.[1]?.trim() || null,
        check: tail.match(/\bwith\s+check\s*\(([^]*)\)$/i)?.[1]?.trim() || null,
        source: compact
      });
      ensureTable(policy[3]);
      continue;
    }

    const grant = compact.match(/grant\s+(.+?)\s+on\s+(?:table\s+)?([\w".]+)\s+to\s+(.+)$/i);
    if (grant) {
      grants.push({
        privileges: grant[1].split(',').map(normalizeIdentifier),
        table: qualifyTable(grant[2]),
        roles: grant[3].split(',').map(normalizeIdentifier),
        source: compact
      });
      ensureTable(grant[2]);
      continue;
    }

    const fn = compact.match(/create\s+(?:or\s+replace\s+)?function\s+([\w".]+)[^]*$/i);
    if (fn) {
      functions.push({
        name: normalizeIdentifier(fn[1]),
        securityDefiner: /security\s+definer/i.test(compact),
        searchPathFixed: /set\s+search_path\s*=/i.test(compact),
        source: compact
      });
      continue;
    }

    const view = compact.match(/create\s+(?:or\s+replace\s+)?view\s+([\w".]+)([^]*)/i);
    if (view) {
      views.push({
        name: qualifyTable(view[1]),
        securityInvoker: /security_invoker\s*=\s*(?:true|on)/i.test(compact),
        source: compact
      });
    }
  }

  return { statements, tables: [...tables.values()], policies, grants, functions, views };
}

function finding(ruleId, severity, title, target, evidence, remediation, confidence = 'high') {
  return { ruleId, severity, title, target, evidence, remediation, confidence };
}

function runRules(model, rawSql) {
  const findings = [];
  const exposedSchemas = new Set(['public', 'storage', 'graphql_public']);

  for (const table of model.tables.filter((item) => item.created)) {
    const schema = table.name.split('.')[0];
    const tablePolicies = model.policies.filter((policy) => policy.table === table.name);

    if (exposedSchemas.has(schema) && !table.rlsEnabled) {
      findings.push(finding(
        'RLS-001', 'critical', 'RLS is disabled on a table in an exposed schema.', table.name,
        `Table ${table.name} is created but there is no ENABLE ROW LEVEL SECURITY statement. Anyone with the anon key can read or write every row through the auto-generated API.`,
        `ALTER TABLE ${table.name} ENABLE ROW LEVEL SECURITY;`
      ));
    } else if (table.rlsEnabled && tablePolicies.length === 0) {
      findings.push(finding(
        'RLS-002', 'medium', 'RLS is enabled but no policies exist.', table.name,
        'All access from regular users is blocked, which usually surfaces as a broken feature rather than a security hole.',
        `-- Review your access rules, then add SELECT/INSERT/UPDATE/DELETE policies for ${table.name}.`
      ));
    }

    const ownershipColumns = table.columns.filter((column) => ['user_id', 'owner_id', 'tenant_id', 'organization_id', 'workspace_id'].includes(column));
    if (ownershipColumns.length && tablePolicies.length) {
      for (const policy of tablePolicies) {
        const expression = `${policy.using || ''} ${policy.check || ''}`.toLowerCase();
        if (!ownershipColumns.some((column) => expression.includes(column))) {
          findings.push(finding(
            'RLS-005', 'high', 'Owner/tenant column is not referenced in the policy condition.', `${table.name} / ${policy.name}`,
            `The table has ${ownershipColumns.join(', ')} column(s), but the policy condition never checks them. Users may be able to reach rows they do not own.`,
            `-- Example: USING ((SELECT auth.uid()) = ${ownershipColumns[0]})`, 'medium'
          ));
        }
      }
    }
  }

  for (const policy of model.policies) {
    if (/^\s*(true|1\s*=\s*1)\s*$/i.test(policy.using || '') || /^\s*(true|1\s*=\s*1)\s*$/i.test(policy.check || '')) {
      const writable = ['insert', 'update', 'delete', 'all'].includes(policy.command);
      findings.push(finding(
        'RLS-003', writable ? 'critical' : 'high', 'Policy condition allows every row.', `${policy.table} / ${policy.name}`,
        `The ${policy.command.toUpperCase()} policy contains an always-true condition, which disables row filtering entirely.`,
        '-- Replace true with a real condition using auth.uid(), tenant_id, or an explicit public-visibility flag.'
      ));
    }

    if (policy.command === 'insert' && !policy.check) {
      findings.push(finding(
        'RLS-004', 'high', 'INSERT policy has no WITH CHECK clause.', `${policy.table} / ${policy.name}`,
        'New rows are not validated, so a user may be able to insert rows with someone else\'s user_id or tenant_id.',
        'WITH CHECK ((SELECT auth.uid()) = user_id)', 'medium'
      ));
    }

    if (policy.roles.includes('public') && ['insert', 'update', 'delete', 'all'].includes(policy.command)) {
      findings.push(finding(
        'RLS-006', 'high', 'Write policy applies to the PUBLIC role.', `${policy.table} / ${policy.name}`,
        'Omitting the TO clause makes the policy apply to PUBLIC, which includes anonymous users.',
        '-- Add TO authenticated (or a restricted DB role) to match your intent.'
      ));
    }
  }

  for (const grant of model.grants) {
    const dangerous = grant.privileges.filter((p) => ['insert', 'update', 'delete', 'truncate', 'all privileges', 'all'].includes(p));
    if (grant.roles.some((role) => ['anon', 'public'].includes(role)) && dangerous.length) {
      findings.push(finding(
        'GRANT-001', 'high', 'Write privileges are granted to the anonymous role.', grant.table,
        `Role(s) ${grant.roles.join(', ')} were granted ${dangerous.join(', ')}. Combined with a weak policy this becomes directly exploitable.`,
        `REVOKE ${dangerous.join(', ').toUpperCase()} ON ${grant.table} FROM ${grant.roles.join(', ')};`
      ));
    }
  }

  for (const fn of model.functions.filter((item) => item.securityDefiner && !item.searchPathFixed)) {
    findings.push(finding(
      'FUNC-001', 'high', 'SECURITY DEFINER function without a pinned search_path.', fn.name,
      'A caller can abuse object resolution order to escalate privileges through this function.',
      `ALTER FUNCTION ${fn.name} SET search_path = pg_catalog, public;`, 'medium'
    ));
  }

  for (const view of model.views.filter((item) => !item.securityInvoker)) {
    findings.push(finding(
      'VIEW-001', 'high', 'View may bypass RLS on its base tables.', view.name,
      'No security_invoker option was found. By default the view runs with the owner\'s privileges, skipping RLS.',
      `-- PostgreSQL 15+: CREATE VIEW ${view.name} WITH (security_invoker = true) AS ...`, 'medium'
    ));
  }

  const secretPatterns = [
    { name: 'Supabase secret/service key', regex: /\b(?:sb_secret_[A-Za-z0-9_-]{12,}|service_role\s*[=:]\s*["']?[A-Za-z0-9._-]{16,})/gi },
    { name: 'PostgreSQL connection string', regex: /postgres(?:ql)?:\/\/[^\s'";]+/gi }
  ];
  for (const pattern of secretPatterns) {
    const matches = [...rawSql.matchAll(pattern.regex)];
    if (matches.length) {
      findings.push(finding(
        'SECRET-001', 'critical', `Possible ${pattern.name} found inside the SQL.`, 'pasted SQL',
        `${matches.length} suspicious value(s) detected. The values themselves are not stored anywhere — this scan runs entirely in your browser.`,
        '-- Rotate the key immediately and move it to a secret manager or server-side environment variable.'
      ));
    }
  }

  return findings.sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity]);
}

export function scanSql(sql, source = 'pasted SQL') {
  const model = extractModel(sql);
  const findings = runRules(model, sql);
  const penalty = findings.reduce((sum, item) => sum + SEVERITY_WEIGHT[item.severity], 0);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of findings) counts[item.severity] += 1;

  return {
    version: '0.1.0',
    source,
    scannedAt: new Date().toISOString(),
    score: Math.max(0, 100 - penalty),
    summary: { ...counts, tables: model.tables.filter((t) => t.created).length, policies: model.policies.length },
    findings
  };
}
