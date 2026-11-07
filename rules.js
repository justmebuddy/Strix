// rules.js — local static analysis: AST sinks + lightweight taint, secrets, authz heuristics.
// Everything runs in the browser; no code is sent to any third party.
import { parse } from 'https://esm.sh/@babel/parser@7';

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

// Test / mock / fixture / story files are not shipped to production, so findings there are down-ranked.
export const isTestPath = (p = '') =>
  /(?:^|\/)(?:__tests__|__mocks__|tests?|spec|e2e|cypress|fixtures?|stories)\//i.test(p) ||
  /\.(?:test|spec|stories)\.[cm]?[jt]sx?$/i.test(p);

/* ---------------------------------------------------------------- helpers */

function lineOf(code, index) {
  let line = 1;
  for (let i = 0; i < index && i < code.length; i++) if (code.charCodeAt(i) === 10) line++;
  return line;
}

function lineText(code, line) {
  const t = (code.split('\n')[line - 1] || '').trim();
  return t.length > 160 ? t.slice(0, 160) + '…' : t;
}

function entropy(s) {
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

const mask = (s) => (s.length <= 8 ? '****' : s.slice(0, 4) + '…' + `(${s.length} chars)`);

/* ---------------------------------------------------------------- secrets */

const SECRET_PATTERNS = [
  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{40,}\b/g, severity: 'CRITICAL' },
  { name: 'OpenAI API key', re: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b/g, severity: 'CRITICAL' },
  { name: 'Google / Gemini API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: 'CRITICAL' },
  { name: 'AWS access key ID', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b/g, severity: 'CRITICAL' },
  { name: 'Azure storage account key', re: /AccountKey=[A-Za-z0-9+/=]{40,}/g, severity: 'CRITICAL' },
  { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, severity: 'HIGH' },
  { name: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, severity: 'HIGH' },
  { name: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: 'HIGH' },
  { name: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, severity: 'HIGH' },
  { name: 'Stripe live key', re: /\b[sr]k_live_[A-Za-z0-9]{20,}\b/g, severity: 'CRITICAL' },
  { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, severity: 'CRITICAL' },
];

const GENERIC_SECRET =
  /\b([\w.-]*(?:secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key)[\w.-]*)\s*[:=]\s*(['"`])([^'"`\n]{12,})\2/gi;
const PLACEHOLDER = /example|your[_-]|xxx|change[_-]?me|placeholder|process\.env|<.*>|\$\{/i;

export function scanSecrets(code) {
  const out = [];
  for (const p of SECRET_PATTERNS) {
    for (const m of code.matchAll(p.re)) {
      const line = lineOf(code, m.index);
      out.push({
        category: 'Secret',
        name: p.name,
        severity: p.severity,
        line,
        description: `Hardcoded credential found (${mask(m[0])}). Revoke and rotate it, then load it from an environment variable or secret manager.`,
        snippet: null,
      });
    }
  }
  for (const m of code.matchAll(GENERIC_SECRET)) {
    const value = m[3];
    if (/\s/.test(value) || PLACEHOLDER.test(value)) continue;
    const h = entropy(value);
    if (h < 3.2) continue;
    out.push({
      category: 'Secret',
      name: 'High-entropy secret assignment',
      severity: h > 4 ? 'HIGH' : 'MEDIUM',
      line: lineOf(code, m.index),
      description: `\`${m[1]}\` is assigned a string with entropy ${h.toFixed(2)} bits/char (${mask(value)}). Looks like a hardcoded secret.`,
      snippet: null,
    });
  }
  return out;
}

/* -------------------------------------------------------------------- AST */

const SKIP_KEYS = new Set(['loc', 'start', 'end', 'extra', 'leadingComments', 'trailingComments', 'innerComments', 'range']);

function walk(node, visit, parent = null) {
  if (!node || typeof node.type !== 'string') return;
  visit(node, parent);
  for (const k in node) {
    if (SKIP_KEYS.has(k)) continue;
    const v = node[k];
    if (Array.isArray(v)) v.forEach((c) => walk(c, visit, node));
    else if (v && typeof v.type === 'string') walk(v, visit, node);
  }
}

const SOURCE_RE =
  /\b(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer|cookie)|window\.name|req\.(?:query|body|params|headers)|request\.(?:query|body|params)|URLSearchParams|event\.data)\b/;

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all']);
const AUTH_RE = /\b(?:req\.user|req\.auth|req\.session|currentUser|authenticate|authorize|isAuthenticated|requireAuth|verifyToken|ensureLoggedIn|passport|jwt|checkRole|can\()/i;
const PRIV_BODY_RE = /req\.body\.(?:role|roles|isAdmin|is_admin|admin|permissions|isPremium|plan)\b/;

const isLiteral = (n) =>
  n && (n.type === 'StringLiteral' || (n.type === 'TemplateLiteral' && n.expressions.length === 0));

const propName = (m) =>
  !m || m.type !== 'MemberExpression'
    ? null
    : !m.computed && m.property.type === 'Identifier'
    ? m.property.name
    : m.property.type === 'StringLiteral'
    ? m.property.value
    : null;

export function scanAST(code, path = '') {
  let ast;
  const isTS = /\.(ts|tsx)$/.test(path);
  try {
    ast = parse(code, {
      sourceType: 'unambiguous',
      errorRecovery: true,
      allowReturnOutsideFunction: true,
      plugins: isTS ? ['jsx', 'typescript'] : ['jsx'],
    });
  } catch {
    return { findings: [], parsed: false };
  }

  const findings = [];
  const tainted = new Set();
  const src = (n) => code.slice(n.start, n.end);

  const identsOf = (node) => {
    const names = [];
    walk(node, (n, parent) => {
      if (n.type === 'Identifier' && !(parent && parent.type === 'MemberExpression' && parent.property === n && !parent.computed)) {
        names.push(n.name);
      }
    });
    return names;
  };

  const isTainted = (node) => {
    if (!node) return false;
    if (SOURCE_RE.test(src(node))) return true;
    return identsOf(node).some((n) => tainted.has(n));
  };

  // confidence: 'high' only when we actually traced user input into the sink.
  const add = (node, category, name, severity, description) =>
    findings.push({
      category,
      name,
      severity,
      description,
      confidence: /^User-controlled|flows into|reaches/i.test(description) ? 'high' : 'low',
      line: node.loc ? node.loc.start.line : lineOf(code, node.start),
    });

  walk(ast, (node) => {
    switch (node.type) {
      case 'VariableDeclarator': {
        if (node.init && isTainted(node.init)) identsOf(node.id).forEach((n) => tainted.add(n));
        break;
      }

      case 'AssignmentExpression': {
        const { left, right } = node;
        if (left.type === 'Identifier' && isTainted(right)) tainted.add(left.name);

        if (left.type === 'MemberExpression') {
          const p = propName(left);
          if ((p === 'innerHTML' || p === 'outerHTML') && !isLiteral(right)) {
            const t = isTainted(right);
            add(node, 'DOM XSS', `Assignment to ${p}`, t ? 'HIGH' : 'MEDIUM',
              t ? `User-controlled data flows into ${p}. Use textContent or sanitize with DOMPurify.`
                : `Non-constant value assigned to ${p}. Verify it is never attacker-influenced; prefer textContent.`);
          }
          if ((p === 'href' || p === 'location') && isTainted(right) && /location/.test(src(left))) {
            add(node, 'Open Redirect', 'Tainted navigation target', 'MEDIUM',
              'User-controlled value assigned to location. Validate against an allow-list of destinations.');
          }
          // a[b][c] = v  →  prototype pollution shape
          if (left.computed && left.object.type === 'MemberExpression' && left.object.computed &&
              left.property.type !== 'StringLiteral' && left.object.property.type !== 'StringLiteral') {
            const t = isTainted(left);
            add(node, 'Prototype Pollution', 'Nested dynamic property write', t ? 'HIGH' : 'MEDIUM',
              'Nested computed assignment obj[a][b] = v. If a/b come from user input, "__proto__" can pollute Object.prototype. Block __proto__/constructor/prototype keys or use Map.');
          }
        }
        break;
      }

      case 'MemberExpression': {
        if (propName(node) === '__proto__') {
          add(node, 'Prototype Pollution', 'Use of __proto__', 'MEDIUM',
            'Direct __proto__ access. Confirm it is not reachable with attacker-controlled keys.');
        }
        break;
      }

      case 'NewExpression': {
        if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
          const t = node.arguments.some(isTainted);
          add(node, 'Code Injection', 'new Function()', t ? 'CRITICAL' : 'MEDIUM',
            t ? 'User-controlled input reaches new Function(): remote code execution.'
              : 'new Function() compiles a string to code. No user input was traced into it in this file, so it is only risky if that string can come from an untrusted source.');
        }
        break;
      }

      case 'JSXAttribute': {
        if (node.name && node.name.name === 'dangerouslySetInnerHTML' && node.value) {
          const t = isTainted(node.value);
          add(node, 'DOM XSS', 'dangerouslySetInnerHTML', t ? 'HIGH' : 'MEDIUM',
            t ? 'User-controlled data reaches dangerouslySetInnerHTML.' : 'Raw HTML injection in React. Sanitize the value (DOMPurify) first.');
        }
        break;
      }

      case 'CallExpression': {
        const { callee, arguments: args } = node;
        const name = callee.type === 'Identifier' ? callee.name : propName(callee);

        if (callee.type === 'Identifier' && name === 'eval') {
          const t = args.some(isTainted);
          add(node, 'Code Injection', 'eval()', t ? 'CRITICAL' : 'MEDIUM',
            t ? 'User-controlled input reaches eval(): remote code execution.'
              : 'eval() executes a string as code. No user input was traced into it in this file, but it is fragile; prefer safe parsing.');
        }

        if (callee.type === 'Identifier' && (name === 'setTimeout' || name === 'setInterval') && args[0] &&
            !/Function|Arrow/.test(args[0].type) && args[0].type !== 'Identifier') {
          add(node, 'Code Injection', `${name} with string`, isTainted(args[0]) ? 'HIGH' : 'MEDIUM',
            `${name}() given a non-function argument behaves like eval().`);
        }

        if (callee.type === 'MemberExpression') {
          if ((name === 'write' || name === 'writeln') && /document/.test(src(callee.object)) && args[0] && !isLiteral(args[0])) {
            add(node, 'DOM XSS', 'document.write()', isTainted(args[0]) ? 'HIGH' : 'MEDIUM',
              'document.write with dynamic content is an XSS sink.');
          }
          if (name === 'insertAdjacentHTML' && args[1] && !isLiteral(args[1])) {
            add(node, 'DOM XSS', 'insertAdjacentHTML()', isTainted(args[1]) ? 'HIGH' : 'MEDIUM',
              'Dynamic HTML inserted into the DOM. Sanitize first.');
          }
          if (name === 'html' && args[0] && !isLiteral(args[0]) && isTainted(args[0])) {
            add(node, 'DOM XSS', 'jQuery .html()', 'HIGH', 'User-controlled data passed to .html().');
          }
          if ((name === 'exec' || name === 'execSync') && args[0] && !isLiteral(args[0])) {
            const t = isTainted(args[0]);
            add(node, 'Command Injection', `${name}()`, t ? 'CRITICAL' : 'MEDIUM',
              t ? 'User-controlled input reaches a shell command.' : 'Shell command built from a dynamic string. Use execFile/spawn with an argument array.');
          }

          // Express-style route heuristics (IDOR / missing authz / privilege escalation)
          if (HTTP_METHODS.has(name) && args.length >= 2 && args[0].type === 'StringLiteral' &&
              /^\//.test(args[0].value)) {
            const handler = args[args.length - 1];
            if (/Function|Arrow/.test(handler.type)) {
              const body = src(handler);
              const routeText = args.slice(0, -1).map(src).join(' ');
              const hasAuth = AUTH_RE.test(body) || AUTH_RE.test(routeText);
              const usesParam = /req\.(?:params|query|body)\.\w*id\b/i.test(body) || /:id\b|:\w+Id\b/.test(args[0].value);
              const mutating = ['delete', 'put', 'patch'].includes(name);

              if (usesParam && !hasAuth) {
                add(node, 'IDOR', `${name.toUpperCase()} ${args[0].value}`, mutating ? 'HIGH' : 'MEDIUM',
                  'Handler uses a client-supplied object ID with no ownership/authorization check visible. Verify the resource belongs to req.user.');
              } else if (mutating && !hasAuth) {
                add(node, 'Broken Access Control', `${name.toUpperCase()} ${args[0].value}`, 'MEDIUM',
                  'State-changing route without any visible authentication middleware or check.');
              }
              if (PRIV_BODY_RE.test(body)) {
                add(node, 'Privilege Escalation', `Mass-assignment of role on ${args[0].value}`, 'HIGH',
                  'Handler reads role/admin/plan fields straight from the request body. Whitelist fields and never accept privilege attributes from clients.');
              }
            }
          }
        }
        break;
      }
    }
  });

  return { findings, parsed: true };
}

/* ------------------------------------------------------------- public API */

export function scanCode(content, path = '') {
  const { findings: astFindings, parsed } = scanAST(content, path);
  const all = [...astFindings, ...scanSecrets(content)];
  const isTest = isTestPath(path);
  const oneLower = (s) => SEVERITIES[Math.min(SEVERITIES.indexOf(s) + 1, SEVERITIES.length - 1)];

  const seen = new Set();
  const result = [];
  for (const f of all) {
    const key = `${f.category}|${f.name}|${f.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (f.snippet === null) f.snippet = ''; // never echo secrets
    else if (f.snippet === undefined) f.snippet = lineText(content, f.line);
    if (f.confidence === undefined) f.confidence = f.category === 'Secret' ? 'high' : 'low';
    if (isTest) {
      f.context = 'test';
      f.severity = f.category === 'Secret' ? oneLower(f.severity) : 'LOW';
      f.confidence = 'low';
      f.description += ' (Test file: usually not production code.)';
    }
    result.push(f);
  }
  result.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.line - b.line);
  result.parseFailed = !parsed;
  return result;
}
