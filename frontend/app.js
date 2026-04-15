/* ====================================================
   PassGuard — app.js
   Branch: feature/frontend-logic
   Contributor: Dev 2
   ==================================================== */

const BACKEND_URL = 'http://localhost:8000'; // Update for production deployment

// ─── Constants ───────────────────────────────────────────────────────────────

const CIRCUMFERENCE = 2 * Math.PI * 32; // r=32 → ~201.1

const CHAR_SETS = {
  lower:   'abcdefghijklmnopqrstuvwxyz',
  upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}|;:,.<>?',
};

const COMMON_PATTERNS = [
  /(.)\1{2,}/,                        // repeated chars: aaa
  /^(123|abc|qwerty|password|pass)/i, // common prefixes
  /^[a-z]+\d{1,3}$/i,                 // word+numbers only
];

// ─── Local Analysis ───────────────────────────────────────────────────────────

function analyzeLocal() {
  const pwd = document.getElementById('pwd').value;

  // Update character count
  document.getElementById('pwd-length').textContent = pwd.length;

  // Evaluate rules
  const rules = {
    len:   pwd.length >= 8,
    upper: /[A-Z]/.test(pwd),
    lower: /[a-z]/.test(pwd),
    num:   /[0-9]/.test(pwd),
    sym:   /[^A-Za-z0-9]/.test(pwd),
    long:  pwd.length >= 12,
  };

  // Update rule indicators
  Object.entries({ len: 'r-len', upper: 'r-upper', lower: 'r-lower', num: 'r-num', sym: 'r-sym', long: 'r-long' })
    .forEach(([key, id]) => setRule(id, rules[key]));

  // Compute score (0–100) with penalty for common patterns
  let score = Object.values(rules).filter(Boolean).length;
  let pct   = Math.round((score / 6) * 100);

  if (pwd.length && COMMON_PATTERNS.some(r => r.test(pwd))) {
    pct = Math.max(0, pct - 20); // pattern penalty
  }

  // Resolve color & label
  const { color, label, desc } = resolveStrength(pwd, pct);

  // Update meter
  const meter = document.getElementById('meter');
  meter.style.width      = pwd.length ? pct + '%' : '0%';
  meter.style.background = color;
  document.getElementById('meter-track').setAttribute('aria-valuenow', pct);

  // Update label
  const lbl = document.getElementById('strength-label');
  lbl.textContent = label;
  lbl.style.color = color;

  // Update score circle
  const ring   = document.getElementById('score-ring');
  const offset = CIRCUMFERENCE - (pct / 100) * CIRCUMFERENCE;
  ring.style.strokeDashoffset = pwd.length ? offset : CIRCUMFERENCE;
  ring.style.stroke = color;

  const num = document.getElementById('score-num');
  num.textContent = pwd.length ? pct : '0';
  num.style.color = color;

  document.getElementById('score-desc').textContent = desc;

  // Show local entropy estimate
  updateEntropyDisplay(pwd, rules);
}

// ─── Strength Resolution ──────────────────────────────────────────────────────

function resolveStrength(pwd, pct) {
  if (!pwd.length)  return { color: 'var(--muted)',  label: '—',      desc: 'Start typing to analyze your password.' };
  if (pct <= 33)    return { color: 'var(--weak)',   label: 'Weak',   desc: 'Too easy to crack. Add uppercase letters, numbers and symbols.' };
  if (pct <= 50)    return { color: 'var(--fair)',   label: 'Fair',   desc: 'Getting there — try mixing more character types and increasing length.' };
  if (pct <= 83)    return { color: 'var(--good)',   label: 'Good',   desc: 'Solid password. A bit more length or symbols would make it excellent.' };
  return               { color: 'var(--strong)', label: 'Strong', desc: 'Excellent! Highly resistant to brute-force and dictionary attacks.' };
}

// ─── Entropy Estimate ────────────────────────────────────────────────────────

function updateEntropyDisplay(pwd, rules) {
  const row = document.getElementById('entropy-row');
  if (!pwd.length) { row.style.display = 'none'; return; }

  const poolSize = (rules.lower ? 26 : 0) + (rules.upper ? 26 : 0) +
                   (rules.num   ? 10 : 0) + (rules.sym   ? 30 : 0);
  const entropy  = poolSize > 0 ? Math.round(pwd.length * Math.log2(poolSize)) : 0;
  const crackStr = estimateCrackTime(entropy);

  document.getElementById('entropy-val').textContent  = `~${entropy} bits entropy`;
  document.getElementById('crack-time').textContent   = `Crack time: ${crackStr}`;
  row.style.display = 'flex';
}

function estimateCrackTime(bits) {
  // Assumes 10 billion guesses/sec (GPU array)
  const guesses  = Math.pow(2, bits);
  const seconds  = guesses / 1e10;
  if (seconds < 1)        return 'instant';
  if (seconds < 60)       return `${Math.round(seconds)}s`;
  if (seconds < 3600)     return `${Math.round(seconds / 60)}min`;
  if (seconds < 86400)    return `${Math.round(seconds / 3600)}hr`;
  if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
  const years = seconds / 31536000;
  if (years < 1e6)        return `${Math.round(years).toLocaleString()} years`;
  return 'centuries+';
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function setRule(id, pass) {
  const el = document.getElementById(id);
  el.classList.toggle('pass', pass);
  el.setAttribute('aria-checked', pass ? 'true' : 'false');
}

function toggleVis() {
  const input = document.getElementById('pwd');
  const icon  = document.getElementById('toggle-icon');
  if (input.type === 'password') {
    input.type  = 'text';
    icon.textContent = '🙈';
  } else {
    input.type  = 'password';
    icon.textContent = '👁';
  }
}

function clearPassword() {
  const input = document.getElementById('pwd');
  input.value = '';
  input.dispatchEvent(new Event('input'));
  analyzeLocal();
  input.focus();
}

function generatePassword() {
  const all   = CHAR_SETS.lower + CHAR_SETS.upper + CHAR_SETS.numbers + CHAR_SETS.symbols;
  const mustHave = [
    CHAR_SETS.lower[Math.floor(Math.random() * CHAR_SETS.lower.length)],
    CHAR_SETS.upper[Math.floor(Math.random() * CHAR_SETS.upper.length)],
    CHAR_SETS.numbers[Math.floor(Math.random() * CHAR_SETS.numbers.length)],
    CHAR_SETS.symbols[Math.floor(Math.random() * CHAR_SETS.symbols.length)],
  ];
  const len   = 16;
  const rest  = Array.from({ length: len - mustHave.length }, () => all[Math.floor(Math.random() * all.length)]);
  const combined = [...mustHave, ...rest].sort(() => Math.random() - 0.5);

  const input = document.getElementById('pwd');
  input.value = combined.join('');
  input.type  = 'text';
  document.getElementById('toggle-icon').textContent = '🙈';
  analyzeLocal();
}

// ─── Backend Analysis ─────────────────────────────────────────────────────────

async function analyzeBackend() {
  const pwd = document.getElementById('pwd').value;
  if (!pwd) { showToast('Enter a password first.'); return; }

  const panel = document.getElementById('backend-panel');
  const body  = document.getElementById('panel-body');
  const btn   = document.getElementById('analyze-btn');
  const blink = document.getElementById('blink-dot');
  const badge = document.getElementById('panel-badge');

  panel.className  = 'backend-panel loading';
  blink.style.display = 'block';
  badge.style.display = 'none';
  body.innerHTML   = '<span style="color:var(--muted)">Contacting backend · checking breach databases…</span>';
  btn.disabled     = true;
  document.getElementById('btn-text').textContent = 'Analyzing…';

  try {
    const res  = await fetch(`${BACKEND_URL}/analyze`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ password: pwd }),
    });

    if (!res.ok) throw new Error(`Server error ${res.status}`);
    const data = await res.json();

    panel.className      = 'backend-panel success';
    blink.style.display  = 'none';
    badge.style.display  = 'inline';
    badge.textContent    = 'Analysis complete';

    renderBackendResult(data, body);

  } catch (err) {
    panel.className     = 'backend-panel error';
    blink.style.display = 'none';
    body.innerHTML = `
      <strong style="color:var(--weak)">Backend unreachable</strong><br/>
      <span style="font-size:0.78rem;color:var(--muted)">
        Make sure the server is running at <code>${BACKEND_URL}</code>
        <br/>Run: <code>uvicorn server:app --reload --port 8000</code>
      </span>`;
  }

  btn.disabled = false;
  document.getElementById('btn-text').textContent = 'Analyze with Backend →';
}

function renderBackendResult(data, container) {
  let html = `<strong>Score: ${data.score}/100</strong> &nbsp;·&nbsp; <strong>${data.label}</strong><br/><br/>`;

  html += data.breached
    ? `<span class="tag breached">⚠ Found in ${data.breach_count?.toLocaleString() ?? '?'} breach records</span><br/>`
    : `<span class="tag safe">✓ Not found in known breaches</span><br/>`;

  if (data.tips?.length) {
    html += '<br/>';
    data.tips.forEach(t => { html += `<span class="tag tip">→ ${t}</span>`; });
  }

  if (data.entropy) {
    html += `<br/><br/>
      <span style="color:var(--muted);font-size:0.74rem">
        Entropy: ${data.entropy} bits &nbsp;·&nbsp; Est. crack time: ${data.crack_time}
      </span>`;
  }

  container.innerHTML = html;
}

// ─── Toast Notification ────────────────────────────────────────────────────────

function showToast(msg) {
  const t = document.createElement('div');
  t.textContent = msg;
  Object.assign(t.style, {
    position: 'fixed', bottom: '2rem', left: '50%', transform: 'translateX(-50%)',
    background: 'var(--surface)', border: '1px solid var(--border2)',
    color: 'var(--text)', fontFamily: 'var(--mono)', fontSize: '0.78rem',
    padding: '0.6rem 1.2rem', borderRadius: '8px',
    boxShadow: '0 8px 32px rgba(0,0,0,0.4)', zIndex: 999,
    animation: 'cardIn 0.3s ease both',
  });
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2800);
}

// ─── Server Health Check ──────────────────────────────────────────────────────

async function checkServer() {
  const dot  = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  try {
    const res = await fetch(`${BACKEND_URL}/health`, { signal: AbortSignal.timeout(2500) });
    if (res.ok) {
      dot.className    = 'status-dot online';
      text.textContent = 'backend connected · localhost:8000';
    } else { throw new Error(); }
  } catch {
    dot.className    = 'status-dot offline';
    text.textContent = 'backend offline · run the Python server';
  }
}

// ─── Init ────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('pwd');
  input.addEventListener('input', analyzeLocal);
  checkServer();
  setInterval(checkServer, 5000);
});
