#!/usr/bin/env python3
"""
Interface web locale — IOC Hunting
Bind uniquement sur 127.0.0.1, jamais exposé sur le réseau.
Protection CSRF : token aléatoire généré au lancement, vérifié sur chaque POST.
"""

import re
import io
import os
import secrets
import socket
from contextlib import redirect_stdout

try:
    from flask import Flask, request, jsonify, render_template_string
except ImportError:
    Flask = None  # géré dans create_app()

# ── ANSI → HTML ────────────────────────────────────────────────────────────────

_ANSI_STYLES = {
    '1':  'font-weight:bold',
    '2':  'opacity:0.45',
    '91': 'color:#ff7b72',
    '92': 'color:#3fb950',
    '93': 'color:#e3b341',
    '95': 'color:#d2a8ff',
    '96': 'color:#79c0ff',
    '97': 'color:#e6edf3',
}

def _ansi_to_html(text: str) -> str:
    """Convertit les séquences ANSI couleur en <span style="...">.
    stack compte les spans ouverts : un reset (\033[0m) les ferme tous d'un coup,
    ce qui évite d'avoir à parser la hiérarchie d'imbrication."""
    result = []
    stack  = 0
    pos    = 0
    for m in re.finditer(r'\033\[([0-9;]*)m', text):
        chunk = text[pos:m.start()].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        result.append(chunk)
        pos   = m.end()
        codes = m.group(1)
        if codes in ('0', ''):
            result.append('</span>' * stack)
            stack = 0
        else:
            styles = [_ANSI_STYLES[c] for c in codes.split(';') if c in _ANSI_STYLES]
            if styles:
                result.append(f'<span style="{";".join(styles)}">')
                stack += 1
    chunk = text[pos:].replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    result.append(chunk)
    result.append('</span>' * stack)
    return ''.join(result)

# ── utilitaire port ────────────────────────────────────────────────────────────

def is_port_available(port: int) -> bool:
    """Teste si le port TCP est libre sur 127.0.0.1 (connect_ex = 0 → occupé)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(('127.0.0.1', port)) != 0

# ── template HTML ──────────────────────────────────────────────────────────────

_HTML = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IOC Hunting</title>
<style>
:root {
  --bg:      #0d1117;
  --surface: #161b22;
  --border:  #21262d;
  --border2: #30363d;
  --text:    #c9d1d9;
  --dim:     #6e7681;
  --accent:  #58a6ff;
  --green:   #3fb950;
  --red:     #f85149;
  --yellow:  #e3b341;
  --cyan:    #79c0ff;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  background:var(--bg);color:var(--text);
  font-family:'JetBrains Mono','Fira Code','Cascadia Code',ui-monospace,monospace;
  min-height:100vh;display:flex;flex-direction:column;
}

/* ── header ── */
header{
  border-bottom:1px solid var(--border);
  padding:14px 32px;
  display:flex;align-items:center;gap:10px;
}
header h1{font-size:.95rem;font-weight:600;letter-spacing:.02em}
.badge{
  font-size:.62rem;padding:2px 8px;border-radius:20px;
  background:#1f3a5f;color:var(--cyan);border:1px solid #1f6feb44;
}
.live{
  margin-left:auto;display:flex;align-items:center;gap:7px;
  font-size:.7rem;color:var(--dim);
}
.dot{
  width:7px;height:7px;border-radius:50%;
  background:var(--green);box-shadow:0 0 5px var(--green);
}

/* ── main ── */
main{
  flex:1;max-width:880px;width:100%;
  margin:0 auto;padding:36px 24px;
  display:flex;flex-direction:column;gap:20px;
}

/* ── search ── */
.search-col{display:flex;flex-direction:column;gap:10px;flex:1}
.search-row{display:flex;gap:10px;align-items:flex-start}
.search-row textarea{
  flex:1;background:var(--surface);
  border:1px solid var(--border2);border-radius:8px;
  color:var(--text);font-family:inherit;font-size:.88rem;
  padding:11px 15px;outline:none;resize:vertical;
  min-height:44px;max-height:200px;line-height:1.5;
  transition:border-color .2s,box-shadow .2s;
}
.search-row textarea:focus{
  border-color:var(--accent);
  box-shadow:0 0 0 3px #58a6ff1a;
}
.search-row textarea::placeholder{color:var(--dim)}
.btn-col{display:flex;flex-direction:column;gap:8px}
.search-row button[type=submit]{
  background:var(--accent);color:#fff;border:none;
  border-radius:8px;padding:11px 22px;
  font-family:inherit;font-size:.88rem;font-weight:600;
  cursor:pointer;transition:background .15s,opacity .15s;white-space:nowrap;width:100%;
}
.search-row button[type=submit]:hover{background:#79c0ff}
.search-row button[type=submit]:disabled{opacity:.45;cursor:default}

/* ── upload btn ── */
.upload-btn{
  background:var(--surface);color:var(--dim);
  border:1px solid var(--border2);border-radius:8px;
  padding:11px 14px;font-family:inherit;font-size:.82rem;
  cursor:pointer;transition:border-color .15s,color .15s;white-space:nowrap;width:100%;
}
.upload-btn:hover{border-color:var(--accent);color:var(--accent)}

/* ── file badge ── */
.file-badge{
  display:none;align-items:center;gap:8px;
  font-size:.75rem;color:var(--cyan);
  background:#1f3a5f33;border:1px solid #1f6feb33;
  border-radius:6px;padding:5px 12px;
}
.file-badge.on{display:flex}
.file-badge .fname{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.file-badge .clr{
  cursor:pointer;color:var(--dim);font-size:.9rem;flex-shrink:0;
  transition:color .15s;
}
.file-badge .clr:hover{color:var(--red)}

/* ── options ── */
.options{
  display:flex;gap:18px;align-items:center;flex-wrap:wrap;
  font-size:.78rem;color:var(--dim);
}
.options label{display:flex;align-items:center;gap:6px;cursor:pointer;user-select:none}
.options input[type=checkbox]{accent-color:var(--accent);cursor:pointer}
.options input[type=text]{
  background:var(--surface);border:1px solid var(--border2);
  border-radius:6px;color:var(--text);font-family:inherit;
  font-size:.78rem;padding:4px 10px;width:78px;outline:none;
}
.options input[type=text]:focus{border-color:var(--accent)}

/* ── loader ── */
.loader{display:none;align-items:center;gap:10px;color:var(--dim);font-size:.82rem}
.loader.on{display:flex}
.spinner{
  width:15px;height:15px;border:2px solid var(--border2);
  border-top-color:var(--accent);border-radius:50%;
  animation:spin .7s linear infinite;flex-shrink:0;
}
@keyframes spin{to{transform:rotate(360deg)}}

/* ── error ── */
.error{
  display:none;background:#2d1117;
  border:1px solid #f8514944;border-radius:8px;
  padding:12px 16px;color:var(--red);font-size:.82rem;
}
.error.on{display:block}

/* ── history ── */
.history{display:flex;gap:7px;flex-wrap:wrap;min-height:0}
.chip{
  background:var(--surface);border:1px solid var(--border2);
  border-radius:20px;padding:3px 12px;
  font-size:.72rem;color:var(--dim);cursor:pointer;
  transition:border-color .15s,color .15s;user-select:none;
}
.chip:hover{border-color:var(--accent);color:var(--accent)}

/* ── summary bar ── */
.summary-bar{
  display:none;align-items:center;justify-content:space-between;
  font-size:.75rem;color:var(--dim);padding:2px 4px;
}
.summary-bar.on{display:flex}

/* ── nav ── */
.nav-list{
  display:none;flex-wrap:wrap;gap:6px;align-items:center;
  padding:10px 14px;
  background:var(--surface);border:1px solid var(--border);
  border-radius:8px;
}
.nav-list.on{display:flex}
.nav-label{font-size:.68rem;color:var(--dim);margin-right:4px;flex-shrink:0}
.nav-chip{
  background:var(--bg);border:1px solid var(--border2);
  border-radius:6px;padding:4px 10px;
  font-size:.72rem;color:var(--dim);cursor:pointer;
  transition:border-color .15s,color .15s,background .15s;user-select:none;
  max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  display:flex;align-items:center;gap:6px;
}
.nav-chip:hover{border-color:var(--accent);color:var(--accent);background:#1f3a5f22}
.nav-chip .nav-num{
  font-size:.62rem;color:var(--border2);flex-shrink:0;
}
.nav-chip .nav-cached{
  font-size:.58rem;color:var(--green);flex-shrink:0;
}

/* ── results list ── */
#results-list{display:flex;flex-direction:column;gap:14px}

/* ── result card ── */
.result{
  background:var(--surface);
  border:1px solid var(--border);border-radius:10px;overflow:hidden;
}
.result-hd{
  padding:9px 16px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;
  font-size:.72rem;color:var(--dim);
}
.result-hd .tgt{color:var(--cyan);font-weight:600}
.result-hd .hd-right{display:flex;align-items:center;gap:8px}
.cached-badge{
  font-size:.65rem;padding:2px 8px;border-radius:20px;
  background:#1a2a1a;color:var(--green);border:1px solid #3fb95033;
}
.dl-btn{
  background:transparent;color:var(--green);
  border:1px solid #3fb95044;border-radius:6px;
  padding:3px 10px;font-family:inherit;font-size:.68rem;
  cursor:pointer;transition:border-color .15s,color .15s;
}
.dl-btn:hover{border-color:var(--green);color:#56d364}
.result-body{padding:20px;overflow-x:auto}
.result-body pre{
  font-family:inherit;font-size:.8rem;
  line-height:1.7;white-space:pre-wrap;word-break:break-all;
}

/* ── side nav ── */
.side-nav{
  position:fixed;
  top:50%;transform:translateY(-50%);
  /* reste à gauche du bloc main centré (880px max + 16px gap) */
  left:max(8px, calc(50vw - 612px));
  width:154px;
  display:none;flex-direction:column;gap:4px;
  z-index:50;
}
.side-nav.on{display:flex}
/* masqué si pas assez de place (évite le chevauchement) */
@media(max-width:1160px){.side-nav{display:none!important}}
.sn-item{
  background:var(--surface);border:1px solid var(--border2);
  border-radius:6px;padding:5px 10px;
  font-size:.68rem;color:var(--dim);cursor:pointer;
  transition:border-color .15s,color .15s,background .15s;
  display:flex;align-items:center;gap:6px;overflow:hidden;
}
.sn-item:hover{border-color:var(--accent);color:var(--accent)}
.sn-item.active{
  border-color:var(--accent);
  background:#1f3a5f44;color:var(--accent);
}
.sn-item .sn-num{font-size:.6rem;color:var(--border2);flex-shrink:0}
.sn-item.active .sn-num{color:var(--accent)}
.sn-item .sn-tgt{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ── scroll-to-top ── */
.scroll-top{
  position:fixed;bottom:24px;left:24px;
  width:48px;height:48px;border-radius:50%;
  background:#1f3a5f;border:1px solid var(--accent);
  color:var(--accent);font-size:1.2rem;line-height:48px;text-align:center;
  cursor:pointer;opacity:0;pointer-events:none;
  transition:opacity .25s,background .15s,color .15s;
  user-select:none;z-index:99;box-shadow:0 0 8px #58a6ff33;
}
.scroll-top.visible{opacity:1;pointer-events:auto}
.scroll-top:hover{background:var(--accent);color:#fff;box-shadow:0 0 12px #58a6ff66}

/* ── footer ── */
footer{
  text-align:center;padding:14px;
  font-size:.68rem;color:var(--border2);
  border-top:1px solid var(--border);
}
</style>
</head>
<body>

<header>
  <h1>IOC Hunting</h1>
  <span class="badge">web</span>
  <span class="live">
    <span class="dot"></span>
    127.0.0.1:{{ port }}
  </span>
</header>

<main>
  <form id="f" autocomplete="off" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <div class="search-row">
      <textarea id="tgt" name="target" rows="1"
                placeholder="IP, URL ou Hash — une cible par ligne" autofocus
                oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,200)+'px'"></textarea>
      <input type="file" id="ftxt" name="targets_file" accept=".txt" style="display:none">
      <div class="btn-col">
        <button type="submit" id="btn">Analyser →</button>
        <button type="button" class="upload-btn" id="upload-btn" title="Une cible par ligne">Charger .txt</button>
      </div>
    </div>

    <div class="file-badge" id="fbadge">
      <span>📄</span>
      <span class="fname" id="fname"></span>
      <span class="clr" id="fclr" title="Retirer le fichier">✕</span>
    </div>

    <div class="options" style="margin-top:11px">
      <label>
        <input type="checkbox" name="nocache" id="nc">
        Ignorer le cache
      </label>
      <label>
        Filtre année
        <input type="text" name="year" placeholder="2024">
      </label>
    </div>
  </form>

  <div class="loader" id="loader">
    <div class="spinner"></div>
    <span id="lmsg">Analyse en cours…</span>
  </div>

  <div class="error" id="err"></div>

  <div class="history" id="hist"></div>

  <div class="summary-bar" id="summary-bar">
    <span id="summary-txt"></span>
    <button class="dl-btn" id="dl-btn">↓ JSON</button>
  </div>

  <div class="nav-list" id="nav-list">
    <span class="nav-label">Aller à →</span>
  </div>

  <div id="results-list"></div>
</main>

<div class="side-nav" id="side-nav"></div>
<div class="scroll-top" id="scroll-top" title="Retour en haut">↑</div>

<footer>IOC Hunting — interface locale · 127.0.0.1 uniquement · Made by hsa5</footer>

<script>
const form       = document.getElementById('f');
const btn        = document.getElementById('btn');
const ldr        = document.getElementById('loader');
const lmsg       = document.getElementById('lmsg');
const err        = document.getElementById('err');
const hist       = document.getElementById('hist');
const ftxt       = document.getElementById('ftxt');
const uploadBtn  = document.getElementById('upload-btn');
const fbadge     = document.getElementById('fbadge');
const fnameEl    = document.getElementById('fname');
const fclr       = document.getElementById('fclr');
const dlBtn      = document.getElementById('dl-btn');
const summaryBar = document.getElementById('summary-bar');
const summaryTxt = document.getElementById('summary-txt');
const navList    = document.getElementById('nav-list');
const resultsList= document.getElementById('results-list');
const scrollTop  = document.getElementById('scroll-top');
const sideNav    = document.getElementById('side-nav');
let navScrollFn = null;
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

// ── scroll-to-top ──
window.addEventListener('scroll', () => {
  scrollTop.classList.toggle('visible', window.scrollY > 300);
});
scrollTop.onclick = () => window.scrollTo({top: 0, behavior: 'smooth'});

// ── side nav ──
function buildSideNav(blocks) {
  sideNav.innerHTML = '';
  if (blocks.length <= 1) { sideNav.classList.remove('on'); return; }

  blocks.forEach((block, i) => {
    const item = document.createElement('div');
    item.className = 'sn-item';
    item.innerHTML = `<span class="sn-num">#${i + 1}</span><span class="sn-tgt">${esc(block.target)}</span>`;
    item.title     = block.target;
    item.onclick   = () =>
      document.getElementById(`result-card-${i}`)
        .scrollIntoView({behavior:'smooth', block:'start'});
    sideNav.appendChild(item);
  });
  sideNav.classList.add('on');

  // Surligne la carte la plus haute encore visible dans le tiers supérieur
  // (scroll listener plus fiable qu'IntersectionObserver pour ce cas)
  function updateActive() {
    const ref = window.innerHeight / 3;
    let activeIdx = 0;
    for (let i = 0; i < blocks.length; i++) {
      const card = document.getElementById(`result-card-${i}`);
      if (card && card.getBoundingClientRect().top <= ref) activeIdx = i;
    }
    sideNav.querySelectorAll('.sn-item').forEach((el, i) =>
      el.classList.toggle('active', i === activeIdx));
  }

  if (navScrollFn) window.removeEventListener('scroll', navScrollFn);
  navScrollFn = updateActive;
  window.addEventListener('scroll', navScrollFn, {passive: true});
  updateActive();
}

let lastRawData = null;

// ── file upload ──
uploadBtn.onclick = () => ftxt.click();

ftxt.onchange = () => {
  if (ftxt.files && ftxt.files[0]) {
    fnameEl.textContent = ftxt.files[0].name;
    fbadge.classList.add('on');
    document.getElementById('tgt').value = '';
  }
};

fclr.onclick = () => {
  ftxt.value = '';
  fbadge.classList.remove('on');
};

// ── JSON download ──
dlBtn.onclick = () => {
  if (!lastRawData) return;
  const blob = new Blob([JSON.stringify(lastRawData, null, 2)], {type: 'application/json'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = 'threathunting_' + new Date().toISOString().slice(0, 10) + '.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

// ── localStorage history ──
const LS = 'th_history';
const getH  = () => { try { return JSON.parse(localStorage.getItem(LS)||'[]'); } catch { return []; } };
const saveH = h => localStorage.setItem(LS, JSON.stringify(h));
function pushHistory(t) {
  let h = getH().filter(x => x !== t);
  h.unshift(t);
  saveH(h.slice(0, 10));
  renderHistory();
}
function renderHistory() {
  hist.innerHTML = '';
  getH().forEach(t => {
    const el = document.createElement('span');
    el.className = 'chip';
    el.textContent = t;
    el.onclick = () => {
      ftxt.value = '';
      fbadge.classList.remove('on');
      const ta = document.getElementById('tgt');
      ta.value = t;
      ta.style.height = 'auto';
      form.requestSubmit();
    };
    hist.appendChild(el);
  });
}
renderHistory();

// ── loader messages ──
const msgs = [
  'Analyse en cours…',
  'Interrogation VirusTotal…',
  'Interrogation AbuseIPDB…',
  'Interrogation Shodan…',
  'Interrogation URLhaus…',
  'Corrélation des sources…',
  'Presque terminé…',
];
let mt;
function startLoader() {
  let i = 0;
  ldr.classList.add('on');
  mt = setInterval(() => { lmsg.textContent = msgs[++i % msgs.length]; }, 4500);
}
function stopLoader() {
  clearInterval(mt);
  ldr.classList.remove('on');
  lmsg.textContent = msgs[0];
}

// ── submit ──
form.addEventListener('submit', async e => {
  e.preventDefault();
  const raw     = document.getElementById('tgt').value;
  const hasFile = ftxt.files && ftxt.files[0];
  if (!raw.trim() && !hasFile) return;

  // Validation : détecte les cibles séparées par des espaces sur une même ligne
  if (!hasFile) {
    const lines = raw.split('\n').map(l => l.trim()).filter(Boolean);
    for (const line of lines) {
      if (line.includes(' ')) {
        err.textContent = '⚠  Une seule cible par ligne — ex: 1.2.3.4  (puis entrée)  puis 5.6.7.8';
        err.classList.add('on');
        return;
      }
    }
  }

  const target = raw.trim();

  btn.disabled = true;
  startLoader();
  err.classList.remove('on');
  resultsList.innerHTML = '';
  navList.innerHTML = '';
  navList.classList.remove('on');
  summaryBar.classList.remove('on');
  sideNav.innerHTML = '';
  sideNav.classList.remove('on');
  if (navScrollFn) { window.removeEventListener('scroll', navScrollFn); navScrollFn = null; }
  lastRawData = null;

  try {
    const r    = await fetch('/analyze', { method:'POST', body: new FormData(form) });
    const data = await r.json();

    if (data.error) {
      err.textContent = '⚠  ' + data.error;
      err.classList.add('on');
    } else {
      // Crée une carte par cible
      const blocks = data.blocks || [];
      blocks.forEach((block, i) => {
        const cardId = `result-card-${i}`;
        const card   = document.createElement('div');
        card.className = 'result';
        card.id        = cardId;
        card.innerHTML =
          `<div class="result-hd">` +
            `<span class="tgt">${esc(block.target)}</span>` +
            `<span class="hd-right">${block.cached ? '<span class="cached-badge">cache</span>' : ''}</span>` +
          `</div>` +
          `<div class="result-body"><pre></pre></div>`;
        card.querySelector('pre').innerHTML = block.html;
        resultsList.appendChild(card);
      });

      // Barre latérale fixe
      buildSideNav(blocks);

      // Nav cliquable (affiché seulement pour plusieurs cibles)
      if (blocks.length > 1) {
        // Vide les chips précédents mais garde le label "Aller à →"
        Array.from(navList.querySelectorAll('.nav-chip')).forEach(el => el.remove());
        blocks.forEach((block, i) => {
          const chip = document.createElement('span');
          chip.className = 'nav-chip';
          chip.title     = block.target;
          chip.innerHTML =
            `<span class="nav-num">#${i + 1}</span>` +
            `<span>${esc(block.target)}</span>` +
            (block.cached ? `<span class="nav-cached">cache</span>` : '');
          chip.onclick = () => {
            document.getElementById(`result-card-${i}`)
              .scrollIntoView({behavior: 'smooth', block: 'start'});
          };
          navList.appendChild(chip);
        });
        navList.classList.add('on');
      }

      // Barre de résumé + bouton JSON
      if (data.raw && data.raw.length) {
        lastRawData = data.raw;
        const n = (data.blocks || []).length;
        summaryTxt.textContent = n > 1 ? `${n} cibles analysées` : '';
        summaryBar.classList.add('on');
      }

      // History — cible unique seulement
      const lines = target.split('\n').map(l => l.trim()).filter(Boolean);
      if (!hasFile && lines.length === 1) pushHistory(lines[0]);
    }
  } catch (ex) {
    err.textContent = '⚠  Erreur réseau : ' + ex.message;
    err.classList.add('on');
  } finally {
    btn.disabled = false;
    stopLoader();
  }
});
</script>
</body>
</html>"""

# ── Flask app ──────────────────────────────────────────────────────────────────

_CSRF_TOKEN = secrets.token_urlsafe(32)

def create_app(keys: dict, cache: dict | None, fns: dict, port: int):
    """Crée et retourne l'application Flask.
    keys  : dict des clés API déchiffrées (transmis par main.py).
    cache : dict partagé du cache disque — None si --nocache.
    fns   : {'correlation', 'hash', 'is_hash', 'parse_years'} — fonctions de main.py.
    port  : utilisé uniquement pour l'injection dans le template HTML.
    """
    if Flask is None:
        raise RuntimeError("Flask manquant — lance : pip install flask")

    app = Flask(__name__, static_folder=None)
    app.secret_key = secrets.token_hex(32)

    @app.route('/')
    def index():
        return render_template_string(_HTML, csrf_token=_CSRF_TOKEN, port=port)

    @app.route('/analyze', methods=['POST'])
    def analyze():
        if request.form.get('csrf_token') != _CSRF_TOKEN:
            return jsonify({'error': 'Token CSRF invalide'}), 403

        year_str     = (request.form.get('year') or '').strip()
        nocache      = bool(request.form.get('nocache'))
        active_cache = None if nocache else cache
        years        = fns['parse_years'](year_str) if year_str else None

        # Fichier .txt prioritaire sur la saisie texte (multipart/form-data)
        uploaded = request.files.get('targets_file')
        if uploaded and uploaded.filename:
            raw_text = uploaded.stream.read().decode('utf-8', errors='replace')
            lines    = [l.strip() for l in raw_text.splitlines()
                        if l.strip() and not l.startswith('#')]
            if not lines:
                return jsonify({'error': 'Fichier vide ou sans cibles valides'}), 400
            targets      = lines
            n            = len(targets)
            target_label = f"{n} cible{'s' if n > 1 else ''}  —  {uploaded.filename}"
        else:
            raw_input = (request.form.get('target') or '').strip()
            if not raw_input:
                return jsonify({'error': 'Cible vide'}), 400
            # Textarea multi-lignes : une cible par ligne, # = commentaire
            lines = [l.strip() for l in raw_input.splitlines()
                     if l.strip() and not l.startswith('#')]
            # Validation serveur (doublon de la validation JS, filet de sécurité)
            for line in lines:
                if ' ' in line:
                    return jsonify({
                        'error': f'Une seule cible par ligne — "{line}" contient des espaces. '
                                  'Sépare les cibles par des sauts de ligne.'
                    }), 400
            if not lines:
                return jsonify({'error': 'Cible vide'}), 400
            targets = lines
            n = len(targets)
            target_label = targets[0] if n == 1 else f"{n} cibles"

        # Capture stdout par cible pour obtenir un bloc HTML indépendant par carte
        blocks      = []
        all_results = []
        for tgt in targets:
            buf = io.StringIO()
            try:
                with redirect_stdout(buf):
                    if fns['is_hash'](tgt):
                        res = fns['hash']([tgt], keys, cache=active_cache)
                        if res:
                            all_results.extend(res)
                    else:
                        res = fns['correlation'](tgt, keys, years=years, cache=active_cache)
                        if res:
                            all_results.append(res)
            except Exception as e:
                blocks.append({
                    'target': tgt,
                    'html':   f'<span style="color:#f85149">Erreur : {e}</span>',
                    'cached': False,
                })
                continue
            output = buf.getvalue()
            blocks.append({
                'target': tgt,
                'html':   _ansi_to_html(output),
                'cached': '(cache)' in output,  # détecté depuis la sortie texte de render_summary
            })

        return jsonify({
            'blocks':       blocks,
            'raw':          all_results,
            'target_label': target_label,
        })

    return app
