"""
webgui.py
=========
Browser dashboard for the deauthentication IDS.

WHY A BROWSER UI
----------------
The CLI prints one line per 2-second window: fine as a log, hard to read while
it happens, and unremarkable as a report screenshot. This serves a single-page
dashboard that shows the same decisions live -- a status banner that turns red
the instant the Random Forest flags a window, running counters, a rolling chart
of deauth frames against packet rate, and the per-window verdict table. The
offline half of the project (generate the dataset, train the model, inspect the
saved metrics and plots) is on the second tab.

NO NEW DEPENDENCIES
-------------------
Everything here is Python's standard library -- `http.server` for the server,
Server-Sent Events for the live push, and plain HTML/CSS/JS on the page. There
is no framework to install and nothing is fetched from the internet, so the
dashboard works fully offline.

HOW IT'S WIRED
--------------
No detection logic lives here. `realtime_detector.py` owns feature extraction
and classification; this file supplies an `on_result` callback and a
`should_stop` predicate, then fans results out to every connected browser:

    worker thread --run_sim/run_pcap/run_live--> on_result(dict)
                                                     |
                                              broadcast() -> one queue
                                                             per browser
                                                     |
    GET /events  (Server-Sent Events, one long-lived response per browser)
                                                     |
                                          page JS updates the DOM

The server binds to 127.0.0.1 only. This is a defensive tool that reports
attacks on your network; it is not something to expose to one.

SAFETY / SCOPE
--------------
Same as the CLI: passive and defensive. It never transmits, injects, or
deauthenticates anything -- it only classifies traffic it is shown. Live
capture still needs a monitor-mode interface and root, and should only be
pointed at a network you own or are authorised to test.

Run it with:   python src/webgui.py     (or: bash run_gui.sh)
"""

import json
import queue
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import config
import realtime_detector as rd

DEFAULT_PORT = 8765
MAX_HISTORY = 400          # verdict rows kept server-side for late joiners


# ===========================================================================
# The page. One file: inline CSS and JS, no external requests, works offline.
# ===========================================================================
INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Deauth IDS Console</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>&#128737;</text></svg>">
<style>
  :root{
    --bg:#0b0e14; --panel:#12161f; --panel2:#171d28; --raised:#1d2532;
    --border:#242c3a; --border2:#2f3949;
    --fg:#e9eef6; --dim:#9fadc0; --muted:#6c7a8d;
    --accent:#5aa2ff; --accent-dim:#16304f;
    --ok:#3ddc9a; --ok-dim:#0e3b2c;
    --alert:#ff5d6b; --warn:#ffb648;
    --radius:14px;
    --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
    --ui:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Roboto,
        "Helvetica Neue",Arial,sans-serif;
  }
  *{box-sizing:border-box}
  /* Must outrank the class rules below: a class selector like .ctlrow
     {display:flex} otherwise beats the UA stylesheet's [hidden] rule and the
     element stays visible when JS sets .hidden = true. */
  [hidden]{display:none !important}
  html,body{margin:0;padding:0}
  body{
    background:var(--bg); color:var(--fg); font-family:var(--ui);
    font-size:14px; line-height:1.5; -webkit-font-smoothing:antialiased;
    padding:0 0 60px;
  }
  .wrap{max-width:1360px; margin:0 auto; padding:0 28px}

  /* ---------- header ---------- */
  header{
    border-bottom:1px solid var(--border); background:rgba(11,14,20,.86);
    backdrop-filter:saturate(160%) blur(12px);
    position:sticky; top:0; z-index:20;
  }
  .hrow{display:flex; align-items:center; gap:16px; padding:18px 0}
  .brand{font-size:17px; font-weight:650; letter-spacing:.02em}
  .brand .dot{color:var(--accent)}
  .tagline{color:var(--muted); font-size:13px; flex:1}
  .badge{
    font-family:var(--mono); font-size:12px; padding:6px 12px;
    border-radius:999px; background:var(--raised); color:var(--dim);
    border:1px solid var(--border2); white-space:nowrap;
  }
  .badge.good{color:var(--ok); border-color:#1d4a3a}
  .badge.warn{color:var(--warn); border-color:#4a3a1a}

  /* ---------- tabs ---------- */
  nav{display:flex; gap:4px; margin-top:2px}
  nav button{
    background:none; border:0; color:var(--muted); font-family:var(--ui);
    font-size:14px; padding:11px 18px; cursor:pointer; border-radius:9px 9px 0 0;
    border-bottom:2px solid transparent; transition:color .15s,border-color .15s;
  }
  nav button:hover{color:var(--dim)}
  nav button[aria-selected="true"]{color:var(--fg); border-bottom-color:var(--accent)}
  section[hidden]{display:none}

  /* ---------- cards ---------- */
  .card{
    background:var(--panel); border:1px solid var(--border);
    border-radius:var(--radius); padding:20px; margin-top:20px;
  }
  .card h2{
    font-size:11px; letter-spacing:.10em; text-transform:uppercase;
    color:var(--muted); margin:0 0 16px; font-weight:650;
  }

  /* ---------- controls ---------- */
  .seg{display:inline-flex; background:var(--panel2); border-radius:10px;
       padding:4px; border:1px solid var(--border); gap:2px}
  .seg button{
    background:none; border:0; color:var(--muted); font-family:var(--ui);
    font-size:13.5px; padding:8px 16px; border-radius:7px; cursor:pointer;
    transition:background .15s,color .15s;
  }
  .seg button:hover{color:var(--dim)}
  .seg button[aria-pressed="true"]{background:var(--accent-dim); color:#cfe4ff}
  .hint{color:var(--muted); font-size:13px; margin-left:14px}

  .ctlrow{display:flex; align-items:center; gap:12px; flex-wrap:wrap;
          margin-top:16px}
  label.f{display:flex; align-items:center; gap:8px; color:var(--dim);
          font-size:13px}
  input[type=text],input[type=number]{
    background:var(--panel2); border:1px solid var(--border); color:var(--fg);
    border-radius:8px; padding:8px 11px; font-family:var(--mono);
    font-size:13px; outline:none; transition:border-color .15s;
  }
  input:focus{border-color:var(--accent)}
  input.w-file{width:340px}
  input.w-num{width:70px; text-align:right}
  .spacer{flex:1}

  button.btn{
    font-family:var(--ui); font-size:13.5px; font-weight:600; cursor:pointer;
    border-radius:9px; padding:10px 20px; border:1px solid transparent;
    transition:background .15s,opacity .15s;
  }
  .btn.primary{background:var(--accent); color:#06121f}
  .btn.primary:hover{background:#79b5ff}
  .btn.danger{background:var(--alert); color:#2a0509}
  .btn.danger:hover{background:#ff828d}
  .btn.ghost{background:var(--raised); color:var(--fg); border-color:var(--border2)}
  .btn.ghost:hover{background:#252f3f}
  .btn:disabled{opacity:.38; cursor:not-allowed}

  /* ---------- banner ---------- */
  .banner{
    display:flex; align-items:stretch; gap:0; margin-top:20px;
    background:var(--panel); border:1px solid var(--border);
    border-radius:var(--radius); overflow:hidden;
    transition:background .25s, border-color .25s;
  }
  .banner .bar{width:6px; background:var(--muted); transition:background .25s}
  .banner .txt{padding:20px 24px}
  .banner h3{margin:0; font-size:23px; font-weight:680; letter-spacing:.01em;
             color:var(--muted); transition:color .25s}
  .banner p{margin:4px 0 0; color:var(--dim); font-size:13.5px}
  .banner.alert{background:#1c0f13; border-color:#4d2027}
  .banner.alert h3{color:var(--alert)}
  .banner.ok h3{color:var(--ok)}
  .banner.info h3{color:var(--accent)}
  .banner.warn h3{color:var(--warn)}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.55}}
  .banner.alert .bar{animation:pulse 1.1s ease-in-out infinite}

  /* ---------- tiles ---------- */
  .tiles{display:grid; grid-template-columns:repeat(4,1fr); gap:14px;
         margin-top:20px}
  .tile{background:var(--panel); border:1px solid var(--border);
        border-radius:var(--radius); padding:16px 18px; position:relative;
        overflow:hidden}
  .tile::before{content:""; position:absolute; inset:0 0 auto 0; height:3px;
                background:var(--muted)}
  .tile.accent::before{background:var(--accent)}
  .tile.ok::before{background:var(--ok)}
  .tile.alert::before{background:var(--alert)}
  .tile .v{font-family:var(--mono); font-size:29px; font-weight:640;
           letter-spacing:-.02em; font-variant-numeric:tabular-nums;
           margin-top:6px}
  .tile.accent .v{color:var(--accent)}
  .tile.ok .v{color:var(--ok)}
  .tile.alert .v{color:var(--alert)}
  .tile .c{font-size:11px; letter-spacing:.09em; text-transform:uppercase;
           color:var(--muted); margin-top:4px}

  /* ---------- chart ---------- */
  .chart-head{display:flex; align-items:center; margin-bottom:12px}
  .legend{margin-left:auto; display:flex; gap:16px; font-size:12px;
          color:var(--muted)}
  .legend i{display:inline-block; width:10px; height:10px; border-radius:2px;
            margin-right:6px; vertical-align:-1px}
  canvas{width:100%; height:190px; display:block}

  /* ---------- table ---------- */
  .tbl-wrap{max-height:340px; overflow:auto; border-radius:9px;
            border:1px solid var(--border)}
  table{width:100%; border-collapse:collapse; font-family:var(--mono);
        font-size:12.5px; font-variant-numeric:tabular-nums}
  thead th{
    position:sticky; top:0; background:var(--panel2); color:var(--muted);
    font-family:var(--ui); font-size:11px; letter-spacing:.07em;
    text-transform:uppercase; font-weight:650; text-align:right;
    padding:11px 14px; border-bottom:1px solid var(--border);
  }
  thead th:nth-child(1),thead th:nth-child(2){text-align:left}
  tbody td{padding:8px 14px; text-align:right; color:var(--dim);
           border-bottom:1px solid rgba(36,44,58,.5)}
  tbody td:nth-child(1),tbody td:nth-child(2){text-align:left}
  tbody tr.attack td{color:var(--alert); background:rgba(255,93,107,.07)}
  tbody tr.normal td:nth-child(2){color:var(--ok)}
  tbody tr:last-child td{border-bottom:0}
  .empty{padding:34px; text-align:center; color:var(--muted); font-size:13px}

  /* ---------- model tab ---------- */
  .two{display:grid; grid-template-columns:300px 1fr; gap:20px; margin-top:20px}
  pre.art{font-family:var(--mono); font-size:12px; color:var(--dim); margin:0;
          white-space:pre-wrap; line-height:1.7}
  select{
    background:var(--panel2); border:1px solid var(--border); color:var(--fg);
    border-radius:8px; padding:8px 11px; font-family:var(--ui); font-size:13px;
    outline:none; cursor:pointer;
  }
  .plot{margin-top:14px; text-align:center; background:#fff; border-radius:9px;
        padding:10px}
  .plot img{max-width:100%; max-height:460px; object-fit:contain;
            display:block; margin:0 auto}

  /* ---------- log ---------- */
  pre.log{
    font-family:var(--mono); font-size:12.5px; line-height:1.65; margin:0;
    max-height:600px; overflow:auto; color:var(--dim); white-space:pre-wrap;
    word-break:break-word;
  }
  .log .l-alert{color:var(--alert)}
  .log .l-ok{color:var(--ok)}
  .log .l-warn{color:var(--warn)}
  .log .l-meta{color:var(--muted)}
  .status-note{font-size:13px; color:var(--muted); margin-top:12px}

  @media (max-width:1000px){
    .tiles{grid-template-columns:repeat(2,1fr)}
    .two{grid-template-columns:1fr}
    input.w-file{width:100%}
  }
</style>
</head>
<body>

<header>
  <div class="wrap">
    <div class="hrow">
      <div class="brand"><span class="dot">&#9679;</span> DEAUTH IDS CONSOLE</div>
      <div class="tagline">Random Forest &middot; 802.11 deauthentication detection &middot; passive</div>
      <div class="badge" id="modelBadge">model: loading&hellip;</div>
    </div>
    <nav>
      <button id="t0" aria-selected="true" onclick="tab(0)">Live Detection</button>
      <button id="t1" aria-selected="false" onclick="tab(1)">Model &amp; Dataset</button>
      <button id="t2" aria-selected="false" onclick="tab(2)">Console Log</button>
    </nav>
  </div>
</header>

<div class="wrap">

<!-- ================= LIVE ================= -->
<section id="s0">
  <div class="card">
    <h2>Traffic source</h2>
    <div>
      <span class="seg">
        <button id="m-sim"  aria-pressed="true"  onclick="setMode('sim')">Simulation</button>
        <button id="m-pcap" aria-pressed="false" onclick="setMode('pcap')">PCAP replay</button>
        <button id="m-live" aria-pressed="false" onclick="setMode('live')">Live capture</button>
      </span>
      <span class="hint" id="modeHint">synthetic frames &mdash; no hardware needed</span>
    </div>

    <div class="ctlrow" id="optPcap" hidden>
      <label class="f">capture file
        <input type="text" id="pcapPath" class="w-file">
      </label>
    </div>
    <div class="ctlrow" id="optLive" hidden>
      <label class="f">monitor interface
        <input type="text" id="iface" class="w-num" style="width:130px" value="wlan0mon">
      </label>
      <span class="hint" style="color:var(--warn)">requires root + monitor mode</span>
    </div>

    <div class="ctlrow">
      <label class="f">window
        <input type="number" id="winSecs" class="w-num" value="2.0" step="0.5" min="0.5">
      </label>
      <span class="hint" style="margin-left:0">seconds</span>
      <label class="f" style="margin-left:10px">windows
        <input type="number" id="nWin" class="w-num" value="20" min="0">
      </label>
      <span class="hint" style="margin-left:0">0 = until stopped</span>
      <span class="spacer"></span>
      <button class="btn ghost"   id="btnClear" onclick="clearRun()">Clear</button>
      <button class="btn primary" id="btnStart" onclick="start()">Start monitoring</button>
      <button class="btn danger"  id="btnStop"  onclick="stop()" disabled>Stop</button>
    </div>
  </div>

  <div class="banner" id="banner">
    <div class="bar" id="bannerBar"></div>
    <div class="txt">
      <h3 id="bannerTitle">IDLE</h3>
      <p id="bannerSub">Choose a traffic source and press Start monitoring.</p>
    </div>
  </div>

  <div class="tiles">
    <div class="tile accent"><div class="v" id="kWin">0</div><div class="c">windows analysed</div></div>
    <div class="tile ok"    id="tileAlerts"><div class="v" id="kAlerts">0</div><div class="c">attack windows</div></div>
    <div class="tile"><div class="v" id="kFrames">0</div><div class="c">frames inspected</div></div>
    <div class="tile" id="tileDeauth"><div class="v" id="kDeauth">0</div><div class="c">deauth frames</div></div>
  </div>

  <div class="card">
    <div class="chart-head">
      <h2 style="margin:0">Recent windows</h2>
      <span class="legend">
        <span><i style="background:#2f6f96"></i>deauth frames</span>
        <span><i style="background:#ffb648"></i>packet rate</span>
        <span><i style="background:#ff5d6b"></i>flagged</span>
      </span>
    </div>
    <canvas id="chart"></canvas>
  </div>

  <div class="card">
    <h2>Per-window verdicts</h2>
    <div class="tbl-wrap">
      <table>
        <thead><tr>
          <th>Time</th><th>Verdict</th><th>Conf.</th><th>Frames</th>
          <th>Deauth</th><th>Rate /s</th><th>Avg len</th><th>RSSI dBm</th>
        </tr></thead>
        <tbody id="rows"></tbody>
      </table>
      <div class="empty" id="tblEmpty">No windows classified yet.</div>
    </div>
  </div>
</section>

<!-- ================= MODEL ================= -->
<section id="s1" hidden>
  <div class="tiles" style="margin-top:20px">
    <div class="tile accent"><div class="v" id="mAcc">&mdash;</div><div class="c">accuracy</div></div>
    <div class="tile accent"><div class="v" id="mPre">&mdash;</div><div class="c">precision</div></div>
    <div class="tile accent"><div class="v" id="mRec">&mdash;</div><div class="c">recall</div></div>
    <div class="tile ok"><div class="v" id="mF1">&mdash;</div><div class="c">f1 score</div></div>
  </div>

  <div class="card">
    <h2>Pipeline</h2>
    <div class="ctlrow" style="margin-top:0">
      <button class="btn ghost pipe" onclick="runScript('generate_dataset.py')">1 &middot; Generate dataset</button>
      <button class="btn ghost pipe" onclick="runScript('train_model.py')">2 &middot; Train model</button>
      <button class="btn ghost pipe" onclick="runScript('make_demo_pcap.py')">3 &middot; Make demo PCAP</button>
      <button class="btn primary pipe" onclick="runScript('generate_dataset.py','train_model.py')">Run 1 &rarr; 2</button>
    </div>
    <div class="status-note" id="pipeStatus">Output streams to the Console Log tab.</div>
  </div>

  <div class="two">
    <div class="card" style="margin-top:0">
      <h2>Artefacts</h2>
      <pre class="art" id="artefacts">loading&hellip;</pre>
    </div>
    <div class="card" style="margin-top:0">
      <div class="chart-head">
        <h2 style="margin:0">Generated plots</h2>
        <span class="legend"><select id="plotSel" onchange="showPlot()"></select></span>
      </div>
      <div class="plot" id="plotBox"><span style="color:#888">no plots yet</span></div>
    </div>
  </div>
</section>

<!-- ================= LOG ================= -->
<section id="s2" hidden>
  <div class="card">
    <h2>Console log</h2>
    <pre class="log" id="log"></pre>
  </div>
</section>

</div>

<script>
// ------------------------------------------------------------------ state
let mode = "sim";
let stats = {win:0, alerts:0, frames:0, deauth:0};
let hist = [];                      // recent results, for the chart
const MAXBARS = 40;

function $(id){ return document.getElementById(id); }
function fmt(n){ return n.toLocaleString(); }

// ------------------------------------------------------------------ tabs
function tab(i){
  for(let k=0;k<3;k++){
    $("t"+k).setAttribute("aria-selected", k===i ? "true":"false");
    $("s"+k).hidden = (k!==i);
  }
  if(i===0) drawChart();
}

// ------------------------------------------------------------------ mode
const HINTS = {
  sim:  "synthetic frames — no hardware needed",
  pcap: "replay a capture file offline",
  live: "sniff a real monitor-mode interface",
};
function setMode(m){
  mode = m;
  for(const k of ["sim","pcap","live"])
    $("m-"+k).setAttribute("aria-pressed", k===m ? "true":"false");
  $("modeHint").textContent = HINTS[m];
  $("optPcap").hidden = (m!=="pcap");
  $("optLive").hidden = (m!=="live");
}

// ------------------------------------------------------------------ banner
function banner(kind, title, sub){
  const b = $("banner");
  b.className = "banner " + kind;
  const col = {alert:"var(--alert)", ok:"var(--ok)", info:"var(--accent)",
               warn:"var(--warn)", "":"var(--muted)"}[kind] || "var(--muted)";
  $("bannerBar").style.background = col;
  $("bannerTitle").textContent = title;
  $("bannerSub").textContent = sub || "";
}

// ------------------------------------------------------------------ tiles
function paintTiles(){
  $("kWin").textContent    = fmt(stats.win);
  $("kAlerts").textContent = fmt(stats.alerts);
  $("kFrames").textContent = fmt(stats.frames);
  $("kDeauth").textContent = fmt(stats.deauth);
  $("tileAlerts").className = "tile " + (stats.alerts ? "alert" : "ok");
  $("tileDeauth").className = "tile " + (stats.deauth > 50 ? "alert" : "");
}

// ------------------------------------------------------------------ table
function addRow(r){
  $("tblEmpty").style.display = "none";
  const f = r.feats, atk = r.pred === 1;
  const tr = document.createElement("tr");
  tr.className = atk ? "attack" : "normal";
  const cells = [
    r.time,
    atk ? "ATTACK — deauth flood" : "normal traffic",
    r.conf.toFixed(2),
    fmt(r.n_frames),
    fmt(Math.round(f.deauth_count)),
    Math.round(f.packet_rate),
    Math.round(f.frame_length),
    Math.round(f.rssi),
  ];
  for(const c of cells){
    const td = document.createElement("td");
    td.textContent = c;
    tr.appendChild(td);
  }
  const body = $("rows");
  body.appendChild(tr);
  while(body.children.length > 400) body.removeChild(body.firstChild);
  const w = body.parentElement.parentElement;
  w.scrollTop = w.scrollHeight;
}

// ------------------------------------------------------------------ chart
function drawChart(){
  const cv = $("chart");
  const dpr = window.devicePixelRatio || 1;
  const W = cv.clientWidth, H = cv.clientHeight;
  if(!W || !H) return;
  cv.width = W*dpr; cv.height = H*dpr;
  const g = cv.getContext("2d");
  g.setTransform(dpr,0,0,dpr,0,0);
  g.clearRect(0,0,W,H);

  const padL=42, padR=46, padT=12, padB=22;
  const plotW = W-padL-padR, plotH = H-padT-padB;

  // grid
  g.strokeStyle = "#242c3a"; g.lineWidth = 1;
  g.font = "10px ui-monospace, Menlo, monospace";
  g.fillStyle = "#6c7a8d";
  for(let i=0;i<=4;i++){
    const y = padT + plotH*i/4;
    g.beginPath(); g.moveTo(padL,y); g.lineTo(W-padR,y); g.stroke();
  }
  if(!hist.length){
    g.fillStyle="#6c7a8d"; g.textAlign="center";
    g.fillText("waiting for traffic…", W/2, H/2);
    return;
  }

  const maxD = Math.max(10, ...hist.map(h=>h.feats.deauth_count));
  const maxR = Math.max(10, ...hist.map(h=>h.feats.packet_rate));
  const n = Math.max(hist.length, 12);
  const bw = plotW/n;

  // y labels
  g.textAlign="right"; g.fillStyle="#6c7a8d";
  for(let i=0;i<=4;i++){
    const y = padT + plotH*i/4;
    g.fillText(Math.round(maxD*(1-i/4)), padL-8, y+3);
  }
  g.textAlign="left";
  for(let i=0;i<=4;i++){
    const y = padT + plotH*i/4;
    g.fillStyle="#8a7040";
    g.fillText(Math.round(maxR*(1-i/4)), W-padR+8, y+3);
  }

  // bars
  hist.forEach((h,i)=>{
    const v = h.feats.deauth_count/maxD;
    const bh = Math.max(v*plotH, v>0?1.5:0);
    g.fillStyle = h.pred===1 ? "#ff5d6b" : "#2f6f96";
    g.fillRect(padL + i*bw + bw*0.16, padT+plotH-bh, bw*0.68, bh);
  });

  // rate line
  g.strokeStyle="#ffb648"; g.lineWidth=1.8; g.beginPath();
  hist.forEach((h,i)=>{
    const x = padL + i*bw + bw/2;
    const y = padT + plotH*(1 - h.feats.packet_rate/maxR);
    i ? g.lineTo(x,y) : g.moveTo(x,y);
  });
  g.stroke();
}
window.addEventListener("resize", drawChart);

// ------------------------------------------------------------------ log
function logLine(text, cls){
  const el = $("log");
  const span = document.createElement("span");
  span.className = "l-" + (cls||"meta");
  span.textContent = text + "\n";
  el.appendChild(span);
  while(el.children.length > 2000) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
}

// ------------------------------------------------------------------ actions
function running(on){
  $("btnStart").disabled = on;
  $("btnStop").disabled  = !on;
}
function clearRun(){
  stats = {win:0, alerts:0, frames:0, deauth:0};
  hist = [];
  $("rows").innerHTML = "";
  $("tblEmpty").style.display = "";
  paintTiles(); drawChart();
}
async function start(){
  clearRun();
  const body = {
    mode: mode,
    window: parseFloat($("winSecs").value),
    n_windows: parseInt($("nWin").value, 10),
    pcap: $("pcapPath").value,
    iface: $("iface").value,
  };
  running(true);
  banner("info","MONITORING","starting …");
  const r = await fetch("/api/start",{method:"POST",body:JSON.stringify(body)});
  const j = await r.json();
  if(!j.ok){ running(false); banner("warn","CANNOT START", j.error); }
}
async function stop(){
  $("btnStop").disabled = true;
  banner("warn","STOPPING","waiting for the current window");
  await fetch("/api/stop",{method:"POST"});
}
async function runScript(script, then){
  document.querySelectorAll(".pipe").forEach(b=>b.disabled=true);
  $("pipeStatus").textContent = "running " + script + " …";
  tab(2);
  await fetch("/api/pipeline",{method:"POST",
              body:JSON.stringify({script:script, then:then||null})});
}

// ------------------------------------------------------------------ meta
async function loadMeta(){
  const m = await (await fetch("/api/meta")).json();
  const b = $("modelBadge");
  if(m.metrics && m.metrics.f1 !== undefined){
    b.textContent = "RF · F1 " + m.metrics.f1.toFixed(3) +
                    " · acc " + m.metrics.accuracy.toFixed(3);
    b.className = "badge good";
  }else{
    b.textContent = "model: not trained";
    b.className = "badge warn";
  }
  const set = (id,k)=> $(id).textContent =
      (m.metrics && m.metrics[k]!==undefined) ? m.metrics[k].toFixed(3) : "—";
  set("mAcc","accuracy"); set("mPre","precision");
  set("mRec","recall");   set("mF1","f1");

  $("artefacts").textContent = m.artefacts;
  if(m.pcap_default && !$("pcapPath").value) $("pcapPath").value = m.pcap_default;

  const sel = $("plotSel"), cur = sel.value;
  sel.innerHTML = "";
  for(const p of m.plots){
    const o = document.createElement("option");
    o.value = p; o.textContent = p; sel.appendChild(o);
  }
  if(cur && m.plots.includes(cur)) sel.value = cur;
  showPlot();
}
function showPlot(){
  const name = $("plotSel").value;
  const box = $("plotBox");
  if(!name){ box.innerHTML = '<span style="color:#888">no plots yet</span>'; return; }
  box.innerHTML = "";
  const img = document.createElement("img");
  img.src = "/api/plot?name=" + encodeURIComponent(name) + "&t=" + Date.now();
  img.alt = name;
  box.appendChild(img);
}

// ------------------------------------------------------------------ SSE
function connect(){
  const es = new EventSource("/events");
  es.onmessage = (ev)=>{
    const m = JSON.parse(ev.data);
    if(m.type === "result"){
      const r = m.data, f = r.feats, atk = r.pred===1;
      stats.win++; stats.frames += r.n_frames;
      stats.deauth += Math.round(f.deauth_count);
      if(atk) stats.alerts++;
      hist.push(r); if(hist.length>MAXBARS) hist.shift();
      paintTiles(); addRow(r); drawChart();
      logLine(m.line, atk ? "alert" : "ok");
      if(atk){
        banner("alert","ATTACK DETECTED",
          fmt(Math.round(f.deauth_count)) + " deauth frames · " +
          Math.round(f.packet_rate) + " frames/s · confidence " +
          Math.round(r.conf*100) + "%");
      }else{
        banner("ok","MONITORING — NORMAL",
          "window " + stats.win + " · " + fmt(r.n_frames) +
          " frames · " + stats.alerts + " alert(s) so far");
      }
    }
    else if(m.type === "log"){ logLine(m.text, m.cls); }
    else if(m.type === "error"){
      logLine(m.text,"warn"); banner("alert","ERROR", m.text); running(false);
    }
    else if(m.type === "done"){
      running(false);
      if(stats.win === 0){
        banner("warn","NO TRAFFIC CLASSIFIED","the source produced no 802.11 frames");
      }else{
        const pct = Math.round(100*stats.alerts/stats.win);
        banner("info","RUN " + m.why.toUpperCase(),
          stats.win + " windows · " + stats.alerts + " attack windows (" +
          pct + "%) · " + fmt(stats.frames) + " frames inspected");
      }
    }
    else if(m.type === "script_done"){
      document.querySelectorAll(".pipe").forEach(b=>b.disabled=false);
      $("pipeStatus").textContent =
        m.script + (m.code===0 ? " finished" : " failed (exit "+m.code+")");
      loadMeta();
    }
    else if(m.type === "running"){ running(m.value); }
  };
  es.onerror = ()=>{ /* EventSource retries on its own */ };
}

setMode("sim"); paintTiles(); loadMeta(); connect(); drawChart();
</script>
</body>
</html>
"""


# ===========================================================================
# Server state: one detection run at a time, fanned out to every browser.
# ===========================================================================
class Hub:
    def __init__(self):
        self.subscribers = set()          # queue.Queue per connected browser
        self.lock = threading.Lock()
        self.worker = None
        self.stop_flag = threading.Event()
        self.model = self.scaler = None
        self.meta = {}
        self.load_model()

    # -- model ---------------------------------------------------------
    def load_model(self):
        try:
            self.model, self.scaler, self.meta = rd.load_model()
            return True
        except (SystemExit, Exception):
            # Missing artefacts raise SystemExit; a stale pickle raises
            # something else. Either way the dashboard must still come up --
            # the Pipeline card is how the user fixes it.
            self.model = self.scaler = None
            self.meta = {}
            return False

    # -- pub/sub -------------------------------------------------------
    def subscribe(self):
        q = queue.Queue()
        with self.lock:
            self.subscribers.add(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            self.subscribers.discard(q)

    def broadcast(self, msg):
        with self.lock:
            targets = list(self.subscribers)
        for q in targets:
            q.put(msg)

    # -- detection runs ------------------------------------------------
    def is_running(self):
        return self.worker is not None and self.worker.is_alive()

    def start(self, mode, window, n_windows, pcap, iface):
        if self.is_running():
            return "a run is already in progress"
        if self.model is None and not self.load_model():
            return "no trained model - run the pipeline first"
        if mode == "pcap" and not Path(pcap).exists():
            return f"capture file not found: {pcap}"

        self.stop_flag.clear()
        self.worker = threading.Thread(
            target=self._run, args=(mode, window, n_windows, pcap, iface),
            daemon=True)
        self.worker.start()
        return None

    def _run(self, mode, window, n_windows, pcap, iface):
        def push(r):
            self.broadcast({"type": "result", "data": r,
                            "line": rd.format_result(r)})
        stop = self.stop_flag.is_set
        try:
            if mode == "sim":
                # Recurring bursts keep a continuous run interesting; a finite
                # run keeps the CLI's deterministic windows 8-12.
                attack = None if n_windows else (lambda w: 8 <= (w % 20) <= 12)
                rd.run_sim(window, self.model, self.scaler,
                           n_windows=n_windows, attack_windows=attack,
                           on_result=push, should_stop=stop, pause=0.35)
            elif mode == "pcap":
                self.broadcast({"type": "log", "text": f"[pcap] reading {pcap}",
                                "cls": "meta"})
                rd.run_pcap(pcap, window, self.model, self.scaler,
                            on_result=push, should_stop=stop)
            else:
                self.broadcast({"type": "log",
                                "text": f"[live] sniffing {iface}",
                                "cls": "meta"})
                rd.run_live(iface, window, self.model, self.scaler,
                            on_result=push, should_stop=stop)
        except SystemExit as e:
            self.broadcast({"type": "error", "text": str(e)})
        except PermissionError:
            self.broadcast({"type": "error",
                            "text": "Live capture needs root. Re-launch with "
                                    "sudo, or use Simulation / PCAP mode."})
        except Exception as e:
            self.broadcast({"type": "error", "text": f"{type(e).__name__}: {e}"})
        finally:
            self.broadcast({"type": "done",
                            "why": "stopped" if stop() else "finished"})

    def stop(self):
        self.stop_flag.set()

    # -- pipeline scripts ----------------------------------------------
    def run_script(self, script, then=None):
        threading.Thread(target=self._script, args=(script, then),
                         daemon=True).start()

    def _script(self, script, then):
        allowed = {"generate_dataset.py", "train_model.py",
                   "make_demo_pcap.py", "make_slides.py"}
        if script not in allowed:
            self.broadcast({"type": "script_done", "script": script, "code": 1})
            return
        path = Path(__file__).resolve().parent / script
        self.broadcast({"type": "log", "text": f"\n$ python src/{script}",
                        "cls": "meta"})
        try:
            proc = subprocess.Popen(
                [sys.executable, str(path)], stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
                cwd=str(config.ROOT_DIR))
            for line in proc.stdout:
                self.broadcast({"type": "log", "text": line.rstrip("\n"),
                                "cls": "meta"})
            code = proc.wait()
        except Exception as e:
            self.broadcast({"type": "log", "text": f"[error] {e}",
                            "cls": "warn"})
            code = 1
        self.broadcast({"type": "log", "text": f"[exit {code}] {script}",
                        "cls": "ok" if code == 0 else "warn"})
        self.load_model()
        if code == 0 and then:
            self._script(then, None)
            return
        self.broadcast({"type": "script_done", "script": script, "code": code})

    # -- metadata for the Model tab ------------------------------------
    def meta_payload(self):
        lines = []
        for label, path in (("dataset", config.RAW_DATASET),
                            ("model", config.MODEL_PATH),
                            ("scaler", config.SCALER_PATH),
                            ("metadata", config.METADATA_PATH),
                            ("demo pcap", config.DATA_DIR / "demo_capture.pcap")):
            if path.exists():
                kb = path.stat().st_size / 1024
                size = f"{kb/1024:.1f} MB" if kb > 1024 else f"{kb:.0f} KB"
                lines.append(f"[ok] {label:<10}{size:>9}")
            else:
                lines.append(f"[--] {label:<10}{'missing':>9}")
        if config.RAW_DATASET.exists():
            try:
                import pandas as pd
                df = pd.read_csv(config.RAW_DATASET)
                n_atk = int(df[config.LABEL_COLUMN].sum())
                lines += ["", f"rows      {len(df):>8,}",
                          f"attack    {n_atk:>8,}",
                          f"normal    {len(df) - n_atk:>8,}"]
            except Exception:
                pass
        lines += ["", f"features  {len(config.FEATURE_COLUMNS):>8}"]
        lines += [f"  {c}" for c in config.FEATURE_COLUMNS]
        return {
            "metrics": self.meta.get("metrics", {}),
            "artefacts": "\n".join(lines),
            "plots": sorted(p.name for p in config.OUTPUT_DIR.glob("*.png")),
            "pcap_default": str(config.DATA_DIR / "demo_capture.pcap"),
        }


HUB = Hub()


# ===========================================================================
# HTTP
# ===========================================================================
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "DeauthIDS"

    def log_message(self, fmt, *args):      # keep the terminal clean
        pass

    # -- helpers -------------------------------------------------------
    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    # -- GET -----------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        elif u.path == "/api/meta":
            self._json(HUB.meta_payload())
        elif u.path == "/api/plot":
            self._serve_plot(parse_qs(u.query).get("name", [""])[0])
        elif u.path == "/events":
            self._events()
        else:
            self._json({"error": "not found"}, 404)

    def _serve_plot(self, name):
        # Resolve inside outputs/ and confirm it stayed there: the name comes
        # from the page, so treat it as untrusted and refuse traversal.
        try:
            path = (config.OUTPUT_DIR / name).resolve()
            path.relative_to(config.OUTPUT_DIR.resolve())
        except (ValueError, OSError):
            self._json({"error": "bad path"}, 400)
            return
        if not path.is_file() or path.suffix.lower() != ".png":
            self._json({"error": "not found"}, 404)
            return
        self._send(200, path.read_bytes(), "image/png")

    def _events(self):
        """One long-lived Server-Sent Events response per browser."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        q = HUB.subscribe()
        # Tell a freshly-connected page whether a run is already going.
        q.put({"type": "running", "value": HUB.is_running()})
        try:
            while True:
                try:
                    msg = q.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")   # hold the socket
                    self.wfile.flush()
                    continue
                payload = json.dumps(msg).encode("utf-8")
                self.wfile.write(b"data: " + payload + b"\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass                                   # browser navigated away
        finally:
            HUB.unsubscribe(q)

    # -- POST ----------------------------------------------------------
    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/start":
            b = self._body()
            try:
                window = float(b.get("window", 2.0))
                n_windows = int(b.get("n_windows", 20))
            except (TypeError, ValueError):
                self._json({"ok": False, "error": "window and windows must be numbers"})
                return
            err = HUB.start(b.get("mode", "sim"), window, n_windows,
                            b.get("pcap", ""), b.get("iface", "wlan0mon"))
            self._json({"ok": err is None, "error": err})
        elif u.path == "/api/stop":
            HUB.stop()
            self._json({"ok": True})
        elif u.path == "/api/pipeline":
            b = self._body()
            HUB.run_script(b.get("script", ""), b.get("then"))
            self._json({"ok": True})
        else:
            self._json({"error": "not found"}, 404)


def main():
    port = DEFAULT_PORT
    for attempt in range(20):
        try:
            # 127.0.0.1 only: this dashboard reports on attacks, it should
            # never be reachable from the network it is watching.
            httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            port += 1
    else:
        raise SystemExit("[error] no free port in 8765-8785")

    httpd.daemon_threads = True
    url = f"http://127.0.0.1:{port}/"
    print(f"[webgui] Deauth IDS console -> {url}")
    print("[webgui] Ctrl-C to stop.")
    if HUB.model is None:
        print("[webgui] no trained model yet - use the Pipeline card in the "
              "Model & Dataset tab.")
    threading.Thread(target=lambda: (time.sleep(0.7), webbrowser.open(url)),
                     daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[webgui] bye.")


if __name__ == "__main__":
    main()
