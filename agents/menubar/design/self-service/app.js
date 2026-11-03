/* Patched — Self Service · board renderer
   One consistent dataset across all six screens; native split-view chrome. */

/* ───────── SF Symbol-style icons ───────── */
const ICONS = {
  grid: '<rect x="4" y="4" width="7" height="7" rx="1.6"/><rect x="13" y="4" width="7" height="7" rx="1.6"/><rect x="4" y="13" width="7" height="7" rx="1.6"/><rect x="13" y="13" width="7" height="7" rx="1.6"/>',
  downcircle: '<circle cx="12" cy="12" r="8.4"/><path d="M12 8v8M8.4 12.4L12 16l3.6-3.6"/>',
  stack: '<path d="M12 3.2l8 4-8 4-8-4 8-4z"/><path d="M4.2 11.4L12 15.3l7.8-3.9M4.2 15.3L12 19.2l7.8-3.9"/>',
  shieldcheck: '<path d="M12 3.2l7 2.4v5.1c0 4.4-2.9 7.6-7 8.9-4.1-1.3-7-4.5-7-8.9V5.6l7-2.4z"/><path d="M8.7 11.7l2.3 2.3 4.3-4.5"/>',
  doctext: '<path d="M6.5 3.5h7l4.5 4.5v12a1 1 0 0 1-1 1h-10.5a1 1 0 0 1-1-1V4.5a1 1 0 0 1 1-1z"/><path d="M13 3.6V8h4.4M8.5 12.5h7M8.5 15.5h7M8.5 9.5h3"/>',
  laptop: '<rect x="4.5" y="5.5" width="15" height="9.5" rx="1.6"/><path d="M2.5 18.5h19"/>',
  sidebar: '<rect x="3.5" y="5" width="17" height="14" rx="2.2"/><path d="M9 5v14"/>',
  search: '<circle cx="11" cy="11" r="6"/><path d="M15.5 15.5L20 20"/>',
  refresh: '<path d="M19 12a7 7 0 1 1-2.1-5"/><path d="M19.2 5v3.4h-3.4"/>',
  export: '<path d="M12 15V4.5M8.4 7.6L12 4l3.6 3.6"/><path d="M5.5 13v5.5a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1V13"/>',
  seal: '<path d="M12 3l2.1 1.6 2.6-.3 1 2.4 2.3 1.2-.6 2.6 1.3 2.3-1.8 1.9.2 2.6-2.5.7-1.2 2.3-2.6-.5L12 21l-2.1-1.3-2.6.5-1.2-2.3-2.5-.7.2-2.6L2 12.1 3.3 9.8l-.6-2.6L5 6l1-2.4 2.6.3z"/><path d="M9.2 12l2 2 3.6-3.8"/>',
  lock: '<rect x="5.2" y="10.8" width="13.6" height="8.4" rx="2"/><path d="M7.6 10.8V8.2a4.4 4.4 0 0 1 8.8 0v2.6"/>',
  warning: '<path d="M12 4.2l8.4 14.6H3.6L12 4.2z"/><path d="M12 10v4.2"/><circle cx="12" cy="16.8" r="0.5" fill="currentColor" stroke="none"/>',
  chevron: '<path d="M9.5 6l6 6-6 6"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7"/>',
  info: '<circle cx="12" cy="12" r="8.2"/><path d="M12 11v5"/><circle cx="12" cy="8" r="0.6" fill="currentColor" stroke="none"/>',
  clock: '<circle cx="12" cy="12" r="8.2"/><path d="M12 7.4V12l3.2 1.9"/>',
  calendar: '<rect x="4" y="5.5" width="16" height="14" rx="2"/><path d="M4 9.5h16M8.5 3.5v3M15.5 3.5v3"/>',
  cpu: '<rect x="7" y="7" width="10" height="10" rx="1.8"/><path d="M10 4.5v2.5M14 4.5v2.5M10 17v2.5M14 17v2.5M4.5 10H7M4.5 14H7M17 10h2.5M17 14h2.5"/>',
  bell: '<path d="M6 9.5a6 6 0 0 1 12 0c0 5 1.5 6.5 1.5 6.5h-15S6 14.5 6 9.5z"/><path d="M10 19a2 2 0 0 0 4 0"/>',
  arrowright: '<path d="M5 12h13M13 6.5l5.5 5.5L13 17.5"/>',
  gear: '<circle cx="12" cy="12" r="3.2"/><path d="M12 4.2v2.2M12 17.6v2.2M19.8 12h-2.2M6.4 12H4.2M17.5 6.5l-1.6 1.6M8.1 15.9l-1.6 1.6M17.5 17.5l-1.6-1.6M8.1 8.1L6.5 6.5"/>',
  bolt: '<path d="M13 3L5.5 13.2H11l-1 7.8L18.5 10.8H13l0-7.8z"/>',
  person: '<circle cx="12" cy="8.5" r="3.6"/><path d="M5.5 19.5a6.5 6.5 0 0 1 13 0"/>',
  key: '<circle cx="8" cy="12" r="3.6"/><path d="M11.4 11h8.1M17 11v3M19.5 11v2.4"/>',
  plus: '<path d="M12 5.5v13M5.5 12h13"/>',
  globe: '<circle cx="12" cy="12" r="8.2"/><path d="M3.8 12h16.4M12 3.8c2.2 2.3 3.4 5.2 3.4 8.2S14.2 17.9 12 20.2c-2.2-2.3-3.4-5.2-3.4-8.2S9.8 6.1 12 3.8z"/>',
  xmark: '<path d="M6 6l12 12M18 6L6 18"/>',
};
function sf(name, size = 16, stroke = 1.7) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${stroke}" stroke-linecap="round" stroke-linejoin="round">${ICONS[name] || ''}</svg>`;
}

/* ───────── Shared data ───────── */
const TIER = { name: 'Endpoint Assurance', tagline: 'Continuous scanning, evidence and specialist review' };
const DEVICE = {
  name: 'Dana’s MacBook Pro', model: 'MacBook Pro 14" · M3 Pro', os: 'macOS 14.5 (23F79)',
  serial: 'C02••••••QX7L', agent: '1.4.2', schedule: 'Continuous · last scan 2 min ago', appCount: 247,
};
const UPDATES = [
  { letter: 'Sa', tint: '#1a73e8', app: 'Safari', from: '17.4', to: '17.5', cve: 'CVE-2026-1842', sev: 'high', source: 'Apple', hash: 'a1f3…9e2c' },
  { letter: 'Ch', tint: '#11a36b', app: 'Google Chrome', from: '125.0', to: '126.0', cve: 'CVE-2026-2011', sev: 'med', source: 'Google', hash: '5b7e…11dd' },
  { letter: 'Zo', tint: '#2b6cff', app: 'Zoom', from: '6.0.10', to: '6.1.2', cve: 'CVE-2026-1990', sev: 'med', source: 'Zoom', hash: 'c0a4…77fb' },
];
const CATALOG = [
  { letter: '1P', tint: '#1564ff', app: '1Password', pub: 'AgileBits', ver: '8.10.30' },
  { letter: 'Sl', tint: '#4a154b', app: 'Slack', pub: 'Salesforce', ver: '4.38.121' },
  { letter: 'Fi', tint: '#7c3aed', app: 'Firefox', pub: 'Mozilla', ver: '126.0' },
  { letter: 'No', tint: '#101114', app: 'Notion', pub: 'Notion Labs', ver: '3.6.0' },
  { letter: 'Co', tint: '#1f8a5b', app: 'Cursor', pub: 'Anysphere', ver: '0.39.4' },
  { letter: 'Ta', tint: '#2a5d44', app: 'Tailscale', pub: 'Tailscale', ver: '1.66.4' },
];
const CIS_GROUPS = [
  ['Accounts & Authentication', 18, 18],
  ['Software Updates', 12, 12],
  ['Network & Firewall', 22, 22],
  ['Logging & Auditing', 26, 26],
  ['System Access & Privacy', 38, 38],
  ['Encryption & Data Protection', 26, 26],
];
const CVES = [
  { id: 'CVE-2026-1842', app: 'Safari 17.4', sev: 'high', desc: 'A memory-safety flaw in WebKit could let a crafted web page run code. Closed by Safari 17.5.', patch: 'Apple' },
  { id: 'CVE-2026-2011', app: 'Google Chrome 125.0', sev: 'med', desc: 'Out-of-bounds read in the V8 engine. Closed by Chrome 126.', patch: 'Google' },
  { id: 'CVE-2026-1990', app: 'Zoom 6.0.10', sev: 'med', desc: 'Improper input validation in screen-share. Closed by Zoom 6.1.2.', patch: 'Zoom' },
];
const TIMELINE = [
  { time: 'Today · 09:41', dot: 'green', title: 'Scan completed', body: '247 apps checked against the NVD and the CIS macOS 14 benchmark. 142 / 142 controls passed.', hash: 'sha256 a1f3…9e2c' },
  { time: 'Today · 09:38', dot: 'uv', title: '3 CVEs detected · patches verified', body: 'Safari, Chrome and Zoom flagged. Patches located and verified against vendor signatures.', hash: null },
  { time: 'Jun 10 · 02:00', dot: 'green', title: 'Scheduled scan', body: 'No configuration drift since last scan. CIS 142 / 142.', hash: 'sha256 7b0c…14aa' },
  { time: 'Jun 03 · 08:12', dot: 'green', title: 'Monthly report generated', body: ' compliance report generated and delivered through the customer portal.', hash: 'sig 3d9f…be71' },
  { time: 'Jun 01 · 00:00', dot: 'green', title: 'Coverage period began', body: 'Continuous monitoring active. 30-day audit window opened.', hash: null },
];

/* ───────── Chrome ───────── */
const NAV = [
  { items: [['Overview', 'grid'], ['Updates', 'downcircle', 3], ['App Catalog', 'stack']] },
  { title: 'Reporting', items: [['Compliance', 'shieldcheck'], ['Evidence', 'doctext']] },
  { title: 'Device', items: [['This Device', 'laptop']] },
];

/* Canonical ring mark. The Archivo P is the only brand-font element in native UI. */
function ringMarkSVG() {
  return `<svg class="pw-mark" viewBox="0 0 64 64" fill="none" aria-hidden="true">
    <rect x="2.304" y="2.304" width="59.392" height="59.392" rx="16.64" stroke="currentColor" stroke-width="4.608"/>
    <path d="M 30.72 2.304 H 47.36 A 16.64 16.64 0 0 1 61.696 16.64" stroke="#F5530A" stroke-width="4.608" stroke-linecap="round"/>
    <text x="32" y="43.8" text-anchor="middle" font-family="Archivo, Helvetica Neue, Arial, sans-serif" font-weight="700" font-size="33.28" letter-spacing="-1.33" fill="currentColor">P</text>
  </svg>`;
}
function pwLockup(px) {
  return `<span class="pwlk" style="font-size:${px}px"><span class="pw-word">Patched</span></span>`;
}

function sidebar(active, theme) {
  const groups = NAV.map(g => `
    <div class="sb-group">
      ${g.title ? `<div class="sb-h">${g.title}</div>` : ''}
      ${g.items.map(([name, ic, count]) => `
        <div class="sb-item ${name === active ? 'sel' : ''}">
          <span class="ic">${sf(ic, 16, 1.7)}</span>${name}
          ${count ? `<span class="count">${count}</span>` : ''}
        </div>`).join('')}
    </div>`).join('');
  return `
    <div class="sidebar">
      <div class="sb-brand"><span class="sb-mark">${ringMarkSVG()}</span></div>
      ${groups}
      <div class="sb-foot">
        <div class="sb-tier"><span class="lab">Your plan</span>
          <span class="val"><span class="dot"></span>${TIER.name}</span></div>
      </div>
    </div>`;
}

const TOOLBAR_TRAIL = {
  Overview: `<button class="btn btn-ghost btn-sm">${sf('refresh', 13, 1.8)} Scan now</button>`,
  Updates: `<div class="tb-search">${sf('search', 13, 1.7)}<span>Search updates</span></div>`,
  'App Catalog': `<div class="tb-search">${sf('search', 13, 1.7)}<span>Search catalog</span></div>`,
  'This Device': `<button class="btn btn-ghost btn-sm">${sf('refresh', 13, 1.8)} Scan now</button>`,
};

function windowEl(screen, theme, modal) {
  return `
    <div class="window ${theme === 'dark' ? 'dark' : ''}">
      <div class="toolbar">
        <div class="lights"><i class="r"></i><i class="y"></i><i class="g"></i></div>
        <span class="tb-icon" style="margin-left:6px">${sf('sidebar', 17, 1.6)}</span>
        <span class="tb-title">${screen}</span>
        <span class="tb-spacer"></span>
        ${TOOLBAR_TRAIL[screen] || ''}
      </div>
      <div class="win-body">
        ${sidebar(screen, theme)}
        <div class="detail"><div class="detail-scroll">${DETAIL[screen]()}</div></div>
      </div>
      ${modal || ''}
    </div>`;
}

/* ───────── Plans / tier-comparison sheet ───────── */
const PLANS = [
  {
    name: 'Endpoint Assurance', spp: 'Assessment, evidence and specialist review', avail: 'Available now', current: true, featured: false,
    blurb: 'Know exactly where every Mac stands, and prove it.',
    features: ['Continuous CVE scanning (NVD)', 'CIS benchmark compliance reporting', 'Signed evidence through customer portal', 'Verified-source patch tracking'],
  },
  {
    name: 'Managed Patching', spp: 'Endpoint Assurance + managed third-party patching', avail: 'Available now', current: false, featured: false,
    blurb: 'Everything in Endpoint Assurance, plus controlled patching and deployment.',
    features: ['Everything in Endpoint Assurance', 'Automatic patching from verified sources', 'App Catalog one-click deployment', 'Nudge-style OS updates, user-actioned'],
  },
  {
    name: 'Full Endpoint Management', spp: 'Full managed lifecycle', avail: 'Available now', current: false, featured: false,
    blurb: 'A fully managed estate, onboarding to offboarding.',
    features: ['Everything in Managed Patching', 'Managed configuration & rollout', 'Onboarding / offboarding workflows', 'Priority response & reviews'],
  },
];

function plansSheet() {
  const cols = PLANS.map(p => `
    <div class="plan ${p.featured ? 'featured' : ''}">
      ${p.featured ? `<div class="plan-ribbon">Recommended next</div>` : ''}
      <div class="plan-avail ${p.current ? 'now' : 'soon'}">${p.avail}</div>
      <div class="plan-name">${p.name}</div>
      <div class="plan-spp">${p.spp}</div>
      <div class="plan-blurb">${p.blurb}</div>
      <div class="plan-feats">
        ${p.features.map(f => `<div class="plan-feat"><span class="fi">${sf('check', 14, 2)}</span>${f}</div>`).join('')}
      </div>
      ${p.current
        ? `<div class="plan-cta"><span class="plan-current">${sf('check', 13, 2.2)} Current plan</span></div>`
        : `<div class="plan-cta"><button class="btn btn-secondary btn-sm" style="width:100%">Talk to us</button></div>`}
    </div>`).join('');
  return `
    <div class="modal-host">
      <div class="modal-dim"></div>
      <div class="sheet">
        <div class="sheet-head">
          <div>
            <div class="sheet-title">Choose your plan</div>
            <div class="sheet-sub">One service, three rungs. Upgrade when you’re ready. Your evidence trail carries over.</div>
          </div>
          <button class="sheet-x" aria-label="Close">${sf('xmark', 15, 2)}</button>
        </div>
        <div class="sheet-body"><div class="plans">${cols}</div></div>
      </div>
    </div>`;
}

/* ───────── Reusable bits ───────── */
const provChip = (source, hash) =>
  `<span class="chip chip-prov" title="${hash ? `sha256 ${hash} · ` : ''}signed by ${source}"><span class="seal">${sf('seal', 11, 1.7)}</span>Verified source · ${source}</span>`;
const sevTag = (sev) => {
  const lab = { high: 'High', med: 'Medium', low: 'Low' }[sev];
  return `<span class="sev ${sev}"><span class="d"></span>${lab}</span>`;
};
const gate = () => `<span class="gate">${sf('lock', 12, 1.8)} Install</span>`;
const soonBanner = (title, body) => `
  <div class="soon-banner">
    <div class="bic">${sf('bolt', 18, 1.7)}</div>
    <div class="bmain">
      <div class="bt">${title} <span class="soon-tag">Managed Patching</span></div>
      <div class="bs">${body}</div>
    </div>
    <button class="btn btn-tinted btn-sm">Learn more</button>
  </div>`;

/* ───────── Screen details ───────── */
const DETAIL = {
  Overview: () => `
    <div class="dh"><h2>Overview</h2><p>Your Mac is monitored continuously. Here’s where it stands right now.</p></div>
    <div class="hero">
      <div class="hero-main">
        <div class="hero-badge">${sf('shieldcheck', 24, 1.7)}</div>
        <div style="flex:1">
          <div class="hero-status">Protected</div>
          <div class="hero-sub">Last scanned 2 minutes ago · continuous</div>
          <div class="hero-compliance"><span class="seal">${sf('seal', 14, 1.7)}</span>CIS 142 / 142 controls · 0 critical findings</div>
        </div>
      </div>
    </div>
    <div class="triplet">
      <div class="trip on">
        <div class="verb">Scan</div>
        <div class="desc">Checks this Mac against live CVE data and CIS benchmarks.</div>
        <div class="state"><span class="d"></span>Active · 2 min ago</div>
      </div>
      <div class="trip soon">
        <div class="ribbon"><span class="soon-tag">Managed Patching</span></div>
        <div class="verb">Patch</div>
        <div class="desc">Installs verified patches from known-good sources.</div>
        <div class="state"><span class="d"></span>Plan required</div>
      </div>
      <div class="trip on">
        <div class="verb">Prove</div>
        <div class="desc">Keeps an auditable trail you can inspect and show.</div>
        <div class="state"><span class="d"></span>Up to date</div>
      </div>
    </div>
    <div class="sec-h">What needs you</div>
    <div class="gi">
      <div class="gi-row">
        <span class="gi-ic" style="color:var(--attention)">${sf('downcircle', 19, 1.7)}</span>
        <div class="gi-main"><div class="gi-t">3 updates recommended</div>
          <div class="gi-s">Safari, Chrome &amp; Zoom · closes 3 known CVEs from verified sources.</div></div>
        <div class="gi-trail"><button class="btn btn-secondary btn-sm">Review</button></div>
      </div>
      <div class="gi-row">
        <span class="gi-ic">${sf('bell', 18, 1.7)}</span>
        <div class="gi-main"><div class="gi-t">Turn on update notifications</div>
          <div class="gi-s">Get a nudge whenever a new verified patch is available.</div></div>
        <div class="gi-trail"><button class="btn btn-secondary btn-sm">Enable</button></div>
      </div>
    </div>
    <div class="tier-strip">
      <span style="color:var(--mute)">${sf('info', 18, 1.7)}</span>
      <div style="flex:1"><div class="tt">Your plan · Endpoint Assurance</div>
        <div class="ts">Endpoint Assurance includes continuous scanning and CIS reporting. Managed Patching adds automatic patching from verified sources.</div></div>
      <button class="btn btn-ghost btn-sm">Compare tiers</button>
    </div>`,

  Updates: () => `
    <div class="dh"><h2>Updates</h2><p>Recommended patches from verified sources. You choose when. Nothing installs on its own.</p></div>
    ${soonBanner('Automatic patching is available with Managed Patching', 'For now, Patched finds and verifies every update so you can install it yourself. Upgrade to let Patched deploy them from known-good sources.')}
    <div class="sec-h">3 available · all from verified sources</div>
    <div class="gi">
      ${UPDATES.map(u => `
        <div class="gi-row">
          <span class="appicon" style="background:${u.tint}">${u.letter}</span>
          <div class="gi-main">
            <div class="gi-t">${u.app}</div>
            <div class="ver">${u.from} <span class="arr">→</span> <span class="to">${u.to}</span></div>
            <div style="display:flex;gap:6px;margin-top:7px;flex-wrap:wrap;align-items:center">
              <span class="chip chip-cve">${u.cve}</span>${sevTag(u.sev)}${provChip(u.source, u.hash)}
            </div>
          </div>
          <div class="gi-trail">${gate()}</div>
        </div>`).join('')}
    </div>
    <div class="note-line">${sf('lock', 13, 1.8)} Install is part of Managed Patching. Endpoint Assurance verifies and tracks every patch. You install when ready.</div>`,

  'App Catalog': () => `
    <div class="dh"><h2>App Catalog</h2><p>Curated, known-good apps ready for verified-source deployment.</p></div>
    ${soonBanner('One-click deployment is available with Managed Patching', 'Every app here is checked and signature-verified by Patched. Upgrade to deploy them to this Mac from a known-good source in one click.')}
    <div class="cat-filters">
      <span class="fchip sel">All</span><span class="fchip">Security</span><span class="fchip">Browsers</span><span class="fchip">Productivity</span><span class="fchip">Developer</span>
    </div>
    <div class="cat-grid">
      ${CATALOG.map(a => `
        <div class="cat-card">
          <div class="cat-top">
            <span class="appicon" style="background:${a.tint}">${a.letter}</span>
            <div style="flex:1;min-width:0">
              <div class="cat-name">${a.app}</div>
              <div class="cat-pub">${a.pub} · <span style="font-family:var(--mono);font-size:11px">${a.ver}</span></div>
            </div>
          </div>
          <div class="cat-foot">
            <span class="chip chip-prov"><span class="seal">${sf('seal', 11, 1.7)}</span>Verified</span>
            <span class="gate">${sf('lock', 12, 1.8)} Get</span>
          </div>
        </div>`).join('')}
    </div>`,

  Compliance: () => `
    <div class="dh"><h2>Compliance</h2><p>CIS benchmark results and CVE findings for this Mac. This is the record you show an auditor.</p></div>
    <div class="cmp-top">
      <div class="cmp-score">
        <div class="cmp-figure">142<span class="den"> / 142</span></div>
        <div class="cmp-label">CIS controls passed</div>
        <div class="cmp-bench">CIS macOS 14 Benchmark v2.1.0 · scanned 2 min ago</div>
      </div>
      <div class="cmp-groups">
        ${CIS_GROUPS.map(([name, pass, total]) => `
          <div class="cmp-grp">
            <span style="color:var(--secure);display:flex">${sf('check', 16, 2)}</span>
            <span class="gname">${name}</span>
            <span class="track"><span class="fill" style="width:${(pass / total) * 100}%"></span></span>
            <span class="gn">${pass} / ${total}</span>
          </div>`).join('')}
      </div>
    </div>
    <div class="sec-h">CVE findings · 3 open · patches available</div>
    <div class="gi">
      ${CVES.map(c => `
        <div class="gi-row">
          <span class="gi-ic" style="color:var(--${c.sev === 'high' ? 'critical' : 'attention'})">${sf('warning', 18, 1.7)}</span>
          <div class="gi-main">
            <div style="display:flex;align-items:center;gap:9px">
              <span style="font-family:var(--mono);font-size:12px;color:var(--slate);font-weight:600">${c.id}</span>${sevTag(c.sev)}
            </div>
            <div class="gi-s">${c.desc}</div>
            <div style="margin-top:7px">${provChip(c.patch, null)}</div>
          </div>
          <div class="gi-trail"><span class="chev">${sf('chevron', 15, 1.8)}</span></div>
        </div>`).join('')}
    </div>`,

  Evidence: () => `
    <div class="dh"><h2>Evidence</h2><p>A continuous, verifiable record. Reports are generated and delivered in the customer portal.</p></div>
    <div class="report-card">
      <div class="rc-main">
        <div class="rc-t"> · Compliance report</div>
        <div class="rc-s">30 days of continuous coverage, signed and ready to inspect. IT administrators generate reports in the customer portal.</div>
        <div class="rc-meta">
          <div class="rc-stat"><div class="n">30</div><div class="l">Days covered</div></div>
          <div class="rc-stat"><div class="n">142/142</div><div class="l">CIS controls</div></div>
          <div class="rc-stat"><div class="n">3</div><div class="l">CVEs · patched-verified</div></div>
          <div class="rc-stat"><div class="n">12</div><div class="l">Scans logged</div></div>
        </div>
      </div>
    </div>
    <div class="sec-h">Audit trail</div>
    <div class="tl">
      ${TIMELINE.map(t => `
        <div class="tl-item">
          <span class="tl-dot ${t.dot}"></span>
          <div class="tl-time">${t.time}</div>
          <div class="tl-title">${t.title}</div>
          <div class="tl-body">${t.body}</div>
          ${t.hash ? `<div class="tl-hash">${sf('key', 12, 1.7)} ${t.hash}</div>` : ''}
        </div>`).join('')}
    </div>`,

  'This Device': () => `
    <div class="dh"><h2>This Device</h2><p>What Patched monitors on this Mac. Patched never takes control. You action every change.</p></div>
    <div class="device-head">
      <div class="dico">${sf('laptop', 26, 1.6)}</div>
      <div style="flex:1">
        <div class="dn">${DEVICE.name}</div>
        <div class="ds">${DEVICE.model} · ${DEVICE.os}</div>
      </div>
      <button class="btn btn-secondary">${sf('refresh', 14, 1.8)} Scan now</button>
    </div>
    <div class="sec-h">Identity</div>
    <div class="gi">
      <div class="kv"><span class="k">Serial number</span><span class="v mono">${DEVICE.serial}</span></div>
      <div class="kv"><span class="k">Operating system</span><span class="v">${DEVICE.os}</span></div>
      <div class="kv"><span class="k">Apps monitored</span><span class="v mono">${DEVICE.appCount}</span></div>
    </div>
    <div class="sec-h">Patched agent</div>
    <div class="gi">
      <div class="kv"><span class="k">Agent version</span><span class="v mono">${DEVICE.agent}</span></div>
      <div class="kv"><span class="k">Scan schedule</span><span class="v">${DEVICE.schedule}</span></div>
      <div class="kv"><span class="k">Plan</span><span class="v">${TIER.name}</span><span class="vtrail"><button class="btn btn-ghost btn-sm">Compare tiers</button></span></div>
    </div>
    <div class="note-line">${sf('lock', 13, 1.8)} No remote control. Patched scans and advises; installs and changes always happen with your go-ahead.</div>`,
};

/* ───────── Build the board ───────── */
const FRAMES = [
  ['01', 'Overview', 'light', 'Overview', 'The hand-off landing. One trustworthy posture summary, the Scan · Patch · Prove triplet with live states. Managed Patching is gated under Endpoint Assurance.'],
  ['02', 'Updates', 'light', 'Updates', 'Recommended patches from verified sources, each with current → target version, the CVE it closes, severity and a provenance chip. The Install control is an honest Managed Patching gate, never a dead button.'],
  ['03', 'App Catalog', 'light', 'App Catalog', 'Curated known-good apps for verified-source deployment. Same provenance treatment and the same honest tier gate as Updates.'],
  ['04', 'Compliance', 'light', 'Compliance', 'The Endpoint Assurance plan core is fully live. CIS controls are grouped by section and CVE findings include plain-language explanations.'],
  ['05', 'Evidence', 'light', 'Evidence', 'A continuous, signed audit trail for end users to inspect. IT administrators generate and deliver reports through the customer portal.'],
  ['06', 'This Device', 'light', 'This Device', 'Identity, agent version, schedule and tier, with a manual Scan now. No remote-control implications anywhere: you action every change.'],
  ['07', 'Overview', 'dark', 'Overview · Dark', 'The same Overview in dark mode. Every token flips, while the single orange accent holds its 2% budget.'],
  ['08', 'Overview', 'light', 'Plans · Upgrade sheet', 'Where every “Compare tiers” and “Learn more” leads. A modal sheet over the app: Endpoint Assurance (current), Managed Patching and Full Endpoint Management. All services are available while deployment remains entitlement-gated.', 'plans'],
];

const board = document.getElementById('board');
board.innerHTML = FRAMES.map(([num, screen, theme, name, note, modal]) => `
  <div class="frame">
    <div class="cap"><span class="cnum">${num}</span>
      <div><div class="cname">${name}</div><div class="cnote">${note}</div></div></div>
    ${windowEl(screen, theme, modal === 'plans' ? plansSheet() : '')}
  </div>`).join('');
