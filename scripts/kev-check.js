#!/usr/bin/env node
'use strict';

/*
 * KEV Triage — cross-checks the CISA KEV catalog against inventory.txt
 * and posts an Adaptive Card to Teams. Runs server-side (no CORS).
 *
 * Env:
 *   TEAMS_WEBHOOK_URL  Power Automate Workflows webhook (from GitHub secret)
 *   RECENCY_DAYS       only flag entries added within N days (0 = all). Default 7.
 *   SEARCH_DESC        "true" to also match on the KEV description. Default off.
 *   POST_WHEN          "always" (post even when clean) | "matches". Default always.
 *   INVENTORY_FILE     path to inventory list. Default inventory.txt.
 */

const fs = require('fs');

const WEBHOOK        = process.env.TEAMS_WEBHOOK_URL || '';
const RECENCY        = parseInt(process.env.RECENCY_DAYS || '7', 10);
const SEARCH_DESC    = /^(1|true|yes)$/i.test(process.env.SEARCH_DESC || '');
const POST_WHEN      = (process.env.POST_WHEN || 'always').toLowerCase();
const INVENTORY_FILE = process.env.INVENTORY_FILE || 'inventory.txt';

const FEEDS = [
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'
];

/* ---------- inventory ---------- */
function parseInventory(text){
  const items = [];
  text.split('\n').forEach(raw => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    let name = line, kw = [];
    const i = line.indexOf('::');
    if (i >= 0) {
      name = line.slice(0, i).trim();
      kw = line.slice(i + 2).split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    }
    if (!kw.length) kw = [name.toLowerCase()];
    if (name) items.push({ name, keywords: kw });
  });
  return items;
}

/* ---------- catalog ---------- */
function normFromKev(v){
  return {
    cve:        (v.cveID || v.cve || '').trim(),
    vendor:     (v.vendorProject || v.vendor || '').trim(),
    product:    (v.product || '').trim(),
    name:       (v.vulnerabilityName || v.name || '').trim(),
    dateAdded:  (v.dateAdded || '').trim(),
    dueDate:    (v.dueDate || '').trim(),
    ransomware: /known/i.test(v.knownRansomwareCampaignUse || ''),
    desc:       (v.shortDescription || v.description || '').trim()
  };
}

async function fetchCatalog(){
  let lastErr;
  for (const url of FEEDS) {
    try {
      const r = await fetch(url, { headers: { 'User-Agent': 'kev-triage' } });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const data = await r.json();
      const arr = Array.isArray(data) ? data : (data.vulnerabilities || data.data || []);
      if (!Array.isArray(arr) || !arr.length) throw new Error('empty catalog');
      const catalog = arr.map(normFromKev).filter(e => e.cve);
      console.log(`Loaded ${catalog.length} KEV entries from ${url}`);
      return { catalog, version: data.catalogVersion || '' };
    } catch (e) {
      lastErr = e;
      console.log(`Feed failed (${url}): ${e.message}`);
    }
  }
  throw new Error('All KEV feeds failed: ' + (lastErr && lastErr.message));
}

/* ---------- matching ---------- */
function esc(s){ return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function matchEntry(entry, inv){
  let hay = [entry.vendor, entry.product, entry.name];
  if (SEARCH_DESC) hay.push(entry.desc);
  hay = hay.join(' ').toLowerCase();
  const hits = [];
  for (const item of inv) {
    for (const kw of item.keywords) {
      const re = new RegExp('(^|[^a-z0-9])' + esc(kw) + '([^a-z0-9]|$)', 'i');
      if (re.test(hay)) { hits.push(item.name); break; }
    }
  }
  return hits;
}
function daysBetween(iso){
  if (!iso) return null;
  const d = new Date(iso + (iso.length <= 10 ? 'T00:00:00Z' : ''));
  if (isNaN(d)) return null;
  return Math.round((d - new Date()) / 86400000);
}

function crossCheck(catalog, inv){
  const now = new Date();
  let entries = catalog;
  if (RECENCY > 0) {
    entries = entries.filter(e => {
      if (!e.dateAdded) return true;
      const a = new Date(e.dateAdded);
      if (isNaN(a)) return true;
      return (now - a) / 86400000 <= RECENCY;
    });
  }
  const matches = [];
  for (const e of entries) {
    const hits = matchEntry(e, inv);
    if (hits.length) {
      const dd = daysBetween(e.dueDate);
      matches.push({ ...e, products: hits, dueIn: dd, overdue: (dd !== null && dd < 0) });
    }
  }
  matches.sort((a, b) => {
    const rank = x => x.overdue ? 0 : x.ransomware ? 1 : 2;
    if (rank(a) !== rank(b)) return rank(a) - rank(b);
    const ad = a.dueIn === null ? 9e9 : a.dueIn, bd = b.dueIn === null ? 9e9 : b.dueIn;
    if (ad !== bd) return ad - bd;
    return (b.dateAdded || '').localeCompare(a.dateAdded || '');
  });
  return { matches, scanned: entries.length, invCount: inv.length, recency: RECENCY, generated: now };
}

/* ---------- outputs ---------- */
function fmtDue(m){
  if (!m.dueDate) return 'no due date';
  if (m.dueIn === null) return m.dueDate;
  if (m.dueIn < 0) return `${m.dueDate} (${Math.abs(m.dueIn)}d overdue)`;
  return `${m.dueDate} (${m.dueIn}d left)`;
}

function teamsCard(res){
  const d = res.generated.toISOString().slice(0, 10);
  const affected = new Set(); res.matches.forEach(m => m.products.forEach(p => affected.add(p)));
  const overdue = res.matches.filter(m => m.overdue).length;
  const ransom  = res.matches.filter(m => m.ransomware).length;

  const body = [
    { type: 'TextBlock', size: 'Large', weight: 'Bolder', text: 'CISA KEV cross-check' },
    { type: 'TextBlock', spacing: 'None', isSubtle: true, text: d + (res.recency > 0 ? ` · last ${res.recency} days` : ' · full catalog') },
    { type: 'FactSet', facts: [
      { title: 'Matched CVEs',      value: String(res.matches.length) },
      { title: 'Products affected', value: String(affected.size) },
      { title: 'Past due',          value: String(overdue) },
      { title: 'Ransomware-linked', value: String(ransom) }
    ]}
  ];

  if (res.matches.length) {
    body.push({ type: 'TextBlock', weight: 'Bolder', text: 'Products to check', separator: true });
    res.matches.slice(0, 20).forEach(m => {
      body.push({
        type: 'TextBlock', wrap: true, spacing: 'Small',
        color: (m.overdue || m.ransomware) ? 'Attention' : 'Warning',
        text: `**${m.cve}** — ${m.products.join(', ')}  \n${m.name} · due ${fmtDue(m)}${m.ransomware ? ' · ransomware' : ''}`
      });
    });
    if (res.matches.length > 20)
      body.push({ type: 'TextBlock', isSubtle: true, text: `+ ${res.matches.length - 20} more` });
  } else {
    body.push({ type: 'TextBlock', wrap: true, color: 'Good', separator: true,
      text: `No exposure this window — scanned ${res.scanned} entries against ${res.invCount} products.` });
  }

  return { type: 'message', attachments: [{
    contentType: 'application/vnd.microsoft.card.adaptive',
    content: { $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', type: 'AdaptiveCard', version: '1.4', body }
  }]};
}

function writeStepSummary(res){
  const path = process.env.GITHUB_STEP_SUMMARY;
  if (!path) return;
  const affected = new Set(); res.matches.forEach(m => m.products.forEach(p => affected.add(p)));
  let md = `## CISA KEV cross-check — ${res.generated.toISOString().slice(0,10)}\n\n`;
  md += `- **Matched CVEs:** ${res.matches.length}\n- **Products affected:** ${affected.size}\n`;
  md += `- **Scanned:** ${res.scanned} entries (${res.recency > 0 ? 'last ' + res.recency + ' days' : 'full catalog'})\n\n`;
  if (res.matches.length) {
    md += `| CVE | Products | Due | Flags |\n|---|---|---|---|\n`;
    res.matches.forEach(m => {
      const flags = [m.overdue ? 'overdue' : '', m.ransomware ? 'ransomware' : ''].filter(Boolean).join(', ');
      md += `| ${m.cve} | ${m.products.join(', ')} | ${fmtDue(m)} | ${flags} |\n`;
    });
  } else {
    md += `_No exposure found in this window._\n`;
  }
  fs.appendFileSync(path, md);
}

async function post(card){
  const r = await fetch(WEBHOOK, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(card)
  });
  if (!r.ok) throw new Error('Teams POST failed: HTTP ' + r.status + ' ' + (await r.text().catch(() => '')));
}

/* ---------- exports for tests ---------- */
if (require.main !== module) {
  module.exports = { parseInventory, normFromKev, matchEntry, crossCheck, teamsCard, fmtDue };
  return;
}

/* ---------- main ---------- */
(async function main(){
  const inv = parseInventory(fs.readFileSync(INVENTORY_FILE, 'utf8'));
  console.log(`Inventory: ${inv.length} products`);

  const { catalog } = await fetchCatalog();
  const res = crossCheck(catalog, inv);

  const affected = new Set(); res.matches.forEach(m => m.products.forEach(p => affected.add(p)));
  console.log(`Result: ${res.matches.length} matched CVEs across ${affected.size} products (scanned ${res.scanned}).`);
  res.matches.forEach(m => console.log(`  ${m.cve} — ${m.products.join(', ')} — due ${fmtDue(m)}${m.ransomware ? ' [ransomware]' : ''}`));

  writeStepSummary(res);

  if (POST_WHEN === 'matches' && res.matches.length === 0) {
    console.log('No matches and POST_WHEN=matches — skipping Teams post.');
    return;
  }
  if (!WEBHOOK) {
    console.log('No TEAMS_WEBHOOK_URL set — skipping Teams post (diff still ran).');
    return;
  }
  await post(teamsCard(res));
  console.log('Posted to Teams.');
})().catch(e => { console.error('ERROR:', e.message); process.exit(1); });
