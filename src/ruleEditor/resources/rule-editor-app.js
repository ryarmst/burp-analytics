"use strict";

let services = [];
let selectedId = null;
const NL = String.fromCharCode(10);
const CR = String.fromCharCode(13);

function byId(id) {
  return document.getElementById(id);
}

function normalizePatterns(p) {
  return Array.isArray(p) ? p : [];
}

function splitLines(t) {
  return String(t || "").split(new RegExp(CR + "?" + NL));
}

function normalizeSearchQuery(q) {
  return (q || "").trim().toLowerCase();
}

function serviceMatchesSearch(service, q) {
  if (!q) return true;
  const hayName = (service.name || "").toLowerCase();
  const hayPatterns = normalizePatterns(service.patterns).join(" ").toLowerCase();
  const hayMethodology = (service.methodology || "").toLowerCase();
  return hayName.includes(q) || hayPatterns.includes(q) || hayMethodology.includes(q);
}

function escapeFqdnForRegex(host) {
  const bs = String.fromCharCode(92);
  const special = bs + ".^$|?*+()[]{}";
  let out = "";
  for (let i = 0; i < host.length; i++) {
    const c = host[i];
    out += special.indexOf(c) >= 0 ? bs + c : c;
  }
  return out;
}

function fqdnPatternLine(fqdn) {
  return "^" + escapeFqdnForRegex(fqdn.toLowerCase()) + "$";
}

function isPlausibleFqdn(host) {
  if (!host || host.length > 253) return false;
  const h = host.toLowerCase();
  if (h.includes("..") || h.startsWith(".") || h.endsWith(".")) return false;
  return /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(h);
}

function tokensFromPaste(text) {
  const out = [];
  for (let line of splitLines(text)) {
    for (let chunk of line.split(/[,;]+/)) {
      for (let t of chunk.trim().split(/\s+/)) {
        const s = t.trim();
        if (s) out.push(s);
      }
    }
  }
  return out;
}

function stripPathQueryHash(tok) {
  let end = tok.length;
  for (let j = 0; j < tok.length; j++) {
    const ch = tok[j];
    if (ch === "/" || ch === "?" || ch === "#") {
      end = j;
      break;
    }
  }
  return tok.slice(0, end);
}

function hostnameFromToken(token) {
  token = token.trim();
  if (!token) return null;
  const low = token.toLowerCase();
  if (low.startsWith("http://") || low.startsWith("https://")) {
    try {
      const hostname = new URL(token).hostname;
      return hostname ? hostname.toLowerCase() : null;
    } catch (e) {
      return null;
    }
  }
  token = stripPathQueryHash(token);
  const colonIdx = token.lastIndexOf(":");
  if (colonIdx > 0) {
    const rest = token.slice(colonIdx + 1);
    if (/^[0-9]+$/.test(rest)) {
      token = token.slice(0, colonIdx);
    }
  }
  return token.trim().toLowerCase() || null;
}

function appendFqdnPatterns() {
  const paste = byId("hostsPaste").value.trim();
  if (!paste) {
    setStatus("Paste at least one host or URL first.", "error");
    return;
  }
  const hosts = [];
  for (const token of tokensFromPaste(paste)) {
    const h = hostnameFromToken(token);
    if (h && isPlausibleFqdn(h)) hosts.push(h);
  }
  const unique = [...new Set(hosts)];
  if (!unique.length) {
    setStatus("No valid FQDNs found. Paste hostnames or https:// URLs.", "error");
    return;
  }
  const existing = new Set(splitLines(byId("patterns").value).map((s) => s.trim()).filter(Boolean));
  const linesAdded = [];
  for (const fqdn of unique) {
    const line = fqdnPatternLine(fqdn);
    if (existing.has(line)) continue;
    existing.add(line);
    linesAdded.push(line);
  }
  if (!linesAdded.length) {
    setStatus("All pasted hosts already have matching ^host$ patterns.");
    return;
  }
  const lines = splitLines(byId("patterns").value);
  while (lines.length && lines[lines.length - 1].trim() === "") {
    lines.pop();
  }
  const cur = lines.join(NL);
  byId("patterns").value = cur ? cur + NL + linesAdded.join(NL) : linesAdded.join(NL);
  byId("hostsPaste").value = "";
  setStatus(
    "Appended " +
      linesAdded.length +
      " FQDN regex line(s): " +
      linesAdded.slice(0, 5).join(", ") +
      (linesAdded.length > 5 ? " …" : ""),
  );
}

function setStatus(message, cls = "") {
  const el = byId("status");
  el.className = "status " + cls;
  el.textContent = message;
}

function serviceFromForm() {
  return {
    schemaVersion: "1",
    id: byId("id").value,
    name: byId("name").value.trim(),
    description: byId("description").value,
    methodology: byId("methodology").value,
    patterns: splitLines(byId("patterns").value)
      .map((s) => s.trim())
      .filter(Boolean),
    tlsPassThrough: byId("tls").checked,
    tlsHostRegex: "",
  };
}

function fillForm(service) {
  selectedId = service?.id || "";
  byId("id").value = service?.id || "";
  byId("name").value = service?.name || "";
  byId("description").value = service?.description || "";
  byId("methodology").value = service?.methodology || "";
  byId("patterns").value = normalizePatterns(service?.patterns).join(NL);
  byId("tls").checked = Boolean(service?.tlsPassThrough);
  renderList();
}

function newService() {
  fillForm({
    schemaVersion: "1",
    methodology: "",
    patterns: ["^analytics\\.example\\.com$"],
  });
  setStatus("New service draft. Save to create a JSON file.");
}

function renderList() {
  const list = byId("serviceList");
  list.textContent = "";
  const searchEl = byId("search");
  const q = normalizeSearchQuery(searchEl ? searchEl.value : "");
  const filtered = services.filter((s) => serviceMatchesSearch(s, q));
  if (filtered.length === 0) {
    const m = document.createElement("div");
    m.className = "muted";
    m.textContent = q ? 'No services match "' + q + '".' : "No services.";
    list.appendChild(m);
    return;
  }
  for (const service of filtered) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "item" + (service.id === selectedId ? " active" : "");
    button.textContent = service.name || service.id;
    button.onclick = () => fillForm(service);
    list.appendChild(button);
  }
}

async function loadServices() {
  let res;
  try {
    res = await fetch("/api/services");
  } catch (e) {
    setStatus("Network error: " + e.message, "error");
    throw e;
  }
  if (!res.ok) {
    const msg = "Failed to load services (HTTP " + res.status + ").";
    setStatus(msg, "error");
    throw new Error(msg);
  }
  let body;
  try {
    body = await res.json();
  } catch (e) {
    setStatus("Invalid JSON from /api/services.", "error");
    throw e;
  }
  services = body.services || [];
  const warningsEl = byId("warnings");
  if (warningsEl) warningsEl.textContent = (body.warnings || []).join(NL);
  renderList();
  if (services.length && !selectedId) fillForm(services[0]);
  setStatus("Loaded " + services.length + " service(s).");
}

async function saveService() {
  let res;
  try {
    res = await fetch("/api/services", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(serviceFromForm()),
    });
  } catch (e) {
    setStatus("Network error: " + e.message, "error");
    return;
  }
  let body;
  try {
    body = await res.json();
  } catch (e) {
    setStatus("Save failed: response was not JSON.", "error");
    return;
  }
  if (!res.ok) {
    setStatus((body.errors || [body.error || "Save failed"]).join(NL), "error");
    return;
  }
  selectedId = body.id;
  setStatus("Saved " + body.name + ".");
  try {
    await loadServices();
    fillForm(services.find((s) => s.id === selectedId) || body);
  } catch (e) {
    /* loadServices already reported */
  }
}

async function deleteService() {
  const id = byId("id").value;
  if (!id || !confirm("Delete this service JSON file and methodology .md sidecar (if any)?")) return;
  try {
    const res = await fetch("/api/services/" + encodeURIComponent(id), { method: "DELETE" });
    if (!res.ok && res.status !== 204) {
      setStatus("Delete failed (HTTP " + res.status + ").", "error");
      return;
    }
  } catch (e) {
    setStatus("Network error: " + e.message, "error");
    return;
  }
  selectedId = null;
  fillForm({});
  try {
    await loadServices();
  } catch (e) {
    /* loadServices reported */
  }
  setStatus("Deleted service.");
}

function wireSearch() {
  const searchEl = byId("search");
  if (searchEl) searchEl.addEventListener("input", renderList);
}

function init() {
  wireSearch();
  loadServices().catch(() => {});
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
