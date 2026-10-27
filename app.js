"use strict";

const STORE = { pw: "lantern.pw", status: "lantern.status", filters: "lantern.filters" };
const FLAG_INFO = {
  "🏢": "Recruitment agency",
  "❓": "Salary not listed",
  "🕒": "Timezone constraints",
  "⚠️": "Details unverified",
  "🆕": "Posted ≤ 3 days ago",
  "📍": "Office days not stated",
};
const EMP_INFO = { "EoR": "Employer of Record", "Contr.": "Contractor", "NL BV": "Dutch entity", "?": "Type unknown" };

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

function store(key, val) {
  try {
    if (val === undefined) return JSON.parse(localStorage.getItem(key));
    if (val === null) localStorage.removeItem(key);
    else localStorage.setItem(key, JSON.stringify(val));
  } catch { return null; }
}

/* ---------- crypto: PBKDF2-SHA256 → AES-256-GCM (matches encrypt.mjs) ---------- */
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function decrypt(blob, password) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64(blob.salt), iterations: blob.iter, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(blob.iv) }, key, b64(blob.ct));
  return JSON.parse(new TextDecoder().decode(plain));
}

/* ---------- state ---------- */
let jobs = [];
let status = store(STORE.status) || {};
let blob = null;

async function loadBlob() {
  const res = await fetch(`data.enc.json?t=${Date.now()}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Could not load data (${res.status})`);
  return res.json();
}

async function unlock(password, remember) {
  const err = $("#lock-error");
  err.hidden = true;
  try {
    blob = blob || await loadBlob();
    const data = await decrypt(blob, password);
    jobs = data.jobs || data;
    if (remember) store(STORE.pw, password);
    $("#lock").hidden = true;
    $("#app").hidden = false;
    restoreFilters();
    render();
  } catch (e) {
    err.textContent = e.name === "OperationError" ? "Wrong password." : e.message;
    err.hidden = false;
    store(STORE.pw, null);
  }
}

/* ---------- filters ---------- */
function readFilters() {
  return {
    q: $("#q").value.trim().toLowerCase(),
    section: $("input[name=section]:checked").value,
    status: $("#status").value,
    since: $("#since").value,
    sort: $("#sort").value,
    fit: +$("#fit").value,
    salary: +$("#salary").value || 0,
    travel: +$("#travel").value || 0,
    match: $$("input[name=match]:checked").map((i) => i.value),
    emp: $$("input[name=emp]:checked").map((i) => i.value),
    hideAgency: $("#hide-agency").checked,
    hideNoSalary: $("#hide-nosalary").checked,
  };
}

function restoreFilters() {
  const f = store(STORE.filters);
  if (!f) return;
  $("#q").value = f.q || "";
  const sec = $(`input[name=section][value="${f.section}"]`);
  if (sec) sec.checked = true;
  for (const id of ["status", "since", "sort"]) if (f[id]) $("#" + id).value = f[id];
  $("#fit").value = f.fit || 0;
  $("#salary").value = f.salary || "";
  $("#travel").value = f.travel || "";
  $$("input[name=match]").forEach((i) => (i.checked = (f.match || ["Core", "Adjacent"]).includes(i.value)));
  $$("input[name=emp]").forEach((i) => (i.checked = (f.emp || Object.keys(EMP_INFO)).includes(i.value)));
  $("#hide-agency").checked = !!f.hideAgency;
  $("#hide-nosalary").checked = !!f.hideNoSalary;
}

const today = () => new Date().toISOString().slice(0, 10);
function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - (n - 1));
  return d.toISOString().slice(0, 10);
}
const fitRatio = (j) => (j.fit_total ? j.fit_met / j.fit_total : null);

function matches(j, f) {
  const st = status[j.id] || "new";
  if (f.status === "active" && st === "hidden") return false;
  if (!["active", "all"].includes(f.status) && st !== f.status) return false;
  if (f.section !== "all" && j.section !== f.section) return false;
  if (f.since !== "all" && j.first_seen < daysAgo(+f.since)) return false;
  if (!f.match.includes(j.match || "Core")) return false;
  if (j.section === "remote" && !f.emp.includes(j.emp_type || "?")) return false;
  if (f.fit && (fitRatio(j) ?? 0) * 100 < f.fit) return false;
  if (f.salary && j.salary_min_month != null && j.salary_min_month < f.salary) return false;
  if (f.hideNoSalary && j.salary_min_month == null) return false;
  if (f.travel && j.section === "nearby" && j.travel_min != null && j.travel_min > f.travel) return false;
  if (f.hideAgency && (j.flags || []).includes("🏢")) return false;
  if (f.q) {
    const hay = [j.title, j.company, j.where, j.notes, j.missing, j.bonus, j.salary].join(" ").toLowerCase();
    if (!f.q.split(/\s+/).every((w) => hay.includes(w))) return false;
  }
  return true;
}

const SORTS = {
  newest: (a, b) => b.first_seen.localeCompare(a.first_seen) || (fitRatio(b) ?? -1) - (fitRatio(a) ?? -1),
  best: (a, b) => (fitRatio(b) ?? -1) - (fitRatio(a) ?? -1) || (b.salary_min_month ?? 0) - (a.salary_min_month ?? 0),
  salary: (a, b) => (b.salary_min_month ?? -1) - (a.salary_min_month ?? -1),
  travel: (a, b) => (a.section === "remote" ? 0 : a.travel_min ?? 999) - (b.section === "remote" ? 0 : b.travel_min ?? 999),
};

/* ---------- render ---------- */
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const safeUrl = (u) => (/^https?:\/\//i.test(u || "") ? u : "#");

function fitBadge(j) {
  const r = fitRatio(j);
  const cls = r == null ? "none" : r >= 0.8 ? "good" : r >= 0.6 ? "mid" : "low";
  return `<div class="fit ${cls}" title="Requirements met">${r == null ? "–" : esc(j.fit)}<small>fit</small></div>`;
}

function card(j) {
  const st = status[j.id] || "new";
  const chips = [
    `<span class="chip">${esc(j.where)}</span>`,
    j.salary && j.salary !== "—" ? `<span class="chip">${esc(j.salary)}</span>` : "",
    j.section === "remote" && j.emp_type ? `<span class="chip" title="${esc(EMP_INFO[j.emp_type] || "")}">${esc(j.emp_type)}</span>` : "",
    j.match === "Adjacent" ? `<span class="chip">Adjacent</span>` : "",
    ...(j.flags || []).map((f) => `<span class="chip flag" title="${esc(FLAG_INFO[f] || "")}">${esc(f)} ${esc(FLAG_INFO[f] || "")}</span>`),
  ].join("");
  const btn = (s, label) => `<button data-id="${esc(j.id)}" data-st="${s}" aria-pressed="${st === s}">${label}</button>`;
  const details = j.notes || j.missing || j.bonus ? `
    <details>
      <summary>Details</summary>
      ${j.missing ? `<p class="miss"><strong>Missing:</strong> ${esc(j.missing)}</p>` : ""}
      ${j.bonus ? `<p class="bonus"><strong>Bonus:</strong> ${esc(j.bonus)}</p>` : ""}
      ${j.notes ? `<p>${esc(j.notes)}</p>` : ""}
    </details>` : "";
  return `
    <article class="job ${st === "hidden" ? "is-hidden" : ""}">
      <div class="job-head">
        <div class="job-main">
          <a class="job-title" href="${esc(safeUrl(j.url))}" target="_blank" rel="noopener noreferrer">${esc(j.title)}</a>
          <div class="company">${esc(j.company)}</div>
        </div>
        ${fitBadge(j)}
      </div>
      <div class="chips">${chips}</div>
      ${details}
      <div class="job-foot">
        <span class="muted">Seen ${esc(j.first_seen)}${j.posted ? ` · posted ${esc(j.posted)}` : ""}</span>
        <div class="status">${btn("saved", "☆ Save")}${btn("applied", "✓ Applied")}${btn("hidden", "✕ Hide")}</div>
      </div>
    </article>`;
}

function render() {
  const f = readFilters();
  store(STORE.filters, f);
  $("#fit-out").textContent = `${f.fit}%`;
  const list = jobs.filter((j) => matches(j, f)).sort(SORTS[f.sort]);

  const newToday = jobs.filter((j) => j.first_seen === today()).length;
  const applied = Object.values(status).filter((s) => s === "applied").length;
  $("#summary").textContent = `${jobs.length} jobs · ${newToday} new today · ${applied} applied`;
  $("#count").textContent = `${list.length} shown`;

  if (!list.length) {
    $("#list").innerHTML = `<p class="empty">No jobs match these filters.</p>`;
    return;
  }
  let html = "";
  let day = null;
  for (const j of list) {
    if (f.sort === "newest" && j.first_seen !== day) {
      day = j.first_seen;
      html += `<h2 class="day">${day === today() ? "Today" : esc(day)}</h2>`;
    }
    html += card(j);
  }
  $("#list").innerHTML = html;
}

/* ---------- events ---------- */
$("#unlock-form").addEventListener("submit", (e) => {
  e.preventDefault();
  unlock($("#pw").value, $("#remember").checked);
});
$("#lock-btn").addEventListener("click", () => {
  store(STORE.pw, null);
  location.reload();
});
$("#toggle-filters").addEventListener("click", (e) => {
  const open = $("#filters").classList.toggle("open");
  e.currentTarget.setAttribute("aria-expanded", open);
});
$("#reset").addEventListener("click", () => {
  store(STORE.filters, {});
  $("input[name=section][value=all]").checked = true;
  $("#status").value = "active";
  $("#since").value = "all";
  $("#sort").value = "newest";
  restoreFilters();
  render();
});
$("#filters").addEventListener("input", render);
$("#filters").addEventListener("change", render);
$("#list").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-st]");
  if (!b) return;
  const { id, st } = b.dataset;
  if (status[id] === st) delete status[id];
  else status[id] = st;
  store(STORE.status, status);
  render();
});

const saved = store(STORE.pw);
if (saved) unlock(saved, true);
