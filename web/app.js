"use strict";

/* ------------------------------------------------------------------ *
 * runeward dashboard
 * Vanilla JS. Talks to the control-plane REST API at the same origin.
 * ------------------------------------------------------------------ */

const POLL_MS = 3000;

const state = {
  sandboxes: [],
  profiles: [],
  selected: null, // sandbox id
  activeTab: "terminal",
  approvals: [],
  activeView: "sandboxes", // "sandboxes" | "fleets"
  // fleets
  fleets: [],
  fleetSelected: null, // fleet id
  fleetTasks: [],
  // terminal
  term: null,
  fitAddon: null,
  socket: null,
  termSandbox: null, // which sandbox the current socket belongs to
  // polling handles
  timers: { global: null, audit: null },
  // policy simulation
  simulation: null,
  // egress explorer
  egress: [],
  // budget view
  budget: null,
};

/* ---------------- DOM helpers ---------------- */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "html") node.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function") {
      node.addEventListener(k.slice(2).toLowerCase(), v);
    } else if (v !== null && v !== undefined) {
      node.setAttribute(k, v);
    }
  }
  for (const c of [].concat(children)) {
    if (c === null || c === undefined) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

/* ---------------- Auth ---------------- */
const auth = {
  token: "",
  principal: null,
  rbac: false,
  onRequired: null, // callback invoked on a 401 (shows the login overlay)
};

function setToken(tok) {
  auth.token = (tok || "").trim();
}

// canApprove reports whether the current identity may resolve approvals. Open
// mode (no principal) and admins can; a principal must have can_approve.
function canApprove() {
  const p = auth.principal;
  return !p || p.can_approve !== false;
}

// canLaunch reports whether the current identity may create sandboxes. Under
// RBAC a non-admin with an empty allowed-profiles list can launch nothing.
function canLaunch() {
  const p = auth.principal;
  if (!p) return true;
  if (p.admin) return true;
  if (auth.rbac && Array.isArray(p.allowed_profiles) && p.allowed_profiles.length === 0) {
    return false;
  }
  return p.can_launch !== false;
}

/* ---------------- API layer ---------------- */
class ApiError extends Error {
  constructor(status, body) {
    super((body && (body.reason || body.error || body.message)) || `HTTP ${status}`);
    this.status = status;
    this.body = body || {};
  }
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (auth.token) opts.headers["Authorization"] = "Bearer " + auth.token;
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, opts);
  } catch (e) {
    throw new ApiError(0, { error: "network error: " + e.message });
  }
  const text = await res.text();
  let data = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }
  if (!res.ok) {
    if (res.status === 401 && typeof auth.onRequired === "function") {
      auth.onRequired();
    }
    throw new ApiError(res.status, data);
  }
  return { status: res.status, data };
}

/* ---------------- Toasts ---------------- */
function toast(msg, kind = "info", title) {
  const stack = $("#toast-stack");
  const node = el("div", { class: `toast ${kind}` }, [
    title ? el("div", { class: "toast-title", text: title }) : null,
    el("div", { class: "toast-msg", text: msg }),
  ]);
  stack.appendChild(node);
  setTimeout(() => {
    node.style.transition = "opacity 0.3s";
    node.style.opacity = "0";
    setTimeout(() => node.remove(), 300);
  }, kind === "error" ? 6000 : 3500);
}

/* ---------------- Header / health ---------------- */
async function refreshHealth() {
  const badge = $("#health-badge");
  const dot = $("#health-dot");
  const txt = $("#health-text");
  try {
    const { data } = await api("GET", "/healthz");
    const ok = data && data.status === "ok";
    badge.className = "badge " + (ok ? "ok" : "bad");
    dot.className = "dot " + (ok ? "dot-ok" : "dot-bad");
    txt.textContent = ok ? "healthy" : "unhealthy";
  } catch {
    badge.className = "badge bad";
    dot.className = "dot dot-bad";
    txt.textContent = "offline";
  }
}

async function refreshAuditVerify() {
  const badge = $("#audit-badge");
  try {
    const { data } = await api("GET", "/v1/audit/verify");
    if (data && data.ok) {
      badge.className = "badge ok";
      badge.title = "Audit ledger verified";
      badge.querySelector(".badge-dot") || badge.prepend(el("span", { class: "badge-dot" }));
      badge.lastChild.textContent = " Audit verified";
    } else {
      badge.className = "badge bad";
      badge.title = (data && data.error) || "Audit verification failed";
      badge.lastChild.textContent = " Audit tampered";
    }
  } catch (e) {
    badge.className = "badge bad";
    badge.title = e.message;
    badge.lastChild.textContent = " Audit ?";
  }
}

/* ---------------- Profiles ---------------- */
function fillProfileSelect(sel, text) {
  if (!sel) return;
  sel.innerHTML = "";
  if (text) {
    sel.appendChild(el("option", { value: "", text }));
    return;
  }
  if (state.profiles.length === 0) {
    sel.appendChild(el("option", { value: "", text: "No profiles" }));
    return;
  }
  for (const p of state.profiles) {
    sel.appendChild(
      el("option", { value: p.name, text: `${p.name} · ${p.host || "?"}/${p.egress || "?"}` })
    );
  }
}

async function loadProfiles() {
  try {
    const { data } = await api("GET", "/v1/profiles");
    state.profiles = (data && data.profiles) || [];
    fillProfileSelect($("#profile-select"));
    fillProfileSelect($("#fleet-profile-select"));
    fillProfileSelect($("#sim-profile-select"));
  } catch (e) {
    fillProfileSelect($("#profile-select"), "profiles unavailable");
    fillProfileSelect($("#fleet-profile-select"), "profiles unavailable");
    fillProfileSelect($("#sim-profile-select"), "profiles unavailable");
    toast("Could not load profiles: " + e.message, "error");
  }
}

/* ---------------- Sandboxes ---------------- */
async function loadSandboxes() {
  try {
    const { data } = await api("GET", "/v1/sandboxes");
    state.sandboxes = (data && data.sandboxes) || [];
  } catch (e) {
    state.sandboxes = [];
    // don't spam toast on poll; health badge covers offline
  }
  renderSandboxList();
  if (state.selected && !state.sandboxes.find((s) => s.id === state.selected)) {
    selectSandbox(null);
  }
}

function renderSandboxList() {
  const list = $("#sandbox-list");
  list.innerHTML = "";
  if (state.sandboxes.length === 0) {
    list.appendChild(el("li", { class: "empty-note", text: "No sandboxes yet." }));
    return;
  }
  for (const s of state.sandboxes) {
    const status = (s.status || "unknown").toLowerCase();
    const item = el(
      "li",
      {
        class: "sandbox-item" + (s.id === state.selected ? " active" : ""),
        title: s.id,
        onClick: () => selectSandbox(s.id),
      },
      [
        el("div", { class: "sb-id", text: s.id }),
        el("div", { class: "sb-meta" }, [
          el("span", { text: s.profile || "—" }),
          el("span", { text: "·" }),
          el("span", { text: s.backend || "—" }),
          // Owner is only meaningful to an admin viewing other principals'
          // sandboxes; non-admins only ever see their own.
          (s.owner && auth.principal && auth.principal.admin)
            ? el("span", { class: "sb-owner", title: "owner", text: "@" + s.owner })
            : null,
          el("span", { class: `sb-status ${status}`, text: status }),
        ]),
        el("button", {
          class: "kill-btn",
          title: "Kill sandbox",
          text: "✕",
          onClick: (ev) => {
            ev.stopPropagation();
            killSandbox(s.id);
          },
        }),
      ]
    );
    list.appendChild(item);
  }
}

function openNewSandboxModal() {
  const profile = $("#profile-select").value;
  if (!profile) {
    toast("Pick a profile first.", "warn");
    return;
  }
  $("#new-modal-profile").textContent = profile;
  $("#new-modal-copyfrom").value = "";
  $("#new-modal").classList.remove("hidden");
  $("#new-modal-copyfrom").focus();
}

function closeNewSandboxModal() {
  $("#new-modal").classList.add("hidden");
}

async function createSandbox() {
  const profile = $("#new-modal-profile").textContent.trim();
  if (!profile) {
    toast("Pick a profile first.", "warn");
    return;
  }
  const copyFrom = $("#new-modal-copyfrom").value.trim();
  const btn = $("#new-modal-create");
  btn.disabled = true;
  try {
    const body = { profile };
    if (copyFrom) body.copy_from = copyFrom;
    const { data } = await api("POST", "/v1/sandboxes", body);
    toast(`Sandbox ${data.id} created`, "success");
    closeNewSandboxModal();
    await loadSandboxes();
    if (data.id) selectSandbox(data.id);
  } catch (e) {
    toast("Create failed: " + e.message, "error");
  } finally {
    btn.disabled = false;
  }
}

async function killSandbox(id) {
  try {
    await api("DELETE", "/v1/sandboxes/" + encodeURIComponent(id));
    toast(`Sandbox ${id} killed`, "info");
    if (state.selected === id) selectSandbox(null);
    await loadSandboxes();
  } catch (e) {
    toast("Kill failed: " + e.message, "error");
  }
}

function selectSandbox(id) {
  state.selected = id;
  renderSandboxList();

  const empty = $("#panel-empty");
  const bodyEl = $("#panel-body");
  if (!id) {
    empty.classList.remove("hidden");
    bodyEl.classList.add("hidden");
    teardownTerminalSocket();
    stopAuditPoll();
    state.egress = [];
    state.budget = null;
    renderEgress();
    renderBudget();
    return;
  }
  empty.classList.add("hidden");
  bodyEl.classList.remove("hidden");

  const sb = state.sandboxes.find((s) => s.id === id) || {};
  $("#sel-id").textContent = id;
  $("#sel-meta").textContent = `${sb.profile || "—"} · ${sb.backend || "—"} · ${sb.image || "—"} · ${sb.status || "—"}`;
  const simSel = $("#sim-profile-select");
  if (simSel && sb.profile) {
    simSel.value = sb.profile;
  }

  // Re-activate the current tab for the new sandbox.
  activateTab(state.activeTab, true);
}

/* ---------------- View switch (Sandboxes | Fleets) ---------------- */
function switchView(name) {
  if (name === state.activeView) return;
  state.activeView = name;

  $("#view-sandboxes").classList.toggle("active", name === "sandboxes");
  $("#view-sandboxes").setAttribute("aria-selected", String(name === "sandboxes"));
  $("#view-fleets").classList.toggle("active", name === "fleets");
  $("#view-fleets").setAttribute("aria-selected", String(name === "fleets"));

  $("#sb-sidebar").classList.toggle("hidden", name !== "sandboxes");
  $("#fleet-sidebar").classList.toggle("hidden", name !== "fleets");
  $("#sb-panel").classList.toggle("hidden", name !== "sandboxes");
  $("#fleet-panel").classList.toggle("hidden", name !== "fleets");

  if (name === "fleets") refreshFleets();
}

/* ---------------- Fleets ---------------- */
function fleetPath(suffix) {
  return `/v1/fleets/${encodeURIComponent(state.fleetSelected)}${suffix || ""}`;
}

async function refreshFleets() {
  await loadFleets();
  if (state.fleetSelected) await refreshFleetDetail();
}

async function loadFleets() {
  try {
    const { data } = await api("GET", "/v1/fleets");
    state.fleets = (data && data.fleets) || [];
  } catch (e) {
    state.fleets = [];
    // don't spam toast on poll; health badge covers offline
  }
  renderFleetList();
  if (state.fleetSelected && !state.fleets.find((f) => f.id === state.fleetSelected)) {
    selectFleet(null);
  }
}

function renderFleetList() {
  const list = $("#fleet-list");
  list.innerHTML = "";
  if (state.fleets.length === 0) {
    list.appendChild(el("li", { class: "empty-note", text: "No fleets yet." }));
    return;
  }
  for (const f of state.fleets) {
    const st = f.stats || {};
    const total = st.total != null ? st.total : 0;
    const done = st.done != null ? st.done : 0;
    const sbCount = (f.sandboxes || []).length;
    const item = el(
      "li",
      {
        class: "sandbox-item" + (f.id === state.fleetSelected ? " active" : ""),
        title: f.id,
        onClick: () => selectFleet(f.id),
      },
      [
        el("div", { class: "sb-id", text: f.id }),
        el("div", { class: "sb-meta" }, [
          el("span", { text: f.profile || "—" }),
          el("span", { text: "·" }),
          el("span", { text: `${done}/${total} done` }),
          el("span", { text: "·" }),
          el("span", { text: `${sbCount} sb` }),
        ]),
        el("button", {
          class: "kill-btn",
          title: "Delete fleet",
          text: "✕",
          onClick: (ev) => {
            ev.stopPropagation();
            deleteFleet(f.id);
          },
        }),
      ]
    );
    list.appendChild(item);
  }
}

async function createFleet() {
  const profile = $("#fleet-profile-select").value;
  if (!profile) {
    toast("Pick a profile first.", "warn");
    return;
  }
  const btn = $("#fleet-create-btn");
  btn.disabled = true;
  try {
    const { data } = await api("POST", "/v1/fleets", { profile });
    toast(`Fleet ${data.id} created`, "success");
    await loadFleets();
    if (data.id) selectFleet(data.id);
  } catch (e) {
    toast("Create fleet failed: " + e.message, "error");
  } finally {
    btn.disabled = false;
  }
}

async function deleteFleet(id) {
  try {
    await api("DELETE", "/v1/fleets/" + encodeURIComponent(id));
    toast(`Fleet ${id} deleted`, "info");
    if (state.fleetSelected === id) selectFleet(null);
    await loadFleets();
  } catch (e) {
    toast("Delete failed: " + e.message, "error");
  }
}

function selectFleet(id) {
  state.fleetSelected = id;
  state.fleetTasks = [];
  renderFleetList();

  const empty = $("#fleet-empty");
  const bodyEl = $("#fleet-body");
  if (!id) {
    empty.classList.remove("hidden");
    bodyEl.classList.add("hidden");
    return;
  }
  empty.classList.add("hidden");
  bodyEl.classList.remove("hidden");
  $("#fleet-claim-note").classList.add("hidden");
  refreshFleetDetail();
}

async function refreshFleetDetail() {
  if (!state.fleetSelected) return;
  try {
    const [fleetRes, tasksRes] = await Promise.all([
      api("GET", fleetPath("")),
      api("GET", fleetPath("/tasks")),
    ]);
    state.fleetTasks = (tasksRes.data && tasksRes.data.tasks) || [];
    renderFleetDetail(fleetRes.data || {});
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      toast("Fleet no longer exists", "warn");
      selectFleet(null);
      loadFleets();
    }
    // otherwise leave prior contents; global health badge covers offline
  }
}

function renderFleetDetail(fleet) {
  const sbs = fleet.sandboxes || [];
  const sbCount = sbs.length;
  $("#fleet-sel-id").textContent = fleet.id || state.fleetSelected;
  $("#fleet-sel-meta").textContent =
    `${fleet.profile || "—"} · ${sbCount} sandbox${sbCount === 1 ? "" : "es"}`;
  $("#fleet-sb-count").textContent = `${sbCount} member${sbCount === 1 ? "" : "s"}`;

  renderFleetStats(fleet.stats || {});
  renderFleetChips(sbs);
  renderFleetTasks();
}

function renderFleetStats(stats) {
  const bar = $("#fleet-stats");
  bar.innerHTML = "";
  for (const key of ["total", "pending", "claimed", "done", "failed"]) {
    bar.appendChild(
      el("span", { class: `stat ${key}` }, [
        key + " ",
        el("b", { text: String(stats[key] != null ? stats[key] : 0) }),
      ])
    );
  }
}

function renderFleetChips(ids) {
  const wrap = $("#fleet-chips");
  wrap.innerHTML = "";
  if (!ids.length) {
    wrap.appendChild(el("span", { class: "empty-note", text: "No member sandboxes." }));
    return;
  }
  for (const id of ids) {
    wrap.appendChild(el("span", { class: "chip", text: id, title: id }));
  }
}

function renderFleetTasks() {
  const body = $("#fleet-task-body");
  body.innerHTML = "";
  if (!state.fleetTasks.length) {
    body.appendChild(
      el("tr", {}, el("td", { colspan: "6", class: "empty-note", text: "No tasks yet." }))
    );
    return;
  }
  for (const t of state.fleetTasks) {
    const st = (t.state || "").toLowerCase();
    const resultOrError = st === "failed" ? t.error || "" : t.result || "";

    const actions = el("div", { class: "task-actions" });
    if (st === "claimed") {
      const requeue = el("input", { type: "checkbox", checked: "checked", class: "requeue-box" });
      actions.appendChild(
        el("button", {
          class: "btn btn-sm btn-approve",
          text: "Complete",
          onClick: () => completeFleetTask(t.id),
        })
      );
      actions.appendChild(
        el("button", {
          class: "btn btn-sm btn-deny",
          text: "Fail",
          onClick: () => failFleetTask(t.id, requeue.checked),
        })
      );
      actions.appendChild(
        el("label", { class: "requeue-label", title: "Requeue task on failure" }, [requeue, " requeue"])
      );
    }

    body.appendChild(
      el("tr", {}, [
        el("td", { text: t.payload || "", title: t.payload || "" }),
        el("td", {}, el("span", { class: "state-tag " + st, text: st || "—" })),
        el("td", { text: t.owner || "—" }),
        el("td", { text: String(t.attempts != null ? t.attempts : 0) }),
        el("td", {
          class: st === "failed" ? "output-err" : "",
          text: resultOrError,
          title: resultOrError,
        }),
        el("td", {}, actions),
      ])
    );
  }
}

async function addFleetTask() {
  if (!state.fleetSelected) return;
  const input = $("#fleet-task-payload");
  const payload = input.value.trim();
  if (!payload) {
    toast("Enter a task payload.", "warn");
    return;
  }
  const btn = $("#fleet-add-task");
  btn.disabled = true;
  try {
    await api("POST", fleetPath("/tasks"), { payload });
    input.value = "";
    toast("Task added", "success");
    await refreshFleetDetail();
  } catch (e) {
    toast("Add task failed: " + e.message, "error");
  } finally {
    btn.disabled = false;
  }
}

async function claimFleetTask() {
  if (!state.fleetSelected) return;
  const owner = $("#fleet-claim-owner").value.trim() || "operator";
  const note = $("#fleet-claim-note");
  const btn = $("#fleet-claim");
  btn.disabled = true;
  try {
    const { data } = await api("POST", fleetPath("/claim"), { owner });
    note.classList.remove("hidden");
    if (data && data.claimed && data.task) {
      note.className = "note ok";
      note.textContent = `Claimed ${data.task.id} by ${owner}: ${data.task.payload || ""}`;
      toast(`Task claimed by ${owner}`, "success");
    } else {
      note.className = "note";
      note.textContent = "No pending tasks to claim.";
    }
    await refreshFleetDetail();
  } catch (e) {
    toast("Claim failed: " + e.message, "error");
  } finally {
    btn.disabled = false;
  }
}

async function completeFleetTask(taskId) {
  const result = window.prompt("Result for this task:", "ok");
  if (result === null) return;
  try {
    await api("POST", fleetPath(`/tasks/${encodeURIComponent(taskId)}/complete`), { result });
    toast("Task completed", "success");
    await refreshFleetDetail();
  } catch (e) {
    toast("Complete failed: " + e.message, "error");
  }
}

async function failFleetTask(taskId, requeue) {
  const error = window.prompt("Failure reason:", "error");
  if (error === null) return;
  try {
    await api("POST", fleetPath(`/tasks/${encodeURIComponent(taskId)}/fail`), {
      error,
      requeue: !!requeue,
    });
    toast(requeue ? "Task failed — requeued" : "Task failed", "info");
    await refreshFleetDetail();
  } catch (e) {
    toast("Fail failed: " + e.message, "error");
  }
}

/* ---------------- Tabs ---------------- */
function activateTab(name, force = false) {
  if (!force && name === state.activeTab) return;
  state.activeTab = name;
  $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  $$(".tab-pane").forEach((p) => p.classList.toggle("active", p.dataset.pane === name));

  stopAuditPoll();

  if (name === "terminal") {
    ensureTerminal();
    connectTerminal();
  } else {
    // only keep the socket alive while the terminal tab is visible
    teardownTerminalSocket();
  }

  if (name === "audit") {
    refreshAudit();
    startAuditPoll();
  }
  if (name === "policy") {
    renderSimulationResults();
  }
  if (name === "egress") {
    refreshEgress();
  }
  if (name === "budget") {
    refreshBudget();
  }
}

/* ---------------- Terminal (xterm.js + WebSocket) ---------------- */
function ensureTerminal() {
  if (state.term) return;
  if (typeof Terminal === "undefined") {
    toast("xterm.js failed to load (offline CDN?)", "error");
    return;
  }
  const term = new Terminal({
    convertEol: true,
    cursorBlink: true,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
    fontSize: 13,
    theme: {
      background: "#05070d",
      foreground: "#dde3ee",
      cursor: "#5b8cff",
      selectionBackground: "#2b3550",
    },
  });
  let fit = null;
  if (typeof FitAddon !== "undefined" && FitAddon.FitAddon) {
    fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
  }
  term.open($("#terminal"));
  if (fit) {
    try { fit.fit(); } catch {}
  }
  term.onData((d) => {
    if (state.socket && state.socket.readyState === WebSocket.OPEN) {
      state.socket.send(d);
    }
  });
  state.term = term;
  state.fitAddon = fit;

  window.addEventListener("resize", debounce(fitAndResize, 120));
  $("#term-reconnect").addEventListener("click", () => connectTerminal(true));
}

function fitAndResize() {
  if (!state.term || !state.fitAddon) return;
  try { state.fitAddon.fit(); } catch { return; }
  sendResize();
}

function sendResize() {
  if (!state.term) return;
  if (state.socket && state.socket.readyState === WebSocket.OPEN) {
    const msg = { type: "resize", rows: state.term.rows, cols: state.term.cols };
    state.socket.send(JSON.stringify(msg));
  }
}

function setTermStatus(kind, label) {
  const s = $("#term-status");
  s.className = "conn-status " + kind;
  s.textContent = label;
}

function teardownTerminalSocket() {
  if (state.socket) {
    try { state.socket.close(); } catch {}
    state.socket = null;
  }
  state.termSandbox = null;
  setTermStatus("conn-off", "disconnected");
}

function connectTerminal(forceReconnect = false) {
  if (!state.selected || !state.term) return;
  // Already connected to the right sandbox?
  if (
    !forceReconnect &&
    state.socket &&
    state.termSandbox === state.selected &&
    (state.socket.readyState === WebSocket.OPEN || state.socket.readyState === WebSocket.CONNECTING)
  ) {
    return;
  }
  teardownTerminalSocket();

  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  setTermStatus("conn-off", "connecting…");
  requestTerminalTicket(state.selected)
    .then((ticket) => {
      const url =
        `${proto}//${location.host}/v1/sandboxes/${encodeURIComponent(state.selected)}/terminal` +
        `?ticket=${encodeURIComponent(ticket)}`;
      const socket = new WebSocket(url);
      socket.binaryType = "arraybuffer";
      state.socket = socket;
      state.termSandbox = state.selected;

      socket.onopen = () => {
        setTermStatus("conn-on", "connected");
        fitAndResize();
        state.term.focus();
      };
      socket.onmessage = (ev) => {
        if (typeof ev.data === "string") {
          state.term.write(ev.data);
        } else if (ev.data instanceof ArrayBuffer) {
          state.term.write(new Uint8Array(ev.data));
        } else if (ev.data instanceof Blob) {
          ev.data.arrayBuffer().then((buf) => state.term.write(new Uint8Array(buf)));
        }
      };
      socket.onerror = () => {
        setTermStatus("conn-err", "error");
      };
      socket.onclose = () => {
        if (state.socket === socket) {
          setTermStatus("conn-off", "disconnected");
          state.socket = null;
        }
      };
    })
    .catch((e) => {
      setTermStatus("conn-err", "error");
      toast("Terminal connect failed: " + e.message, "error");
    });
}

async function requestTerminalTicket(sandboxID) {
  const { data } = await api("POST", "/v1/tickets", {
    kind: "terminal",
    sandbox_id: sandboxID,
    ttl_seconds: 30,
  });
  if (!data || !data.ticket) {
    throw new Error("terminal ticket unavailable");
  }
  return data.ticket;
}

/* ---------------- Files tab ---------------- */
function sbPath(suffix) {
  return `/v1/sandboxes/${encodeURIComponent(state.selected)}${suffix}`;
}

async function fileList() {
  if (!state.selected) return;
  const path = $("#list-path").value || ".";
  const out = $("#list-output");
  out.textContent = "…";
  try {
    const { data } = await api("POST", sbPath("/file/list"), { path });
    out.textContent = data.output || "(empty)";
  } catch (e) {
    out.textContent = "";
    toast("List failed: " + e.message, "error");
  }
}

async function fileRead() {
  if (!state.selected) return;
  const path = $("#file-path").value.trim();
  const note = $("#file-note");
  if (!path) { toast("Enter a file path.", "warn"); return; }
  try {
    const { data } = await api("POST", sbPath("/file/read"), { path });
    $("#file-content").value = data.content != null ? data.content : "";
    note.className = "note ok";
    note.textContent = `Loaded ${path}`;
  } catch (e) {
    note.className = "note err";
    note.textContent = "Read failed: " + e.message;
  }
}

async function fileWrite() {
  if (!state.selected) return;
  const path = $("#file-path").value.trim();
  const content = $("#file-content").value;
  const note = $("#file-note");
  if (!path) { toast("Enter a file path.", "warn"); return; }
  try {
    const { data } = await api("POST", sbPath("/file/write"), { path, content });
    note.className = "note ok";
    note.textContent = `Wrote ${data.bytes != null ? data.bytes : content.length} bytes to ${path}`;
  } catch (e) {
    note.className = "note err";
    note.textContent = "Write failed: " + e.message;
  }
}

async function fileSearch() {
  if (!state.selected) return;
  const query = $("#search-query").value;
  const path = $("#search-path").value || ".";
  const out = $("#search-output");
  if (!query) { toast("Enter a search query.", "warn"); return; }
  out.textContent = "…";
  try {
    const { data } = await api("POST", sbPath("/file/search"), { query, path });
    out.textContent = data.output || "(no matches)";
  } catch (e) {
    out.textContent = "";
    toast("Search failed: " + e.message, "error");
  }
}

/* ---------------- Shell / code exec ---------------- */
function renderExecResult(prefix, status, data) {
  $(`#${prefix}-result`).classList.remove("hidden");
  const verdictEl = $(`#${prefix}-verdict`);
  const exitEl = $(`#${prefix}-exit`);
  const durEl = $(`#${prefix}-duration`);
  const noteEl = $(`#${prefix}-note`);
  const outEl = $(`#${prefix}-stdout`);
  const errEl = $(`#${prefix}-stderr`);

  noteEl.className = "note hidden";
  noteEl.textContent = "";

  const verdict = data.verdict || (status === 202 ? "require-approval" : status === 403 ? "deny" : "allow");
  verdictEl.className = "verdict " + verdict;
  verdictEl.textContent = verdict;

  if (status === 202 || verdict === "require-approval") {
    exitEl.textContent = "";
    durEl.textContent = "";
    outEl.textContent = "";
    errEl.textContent = "";
    noteEl.className = "note warn";
    noteEl.textContent =
      "Action requires approval" +
      (data.approval_id ? ` (id ${data.approval_id})` : "") +
      ". Open the Approvals panel to allow or deny it.";
    refreshApprovals();
    return;
  }
  if (status === 403 || verdict === "deny") {
    exitEl.textContent = "";
    durEl.textContent = "";
    outEl.textContent = "";
    errEl.textContent = "";
    noteEl.className = "note err";
    noteEl.textContent = "Denied by policy: " + (data.reason || "no reason given");
    return;
  }

  exitEl.textContent = "exit " + (data.exit_code != null ? data.exit_code : "?");
  durEl.textContent = data.duration_ms != null ? data.duration_ms + " ms" : "";
  outEl.textContent = data.stdout || "";
  errEl.textContent = data.stderr || "";
}

async function runShell() {
  if (!state.selected) return;
  const raw = $("#shell-cmd").value.trim();
  const workdir = $("#shell-workdir").value.trim();
  if (!raw) { toast("Enter a command.", "warn"); return; }
  const command = tokenize(raw);
  const btn = $("#shell-run");
  btn.disabled = true;
  try {
    const { status, data } = await api("POST", sbPath("/shell/exec"), { command, workdir });
    renderExecResult("shell", status, data);
  } catch (e) {
    if (e instanceof ApiError && (e.status === 403 || e.status === 202)) {
      renderExecResult("shell", e.status, e.body);
    } else {
      renderExecResult("shell", 500, { verdict: "deny", reason: e.message, stderr: e.message });
      toast("Exec failed: " + e.message, "error");
    }
  } finally {
    btn.disabled = false;
  }
}

async function runCode() {
  if (!state.selected) return;
  const lang = $("#code-lang").value;
  const code = $("#code-source").value;
  if (!code.trim()) { toast("Enter some code.", "warn"); return; }
  const btn = $("#code-run");
  btn.disabled = true;
  try {
    const { status, data } = await api("POST", sbPath("/code/" + lang), { code });
    renderExecResult("code", status, data);
  } catch (e) {
    if (e instanceof ApiError && (e.status === 403 || e.status === 202)) {
      renderExecResult("code", e.status, e.body);
    } else {
      renderExecResult("code", 500, { verdict: "deny", reason: e.message, stderr: e.message });
      toast("Code exec failed: " + e.message, "error");
    }
  } finally {
    btn.disabled = false;
  }
}

// Minimal shell-ish tokenizer: splits on whitespace, respects single/double quotes.
function tokenize(str) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(str)) !== null) {
    out.push(m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : m[3]);
  }
  return out.length ? out : [str];
}

/* ---------------- Audit tab ---------------- */
async function refreshAudit() {
  if (!state.selected) return;
  const body = $("#audit-body");
  try {
    const { data } = await api("GET", sbPath("/audit"));
    const events = (data && data.events) || [];
    if (events.length === 0) {
      body.innerHTML = "";
      body.appendChild(
        el("tr", {}, el("td", { colspan: "6", class: "empty-note", text: "No events yet." }))
      );
      return;
    }
    body.innerHTML = "";
    for (const ev of events) {
      const verdict = (ev.verdict || "").toLowerCase();
      body.appendChild(
        el("tr", {}, [
          el("td", { text: String(ev.seq != null ? ev.seq : "") }),
          el("td", { text: fmtTime(ev.time) }),
          el("td", { text: ev.tool || "" }),
          el("td", { text: ev.action || "", title: ev.action || "" }),
          el("td", {}, el("span", { class: "v-tag " + verdict, text: verdict || "—" })),
          el("td", { text: ev.exit_code != null ? String(ev.exit_code) : "" }),
        ])
      );
    }
  } catch (e) {
    // leave prior contents; only toast on manual
  }
}

function startAuditPoll() {
  stopAuditPoll();
  state.timers.audit = setInterval(refreshAudit, POLL_MS);
}
function stopAuditPoll() {
  if (state.timers.audit) {
    clearInterval(state.timers.audit);
    state.timers.audit = null;
  }
}

/* ---------------- Approvals ---------------- */
async function refreshApprovals() {
  try {
    const { data } = await api("GET", "/v1/approvals");
    state.approvals = (data && data.approvals) || [];
  } catch {
    state.approvals = state.approvals || [];
  }
  renderApprovals();
}

function renderApprovals() {
  const n = state.approvals.length;
  const countEl = $("#approvals-count");
  countEl.textContent = String(n);
  countEl.classList.toggle("hidden", n === 0);

  const list = $("#approvals-list");
  list.innerHTML = "";
  if (n === 0) {
    list.appendChild(el("li", { class: "empty-note", text: "No pending approvals." }));
    return;
  }
  for (const a of state.approvals) {
    list.appendChild(
      el("li", { class: "approval-item" }, [
        el("div", { class: "approval-head" }, [
          el("span", { class: "approval-tool", text: a.tool || "action" }),
          el("span", { class: "muted mono", text: a.sandbox || "" }),
        ]),
        el("div", { class: "approval-action", text: a.action || "" }),
        a.reason ? el("div", { class: "approval-reason", text: a.reason }) : null,
        el("div", { class: "approval-meta", text: `requested ${fmtTime(a.created)}` }),
        canApprove()
          ? el("div", { class: "approval-actions" }, [
              el("button", {
                class: "btn btn-sm btn-approve",
                text: "Approve",
                onClick: () => decideApproval(a.id, "approve"),
              }),
              el("button", {
                class: "btn btn-sm btn-deny",
                text: "Deny",
                onClick: () => decideApproval(a.id, "deny"),
              }),
            ])
          : el("div", { class: "approval-meta", text: "You do not have permission to resolve approvals." }),
      ])
    );
  }
}

async function decideApproval(id, decision) {
  try {
    await api("POST", `/v1/approvals/${encodeURIComponent(id)}/${decision}`);
    toast(`Approval ${decision === "approve" ? "approved" : "denied"}`, decision === "approve" ? "success" : "info");
    await refreshApprovals();
  } catch (e) {
    toast("Failed to " + decision + ": " + e.message, "error");
  }
}

function openDrawer() { $("#approvals-drawer").classList.remove("hidden"); refreshApprovals(); }
function closeDrawer() { $("#approvals-drawer").classList.add("hidden"); }

/* ---------------- Policy simulation ---------------- */
function parseSimulationActions(text) {
  const out = [];
  const lines = String(text || "").split(/\r?\n/);
  for (const line of lines) {
    const raw = line.trim();
    if (!raw || raw.startsWith("#")) continue;
    const parts = raw.split("|");
    if (parts.length < 2) {
      throw new Error(`invalid action line: "${raw}" (use "tool | action")`);
    }
    const tool = parts[0].trim();
    const action = parts.slice(1).join("|").trim();
    if (!tool || !action) {
      throw new Error(`invalid action line: "${raw}"`);
    }
    out.push({ tool, command: action, args: tokenize(action) });
  }
  return out;
}

async function runPolicySimulation() {
  const note = $("#sim-note");
  note.className = "note";
  note.textContent = "";
  if (!state.selected) {
    note.className = "note warn";
    note.textContent = "Select a sandbox first.";
    return;
  }
  const raw = $("#sim-actions").value;
  let actions;
  try {
    actions = parseSimulationActions(raw);
  } catch (e) {
    note.className = "note err";
    note.textContent = e.message;
    return;
  }
  if (!actions.length) {
    note.className = "note warn";
    note.textContent = "Add one or more sample actions.";
    return;
  }
  const useSelected = $("#sim-use-selected-profile").checked;
  const selectedSB = state.sandboxes.find((s) => s.id === state.selected) || {};
  const profileName = useSelected ? (selectedSB.profile || "") : ($("#sim-profile-select").value || "");
  if (!profileName) {
    note.className = "note warn";
    note.textContent = "Pick a profile to simulate.";
    return;
  }
  const btn = $("#sim-run");
  btn.disabled = true;
  try {
    const { data } = await api("POST", "/v1/policy/simulate", {
      profile_name: profileName,
      actions,
    });
    state.simulation = data || {};
    renderSimulationResults();
    note.className = "note ok";
    note.textContent = `Simulated ${actions.length} action${actions.length === 1 ? "" : "s"} against ${profileName}.`;
  } catch (e) {
    note.className = "note err";
    note.textContent = "Simulation failed: " + e.message;
  } finally {
    btn.disabled = false;
  }
}

function renderSimulationResults() {
  const wrap = $("#sim-results");
  if (!wrap) return;
  wrap.innerHTML = "";
  const results = (state.simulation && state.simulation.results) || [];
  if (!results.length) {
    wrap.className = "sim-results empty-note";
    wrap.textContent = "Run a simulation to see verdicts and trace.";
    return;
  }
  wrap.className = "sim-results";
  for (const r of results) {
    const verdict = String(r.verdict || "allow");
    const title = r.name || `${r.tool || "action"} ${r.arg || ""}`.trim();
    const trace = Array.isArray(r.trace) ? r.trace : [];
    const traceText = trace.map((step) => {
      const idx = step.index != null ? `#${step.index}` : "";
      const engine = step.engine || "";
      const match = step.matched ? "match" : "skip";
      const summary = step.expr || step.match || step.query || step.tool || "";
      return `${idx} ${engine} ${match} ${summary}`.trim();
    }).join("\n");
    wrap.appendChild(
      el("div", { class: "sim-item" }, [
        el("div", { class: "sim-head" }, [
          el("span", { class: "mono", text: title }),
          el("span", { class: "verdict " + verdict, text: verdict }),
        ]),
        r.reason ? el("div", { class: "note " + (verdict === "deny" ? "err" : "warn"), text: r.reason }) : null,
        traceText ? el("div", { class: "sim-trace", text: traceText }) : null,
      ])
    );
  }
}

/* ---------------- Egress explorer ---------------- */
async function refreshEgress() {
  if (!state.selected) return;
  try {
    const { data } = await api("GET", sbPath("/egress"));
    state.egress = (data && data.decisions) || [];
  } catch (e) {
    state.egress = [];
  }
  renderEgress();
}

function renderEgress() {
  const body = $("#egress-body");
  if (!body) return;
  body.innerHTML = "";
  if (!state.selected) {
    body.appendChild(el("tr", {}, el("td", { colspan: "5", class: "empty-note", text: "Select a sandbox first." })));
    return;
  }
  if (!state.egress.length) {
    body.appendChild(el("tr", {}, el("td", { colspan: "5", class: "empty-note", text: "No decisions yet." })));
    return;
  }
  for (const d of state.egress.slice().reverse()) {
    body.appendChild(el("tr", {}, [
      el("td", { text: fmtTime(d.timestamp || d.time) }),
      el("td", { text: d.host || "—", title: d.host || "" }),
      el("td", { text: d.ip || "—" }),
      el("td", {}, el("span", { class: "verdict-cell " + (d.allow ? "allow" : "deny"), text: d.allow ? "allow" : "deny" })),
      el("td", { text: d.reason || "", title: d.reason || "" }),
    ]));
  }
}

/* ---------------- Budget burn-down ---------------- */
async function refreshBudget() {
  if (!state.selected) return;
  try {
    const [sbRes, auditRes] = await Promise.all([
      api("GET", sbPath("")),
      api("GET", sbPath("/audit")),
    ]);
    state.budget = deriveBudget(sbRes.data || {}, (auditRes.data && auditRes.data.events) || []);
  } catch (e) {
    state.budget = null;
  }
  renderBudget();
}

function deriveBudget(sb, events) {
  const limits = sb.limits || {};
  const usage = sb.usage || {};
  const execCount = events.filter((ev) => ev.tool && ev.tool !== "approval" && ev.tool !== "usage").length;
  const egressCount = events.filter((ev) => ev.tool === "browser" || ev.tool === "net").length;
  let wallSeconds = 0;
  if (events.length > 1) {
    const times = events
      .map((ev) => new Date(ev.time).getTime())
      .filter((v) => Number.isFinite(v))
      .sort((a, b) => a - b);
    if (times.length > 1) {
      wallSeconds = Math.max(0, Math.floor((times[times.length - 1] - times[0]) / 1000));
    }
  }
  return {
    usage: {
      tokens: usage.tokens || 0,
      cost_usd: usage.cost_usd || 0,
      execs: execCount,
      egress_requests: egressCount,
      wall_seconds: wallSeconds,
    },
    limits: {
      max_tokens: limits.max_tokens || 0,
      max_cost_usd: limits.max_cost_usd || 0,
      max_execs: limits.max_execs || 0,
      egress_requests: limits.egress_requests || 0,
      wall_clock: limits.wall_clock || "",
    },
  };
}

function parseDurationSeconds(raw) {
  const s = String(raw || "").trim();
  if (!s) return 0;
  let total = 0;
  const re = /(\d+)(h|m|s)/g;
  let m;
  while ((m = re.exec(s)) !== null) {
    const n = Number(m[1]);
    if (m[2] === "h") total += n * 3600;
    else if (m[2] === "m") total += n * 60;
    else total += n;
  }
  return total;
}

function money(v) {
  return "$" + Number(v || 0).toFixed(4);
}

function renderBudget() {
  const grid = $("#budget-grid");
  if (!grid) return;
  grid.innerHTML = "";
  if (!state.selected) {
    grid.appendChild(el("div", { class: "empty-note", text: "Select a sandbox first." }));
    return;
  }
  if (!state.budget) {
    grid.appendChild(el("div", { class: "empty-note", text: "Budget usage unavailable." }));
    return;
  }
  const u = state.budget.usage;
  const lim = state.budget.limits;
  const rows = [
    { label: "Tokens", used: u.tokens, limit: lim.max_tokens, usedLabel: String(u.tokens), limitLabel: lim.max_tokens ? String(lim.max_tokens) : "unlimited" },
    { label: "Cost USD", used: u.cost_usd, limit: lim.max_cost_usd, usedLabel: money(u.cost_usd), limitLabel: lim.max_cost_usd ? money(lim.max_cost_usd) : "unlimited" },
    { label: "Exec actions", used: u.execs, limit: lim.max_execs, usedLabel: String(u.execs), limitLabel: lim.max_execs ? String(lim.max_execs) : "unlimited" },
    { label: "Egress requests", used: u.egress_requests, limit: lim.egress_requests, usedLabel: String(u.egress_requests), limitLabel: lim.egress_requests ? String(lim.egress_requests) : "unlimited" },
    {
      label: "Wall clock",
      used: u.wall_seconds,
      limit: parseDurationSeconds(lim.wall_clock),
      usedLabel: `${u.wall_seconds}s`,
      limitLabel: lim.wall_clock || "unlimited",
    },
  ];
  for (const row of rows) {
    const ratio = row.limit > 0 ? Math.min(1, row.used / row.limit) : 0;
    grid.appendChild(el("div", { class: "budget-card" }, [
      el("div", { class: "budget-label", text: row.label }),
      el("div", { class: "budget-value", text: `${row.usedLabel} / ${row.limitLabel}` }),
      el("div", { class: "budget-bar" }, el("div", { class: "budget-fill", style: `width:${Math.round(ratio * 100)}%` })),
    ]));
  }
}

/* ---------------- Utilities ---------------- */
function fmtTime(t) {
  if (!t) return "";
  const d = new Date(t);
  if (isNaN(d.getTime())) return String(t);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function debounce(fn, ms) {
  let h;
  return (...args) => {
    clearTimeout(h);
    h = setTimeout(() => fn(...args), ms);
  };
}

/* ---------------- Polling loop ---------------- */
function startGlobalPoll() {
  if (state.timers.global) return;
  const tick = async () => {
    await Promise.all([
      refreshHealth(),
      refreshAuditVerify(),
      loadSandboxes(),
      canApprove() ? refreshApprovals() : Promise.resolve(),
      state.activeView === "fleets" ? refreshFleets() : Promise.resolve(),
      state.activeTab === "egress" ? refreshEgress() : Promise.resolve(),
      state.activeTab === "budget" ? refreshBudget() : Promise.resolve(),
    ]);
  };
  tick();
  state.timers.global = setInterval(tick, POLL_MS);
}

function stopGlobalPoll() {
  if (state.timers.global) {
    clearInterval(state.timers.global);
    state.timers.global = null;
  }
}

/* ---------------- Wiring ---------------- */
function wireEvents() {
  $("#create-btn").addEventListener("click", openNewSandboxModal);
  $("#new-modal-create").addEventListener("click", createSandbox);
  $$("[data-close-modal]").forEach((n) => n.addEventListener("click", closeNewSandboxModal));
  $("#new-modal-copyfrom").addEventListener("keydown", (e) => { if (e.key === "Enter") createSandbox(); });
  $("#refresh-btn").addEventListener("click", () => { loadSandboxes(); loadProfiles(); });

  // View switch + fleets
  $("#view-sandboxes").addEventListener("click", () => switchView("sandboxes"));
  $("#view-fleets").addEventListener("click", () => switchView("fleets"));
  $("#fleet-create-btn").addEventListener("click", createFleet);
  $("#fleet-refresh-btn").addEventListener("click", () => { loadFleets(); loadProfiles(); });
  $("#fleet-add-task").addEventListener("click", addFleetTask);
  $("#fleet-task-payload").addEventListener("keydown", (e) => { if (e.key === "Enter") addFleetTask(); });
  $("#fleet-claim").addEventListener("click", claimFleetTask);
  $("#fleet-claim-owner").addEventListener("keydown", (e) => { if (e.key === "Enter") claimFleetTask(); });

  $$(".tab").forEach((t) =>
    t.addEventListener("click", () => activateTab(t.dataset.tab))
  );

  $("#list-btn").addEventListener("click", fileList);
  $("#read-btn").addEventListener("click", fileRead);
  $("#write-btn").addEventListener("click", fileWrite);
  $("#search-btn").addEventListener("click", fileSearch);
  $("#search-query").addEventListener("keydown", (e) => { if (e.key === "Enter") fileSearch(); });
  $("#list-path").addEventListener("keydown", (e) => { if (e.key === "Enter") fileList(); });

  $("#shell-run").addEventListener("click", runShell);
  $("#shell-cmd").addEventListener("keydown", (e) => { if (e.key === "Enter") runShell(); });
  $("#code-run").addEventListener("click", runCode);
  $("#sim-run").addEventListener("click", runPolicySimulation);
  $("#sim-actions").addEventListener("keydown", (e) => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") runPolicySimulation(); });
  $("#egress-refresh").addEventListener("click", refreshEgress);

  $("#approvals-btn").addEventListener("click", openDrawer);
  $$("[data-close-drawer]").forEach((n) => n.addEventListener("click", closeDrawer));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeDrawer(); closeNewSandboxModal(); } });
}

/* ---------------- Login / identity ---------------- */
function showLogin() {
  const ov = $("#login-overlay");
  if (ov) ov.classList.remove("hidden");
  const t = $("#login-token");
  if (t) setTimeout(() => t.focus(), 0);
}

function hideLogin() {
  const ov = $("#login-overlay");
  if (ov) ov.classList.add("hidden");
}

// applyPrincipal renders the caller's identity in the topbar and gates
// controls (create, approvals) that the identity isn't permitted to use.
function applyPrincipal() {
  const p = auth.principal || {};
  const chip = $("#identity");
  if (chip) {
    chip.classList.remove("hidden");
    let name, role;
    if (auth.rbac) {
      name = p.name || "(unnamed)";
      role = p.admin ? "admin" : (p.can_approve ? "approver" : "user");
    } else {
      name = "open mode";
      role = "";
    }
    $("#identity-name").textContent = name;
    $("#identity-role").textContent = role;
    $("#identity-role").classList.toggle("hidden", !role);
    // A sign-out only makes sense when authenticating with a token.
    $("#signout-btn").classList.toggle("hidden", !auth.token);
  }
  // Hide approvals entirely when the identity can't resolve them.
  $("#approvals-btn").classList.toggle("hidden", !canApprove());
  // Disable sandbox/fleet creation when the identity can launch nothing.
  const allowed = canLaunch();
  ["#create-btn", "#fleet-create-btn"].forEach((sel) => {
    const b = $(sel);
    if (b) {
      b.disabled = !allowed;
      if (!allowed) b.title = "Your role is not permitted to launch profiles";
    }
  });
}

// Start the live app exactly once, regardless of how many times boot runs
// (initial load, then again after an interactive login).
function startApp() {
  if (state.started) return;
  state.started = true;
  loadProfiles();
  startGlobalPoll();
}

async function loadWhoami() {
  const { data } = await api("GET", "/v1/whoami");
  auth.principal = data.principal || null;
  auth.rbac = !!data.rbac;
}

async function bootSession() {
  try {
    await loadWhoami();
    hideLogin();
    applyPrincipal();
    startApp();
  } catch (e) {
    if (e.status === 401) {
      showLogin();
      return;
    }
    // whoami unavailable (older server / no auth): fall back to least privilege.
    auth.principal = { name: "", admin: false, can_approve: false, can_launch: false };
    auth.rbac = false;
    hideLogin();
    applyPrincipal();
    startApp();
  }
}

function wireLogin() {
  auth.onRequired = () => { stopGlobalPoll(); state.started = false; showLogin(); };
  const form = $("#login-form");
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const err = $("#login-error");
      err.classList.add("hidden");
      setToken($("#login-token").value);
      try {
        await loadWhoami();
        hideLogin();
        applyPrincipal();
        startApp();
        toast("Signed in" + (auth.principal && auth.principal.name ? ` as ${auth.principal.name}` : ""), "success");
      } catch (ex) {
        setToken("");
        err.textContent = ex.status === 401
          ? "Invalid token. Please try again."
          : "Sign-in failed: " + ex.message;
        err.classList.remove("hidden");
      }
    });
  }
  const signout = $("#signout-btn");
  if (signout) {
    signout.addEventListener("click", () => {
      setToken("");
      location.reload();
    });
  }
}

function init() {
  wireEvents();
  wireLogin();
  bootSession();
}

document.addEventListener("DOMContentLoaded", init);
