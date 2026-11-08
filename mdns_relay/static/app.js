"use strict";

// Service names and TXT values come from the network and are untrusted. All text
// reaches the page through el(), which uses textContent and never parses HTML.
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "on") {
      for (const [event, handler] of Object.entries(value)) node.addEventListener(event, handler);
    } else if (key in node) node[key] = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

const $ = (id) => document.getElementById(id);

const state = {
  services: [],
  rules: [],
  interfaces: [],
  pinned: false,
  activity: [],
  status: null,
  editingRuleId: null,
};

const PROTOCOL_LABELS = { mdns: "mDNS", ssdp: "SSDP" };

const DROP_REASONS = {
  no_rule: "No rule for this path",
  nothing_permitted: "Rule exists, but nothing in the packet matched",
  probe: "Name probe, never relayed",
  unicast: "Not sent to the multicast group",
  malformed: "Malformed packet",
  legacy_source_port: "Source port isn't 5353",
  bad_location: "Device URL isn't the sender's own address",
  search_limit: "Too many searches in progress",
  wrong_interface: "Reply arrived on the wrong interface",
  send_failed: "Couldn't send",
  internal_error: "Internal error",
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function api(path, options = {}) {
  const init = { ...options, headers: { ...(options.headers || {}) } };
  if (options.body !== undefined) {
    init.body = JSON.stringify(options.body);
    init.headers["Content-Type"] = "application/json";
  }
  const response = await fetch(path, init);
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    throw new HttpError(response.status, data.error || `Request failed (${response.status})`);
  }
  return data;
}

// Rows are rebuilt on live updates, so keep keyboard focus on the matching control.
function replaceBody(body, rows) {
  const focused = document.activeElement;
  const key = body.contains(focused) ? focused.dataset.focus : null;
  body.replaceChildren(...rows);
  if (key) body.querySelector(`[data-focus="${CSS.escape(key)}"]`)?.focus();
}

function formatAge(epochSeconds) {
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - epochSeconds));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  return `${Math.round(seconds / 3600)}h ago`;
}

function formatTime(epochSeconds) {
  return new Date(epochSeconds * 1000).toLocaleTimeString();
}

function plural(count, word) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

// --- Services ---

function renderServices() {
  const query = $("service-search").value.trim().toLowerCase();
  const filter = $("service-filter").value;
  const matches = state.services.filter((service) => {
    if (filter !== "all" && (service.relayed_to.length > 0) !== (filter === "relayed")) return false;
    if (!query) return true;
    return [service.instance, service.service_type, service.protocol, service.iface, service.host, ...service.addresses]
      .some((value) => value && value.toLowerCase().includes(query));
  });

  replaceBody($("services-body"), matches.map((service) => {
    const relayed = service.relayed_to.length
      ? service.relayed_to.map((name) => el("span", { class: "badge good" }, name))
      : [el("span", { class: "badge" }, "Not relayed")];
    return el("tr", {},
      el("td", { class: "instance" }, service.instance),
      el("td", {}, el("span", { class: "badge" }, PROTOCOL_LABELS[service.protocol])),
      el("td", { class: "mono" }, service.service_type),
      el("td", {}, el("span", { class: "badge" }, service.iface)),
      el("td", {},
        el("span", { class: "stack mono" }, service.host ?? "Host not yet known"),
        ...service.addresses.map((address) => el("span", { class: "stack mono muted" }, address))),
      el("td", {},
        el("span", { class: "stack" }, service.port !== null ? `Port ${service.port}` : "Port not yet known"),
        el("span", { class: "stack muted" }, `Seen ${formatAge(service.last_seen)}`),
        el("span", { class: "stack muted" }, service.families.join(", ")),
        service.txt.length ? el("span", { class: "stack txt" }, service.txt.join(" · ")) : null),
      el("td", {}, ...relayed),
      el("td", {},
        el("div", { class: "actions" },
          el("button", {
            type: "button",
            "data-focus": `create-${service.iface}-${service.name}`,
            on: { click: () => openRuleDialog({
              protocol: service.protocol,
              service_type: service.service_type,
              instance_pattern: "*",
              provider_iface: service.iface,
            }) },
          }, "Create rule"))),
    );
  }));

  const empty = $("services-empty");
  empty.hidden = matches.length > 0;
  if (state.services.length === 0) {
    empty.textContent = state.status?.browse
      ? "No services discovered yet. Discovery queries are being sent on active interfaces."
      : "No services discovered yet. Services will appear when devices announce themselves.";
  } else {
    empty.textContent = "No services match your search or filter.";
  }
}

// --- Rules ---

function ruleAccess(rule) {
  return el("span", {},
    el("span", { class: "badge" }, rule.provider_iface),
    el("span", { class: "muted" }, "visible to "),
    el("span", { class: "badge" }, rule.client_iface));
}

function renderRules() {
  replaceBody($("rules-body"), state.rules.map((rule) => el("tr", {},
    el("td", {},
      el("input", {
        type: "checkbox",
        checked: rule.enabled,
        "data-focus": `enable-${rule.id}`,
        "aria-label": `Enable rule for ${rule.service_type}`,
        on: { change: (event) => setRuleEnabled(rule, event.target) },
      })),
    el("td", {}, el("span", { class: "badge" }, PROTOCOL_LABELS[rule.protocol])),
    el("td", { class: "mono" }, rule.service_type === "*" ? "* (every service type)" : rule.service_type),
    el("td", { class: "mono" }, rule.instance_pattern),
    el("td", {},
      ruleAccess(rule),
      ...rule.problems.map((problem) => el("span", { class: "problem" }, `Inactive: ${problem}`))),
    el("td", {}, rule.note),
    el("td", {},
      el("div", { class: "actions" },
        el("button", { type: "button", "data-focus": `edit-${rule.id}`, on: { click: () => openRuleDialog(rule, rule.id) } }, "Edit"),
        el("button", { type: "button", class: "danger", "data-focus": `delete-${rule.id}`, on: { click: () => deleteRule(rule) } }, "Delete"))),
  )));
  $("rules-empty").hidden = state.rules.length > 0;
}

async function setRuleEnabled(rule, checkbox) {
  checkbox.disabled = true;
  try {
    await api(`/api/rules/${encodeURIComponent(rule.id)}`, {
      method: "PATCH",
      body: { enabled: checkbox.checked },
    });
  } catch (error) {
    checkbox.checked = !checkbox.checked;
    alert(error.message);
  }
  await refreshRules();
}

async function deleteRule(rule) {
  if (!confirm(`Delete the rule for ${rule.service_type} (${rule.provider_iface} to ${rule.client_iface})? Relaying under this rule stops immediately.`)) return;
  try {
    await api(`/api/rules/${encodeURIComponent(rule.id)}`, { method: "DELETE" });
  } catch (error) {
    alert(error.message);
  }
  await refreshRules();
}

function fillInterfaceSelect(select, selected) {
  const names = state.interfaces.filter((item) => item.eligible).map((item) => item.name);
  if (selected && !names.includes(selected)) names.push(selected);
  select.replaceChildren(
    el("option", { value: "" }, "Choose an interface"),
    ...names.map((name) => el("option", { value: name }, name)));
  select.value = selected || "";
}

function updateRuleHints() {
  const form = $("rule-form");
  const ssdp = form.elements.protocol.value === "ssdp";
  form.elements.service_type.placeholder = ssdp ? "urn:schemas-upnp-org:device:MediaServer:1" : "_airplay._tcp";
  $("rule-type-hint").textContent = ssdp
    ? "A search target such as upnp:rootdevice or a urn:, or * for everything."
    : "Use the exact type, or * for every service type.";
  $("rule-instance-hint").textContent = ssdp
    ? "A USN or pattern, such as uuid:1234* . Use * for all devices."
    : "A name or pattern, such as Living* . Use * for all instances.";
}

function openRuleDialog(values = {}, ruleId = null) {
  state.editingRuleId = ruleId;
  const form = $("rule-form");
  $("rule-dialog-title").textContent = ruleId ? "Edit rule" : "Add rule";
  form.elements.protocol.value = values.protocol || "mdns";
  updateRuleHints();
  form.elements.service_type.value = values.service_type || "";
  form.elements.instance_pattern.value = values.instance_pattern || "*";
  form.elements.note.value = values.note || "";
  fillInterfaceSelect(form.elements.provider_iface, values.provider_iface);
  fillInterfaceSelect(form.elements.client_iface, values.client_iface);
  $("rule-error").hidden = true;
  $("rule-dialog").showModal();
}

async function submitRule(event) {
  event.preventDefault();
  const form = event.target;
  const body = {
    protocol: form.elements.protocol.value,
    service_type: form.elements.service_type.value.trim(),
    instance_pattern: form.elements.instance_pattern.value.trim(),
    provider_iface: form.elements.provider_iface.value,
    client_iface: form.elements.client_iface.value,
    note: form.elements.note.value.trim(),
  };
  const save = $("rule-save");
  save.disabled = true;
  try {
    if (state.editingRuleId) {
      await api(`/api/rules/${encodeURIComponent(state.editingRuleId)}`, { method: "PATCH", body });
    } else {
      await api("/api/rules", { method: "POST", body });
    }
    $("rule-dialog").close();
    await Promise.all([refreshRules(), refreshServices()]);
  } catch (error) {
    const box = $("rule-error");
    box.textContent = error.message;
    box.hidden = false;
  } finally {
    save.disabled = false;
  }
}

// --- Interfaces ---

function renderInterfaces() {
  const browse = state.status?.browse
    ? "This app sends its own discovery queries on active interfaces so that the Services list fills in. Those queries stay on their own interface. Nothing else is sent without a rule."
    : "Discovery queries are off, so the Services list relies on devices announcing themselves.";
  const pinned = state.pinned ? " Interfaces are fixed by the --interface option, so they can't be changed here." : "";
  $("interfaces-hint").textContent = browse + pinned;

  replaceBody($("interfaces-body"), state.interfaces.map((item) => {
    const counters = item.counters || {};
    let reason = null;
    if (item.loopback) reason = "Loopback";
    else if (!item.up) reason = "Down";
    else if (!item.multicast) reason = "No multicast";
    return el("tr", {},
      el("td", {},
        el("input", {
          type: "checkbox",
          checked: item.active,
          disabled: state.pinned || !item.eligible,
          "data-focus": `iface-${item.name}`,
          "aria-label": `Use interface ${item.name}`,
          on: { change: (event) => setInterfaceEnabled(item, event.target) },
        })),
      el("td", { class: "nowrap" }, item.name, " ",
        reason ? el("span", { class: "badge" }, reason) : null),
      el("td", {},
        ...[...item.ipv4, ...item.ipv6].map((address) => el("span", { class: "stack mono" }, address))),
      el("td", { class: "num" }, counters.received || 0),
      el("td", { class: "num" }, counters.sent || 0),
      el("td", { class: "num" }, counters.dropped || 0),
    );
  }));
}

async function setInterfaceEnabled(item, checkbox) {
  checkbox.disabled = true;
  try {
    await api(`/api/interfaces/${encodeURIComponent(item.name)}`, {
      method: "PATCH",
      body: { enabled: checkbox.checked },
    });
  } catch (error) {
    alert(error.message);
  }
  await Promise.all([refreshInterfaces(), refreshRules(), refreshServices()]);
}

// --- Activity ---

function renderActivity() {
  const filter = $("activity-filter").value;
  const items = state.activity.filter((item) => filter === "all" || item.action === filter);
  replaceBody($("activity-body"), items.map((item) => {
    const relayed = item.action === "relayed";
    return el("tr", {},
      el("td", { class: "nowrap muted" }, formatTime(item.time)),
      el("td", {},
        el("span", { class: `badge ${relayed ? "good" : ""}` }, relayed ? "Relayed" : "Dropped"),
        relayed ? null : el("span", { class: "stack muted" }, DROP_REASONS[item.reason] || item.reason)),
      el("td", { class: "nowrap" },
        item.source, item.destination ? ` to ${item.destination}` : "",
        el("span", { class: "stack muted" }, `${item.family}, from ${item.source_address}`)),
      el("td", {}, `${PROTOCOL_LABELS[item.protocol]} ${item.kind ?? "unknown"}`),
      el("td", { class: "mono" }, item.summary),
    );
  }));
  $("activity-empty").hidden = items.length > 0;
}

// --- Data loading ---

function renderSummary() {
  if (!state.status) return;
  const { active_interfaces: active, service_count: services, rule_count: rules } = state.status;
  $("summary").textContent =
    `${plural(services, "service")} on ${plural(active.length, "active interface")}, ${plural(rules, "rule")}`;
}

async function refreshStatus() {
  state.status = await api("/api/status");
  renderSummary();
}
async function refreshServices() {
  state.services = (await api("/api/services")).services;
  renderServices();
}
async function refreshRules() {
  state.rules = (await api("/api/rules")).rules;
  renderRules();
}
async function refreshInterfaces() {
  const data = await api("/api/interfaces");
  state.interfaces = data.interfaces;
  state.pinned = data.pinned;
  renderInterfaces();
}
async function refreshActivity() {
  state.activity = (await api("/api/activity")).activity;
  renderActivity();
}

async function refreshAll() {
  await refreshStatus();
  await Promise.all([refreshServices(), refreshRules(), refreshInterfaces(), refreshActivity()]);
  renderInterfaces();
  renderServices();
}

let refreshing = false;
let refreshQueued = false;
let pointerDown = false;

async function scheduleRefresh() {
  // Replacing a row between press and release would lose the click.
  if (refreshing || pointerDown) {
    refreshQueued = true;
    return;
  }
  refreshing = true;
  try {
    await refreshAll();
  } catch (error) {
    console.warn("Refresh failed:", error.message);
  } finally {
    refreshing = false;
    if (refreshQueued) {
      refreshQueued = false;
      scheduleRefresh();
    }
  }
}

let events = null;

function connectEvents() {
  if (events) events.close();
  const connection = $("connection");
  events = new EventSource("/api/events");
  events.addEventListener("open", () => {
    connection.dataset.state = "live";
    connection.textContent = "Live";
  });
  events.addEventListener("update", scheduleRefresh);
  events.addEventListener("error", () => {
    connection.dataset.state = "lost";
    connection.textContent = "Reconnecting";
  });
}

// --- Sign-in ---

function showLogin() {
  const dialog = $("login-dialog");
  if (dialog.open) return;
  if (events) {
    events.close();
    events = null;
  }
  const connection = $("connection");
  connection.dataset.state = "lost";
  connection.textContent = "Signed out";
  dialog.showModal();
}

async function submitLogin(event) {
  event.preventDefault();
  const form = event.target;
  const box = $("login-error");
  box.hidden = true;
  try {
    await api("/api/login", { method: "POST", body: { token: form.elements.token.value } });
    form.reset();
    $("login-dialog").close();
    await start();
  } catch (error) {
    box.textContent = error.message;
    box.hidden = false;
  }
}

// --- Page setup ---

function setupTabs() {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const select = (tab, focus = false) => {
    for (const other of tabs) {
      const selected = other === tab;
      other.setAttribute("aria-selected", String(selected));
      other.tabIndex = selected ? 0 : -1;
      $(other.getAttribute("aria-controls")).hidden = !selected;
    }
    if (focus) tab.focus();
  };
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => select(tab));
    tab.addEventListener("keydown", (event) => {
      const step = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
      if (step) select(tabs[(index + step + tabs.length) % tabs.length], true);
    });
  });
  select(tabs[0]);
}

async function start() {
  try {
    await refreshAll();
    connectEvents();
  } catch (error) {
    if (error.status !== 401) {
      const connection = $("connection");
      connection.dataset.state = "lost";
      connection.textContent = "Can't reach server";
      setTimeout(start, 3000);
    }
  }
}

function pointerReleased() {
  pointerDown = false;
  if (refreshQueued) {
    refreshQueued = false;
    scheduleRefresh();
  }
}

setupTabs();
document.addEventListener("pointerdown", () => { pointerDown = true; });
document.addEventListener("pointerup", pointerReleased);
document.addEventListener("pointercancel", pointerReleased);
setInterval(scheduleRefresh, 15000);  // Keeps "Seen" ages current on a quiet network.
$("service-search").addEventListener("input", renderServices);
$("service-filter").addEventListener("change", renderServices);
$("activity-filter").addEventListener("change", renderActivity);
$("add-rule").addEventListener("click", () => openRuleDialog());
$("rule-form").addEventListener("submit", submitRule);
$("rule-protocol").addEventListener("change", updateRuleHints);
$("rule-cancel").addEventListener("click", () => $("rule-dialog").close());
$("login-form").addEventListener("submit", submitLogin);
$("login-dialog").addEventListener("cancel", (event) => event.preventDefault());
start();
