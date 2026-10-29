// Activity: the log of what doorwarden and its operators did, live.

import { h, replace } from "../dom.js";
import { get } from "../api.js";
import * as events from "../events.js";
import { pageHead, errorBox, empty, loading, fmtTime, parseTime } from "../ui.js";

const MAX = 300;
const LEVELS = [
  { v: "", label: "All levels" },
  { v: "info", label: "Info" },
  { v: "warn", label: "Warnings" },
  { v: "error", label: "Errors" },
];

export function mount(root) {
  const st = { entries: null, error: null, level: "", q: "" };
  const status = h("p", { class: "live-note", role: "status" });
  const levelSel = h("select", { "aria-label": "Level", on: { change: (e) => { st.level = e.target.value; render(); } } },
    LEVELS.map((l) => h("option", { value: l.v }, l.label)));
  const search = h("input", { type: "search", class: "search-input", placeholder: "Filter messages", "aria-label": "Filter messages",
    on: { input: (e) => { st.q = e.target.value.trim().toLowerCase(); render(); } } });
  const body = h("div", { class: "page-body" });
  root.appendChild(pageHead("Activity", "Every change doorwarden makes, and who asked for it.", status));
  root.appendChild(h("div", { class: "toolbar" }, h("div", { class: "toolbar-right" }, h("label", { class: "search" }, search), levelSel)));
  root.appendChild(body);
  let alive = true;

  async function load() {
    try {
      const r = await get("/activity?limit=200");
      st.entries = r.activity || [];
      st.error = null;
    } catch (e) {
      st.error = e;
    }
    if (alive) render();
  }

  function level(e) {
    const l = String(e.level || "info").toLowerCase();
    return l === "warning" ? "warn" : l;
  }

  function render() {
    if (st.error && !st.entries) return replace(body, errorBox(st.error));
    if (!st.entries) return replace(body, loading("Loading activity…"));
    const shown = st.entries.filter((e) => (!st.level || level(e) === st.level) && (!st.q || String(e.message).toLowerCase().includes(st.q)));
    if (!shown.length) return replace(body, empty(st.entries.length ? "Nothing matches" : "No activity yet", st.entries.length ? "Clear the filter to see everything." : "Changes appear here as doorwarden makes them."));
    replace(body, h("ol", { class: "log", role: "list", "aria-label": "Activity" }, shown.map((e) => {
      const l = level(e);
      const d = parseTime(e.ts);
      return h("li", { class: "log-row log-" + l },
        d ? h("time", { class: "log-time mono", datetime: d.toISOString() }, fmtTime(d)) : h("span", { class: "log-time" }),
        h("span", { class: "log-level" }, l),
        h("span", { class: "log-kind" }, e.kind || ""),
        h("span", { class: "log-msg" }, String(e.message || "")));
    })));
  }

  const offActivity = events.on("activity", (v) => {
    if (!st.entries) return;
    st.entries.unshift({ ts: new Date().toISOString(), level: v.level || "info", kind: v.kind || "", message: typeof v.message === "string" ? v.message : "" });
    if (st.entries.length > MAX) st.entries.length = MAX;
    render();
  });
  const offCycle = events.on("cycle", () => load());
  const offState = events.on("state", (s) => {
    status.dataset.state = s;
    status.textContent = s === "live" ? "Updating live" : s === "off" ? "" : "Reconnecting to live updates…";
  });

  render();
  load();
  return {
    dispose: () => { alive = false; offActivity(); offCycle(); offState(); },
  };
}
