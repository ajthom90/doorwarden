// Services: everything the sources found, its state, and the operator's
// overrides (approve, publish/unpublish, rename, port, TLS verification).

import { h, replace, clear } from "../dom.js";
import { get, post, seg } from "../api.js";
import {
  badge, mono, doorGlyph, pageHead, section, button, busy, toast, modal, actions, confirmDialog, promptDialog,
  errorBox, empty, loading, backendText, fingerprint, timeEl, plural, icon,
} from "../ui.js";

const STATES = {
  published: { label: "Published", door: "open", tone: "ok" },
  pending: { label: "Waiting for approval", door: "ajar", tone: "warn" },
  discovered: { label: "Discovered", door: "ajar", tone: "" },
  skipped: { label: "Not published", door: "shut", tone: "" },
  off: { label: "Ignored", door: "shut", tone: "" },
  stopped: { label: "Stopped", door: "shut", tone: "" },
  removed: { label: "Being removed", door: "shut", tone: "" },
  conflict: { label: "Conflict", door: "barred", tone: "danger" },
  error: { label: "Error", door: "barred", tone: "danger" },
};

const ISSUE = {
  Conflict: { label: "Conflict", tone: "danger" },
  Invalid: { label: "Invalid", tone: "danger" },
  Skip: { label: "Skipped", tone: "warn" },
};

const FILTERS = [
  { id: "all", label: "All" },
  { id: "attention", label: "Need attention" },
  { id: "pending", label: "Waiting" },
  { id: "published", label: "Published" },
  { id: "unpublished", label: "Not published" },
];

function stateOf(svc) {
  return STATES[svc.state] || { label: svc.state || "Unknown", door: "shut", tone: "" };
}

function problems(svc) {
  return (svc.issues || []).filter((i) => i.kind === "Conflict" || i.kind === "Invalid");
}

function needsAttention(svc) {
  return problems(svc).length > 0 || svc.state === "conflict" || svc.state === "error";
}

function matches(svc, filter, q, source) {
  if (source && svc.source !== source) return false;
  if (filter === "attention" && !needsAttention(svc)) return false;
  if (filter === "pending" && svc.state !== "pending") return false;
  if (filter === "published" && svc.state !== "published") return false;
  if (filter === "unpublished" && ["published", "pending"].includes(svc.state)) return false;
  if (q) {
    const hay = [svc.name, svc.hostname, svc.key, svc.source, backendText(svc.backend)].join(" ").toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

export function mount(root, ctx) {
  const st = { services: null, plan: null, error: null, filter: "all", q: "", source: "" };
  const body = h("div", { class: "page-body" });
  const refreshBtn = button([icon("refresh"), h("span", null, "Reload")], { kind: "quiet", small: true, on: { click: () => load() } });
  root.appendChild(pageHead("Services", "Everything doorwarden found, and what it publishes.", refreshBtn));
  root.appendChild(body);
  let alive = true;
  let toolbar = null;
  const list = h("div", { class: "ledger-host" });

  async function load() {
    try {
      const [s, p] = await Promise.all([get("/services"), get("/plan")]);
      st.services = Array.isArray(s.services) ? s.services : [];
      st.plan = p;
      st.error = null;
    } catch (e) {
      st.error = e;
    }
    if (alive) render();
  }

  function render() {
    if (st.error && !st.services) return replace(body, errorBox(st.error));
    if (!st.services) return replace(body, loading("Loading services…"));
    const svcs = st.services.slice().sort((a, b) => (a.name || a.key).localeCompare(b.name || b.key));
    const out = [];
    if (st.error) out.push(errorBox(st.error));
    const bad = svcs.filter(needsAttention);
    if (bad.length) out.push(attentionBanner(bad));
    if (!toolbar) toolbar = buildToolbar();
    updateToolbar(svcs);
    out.push(toolbar);
    renderList(svcs);
    out.push(list);
    out.push(planPanel(st.plan));
    replace(body, out);
  }

  function attentionBanner(bad) {
    return h("div", { class: "alert alert-danger", role: "alert" },
      h("h2", { class: "alert-title" }, bad.length === 1 ? "1 service cannot be published as it is" : bad.length + " services cannot be published as they are"),
      h("ul", { class: "alert-list" }, bad.map((svc) => {
        const p = problems(svc)[0];
        return h("li", null, h("strong", null, svc.name || svc.key), ": ", p ? p.reason || p.kind : stateOf(svc).label);
      })),
      h("p", { class: "hint" }, "Each one is marked below with the reason. Fix the label or config at the source, or use the overrides here."));
  }

  let counts = {};
  let segBtns = [];
  let sourceSel = null;
  function buildToolbar() {
    const search = h("input", { type: "search", class: "search-input", placeholder: "Search name, host or backend", "aria-label": "Search services",
      on: { input: (e) => { st.q = e.target.value.trim().toLowerCase(); renderList(st.services); } } });
    sourceSel = h("select", { "aria-label": "Source", on: { change: (e) => { st.source = e.target.value; renderList(st.services); } } });
    segBtns = FILTERS.map((f) => h("button", { type: "button", class: "seg-btn", "aria-pressed": String(st.filter === f.id), data: { f: f.id },
      on: { click: () => { st.filter = f.id; segBtns.forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.f === f.id))); renderList(st.services); } } }));
    return h("div", { class: "toolbar" },
      h("div", { class: "seg", role: "group", "aria-label": "Show" }, segBtns),
      h("div", { class: "toolbar-right" },
        h("label", { class: "search" }, icon("search"), search),
        sourceSel));
  }

  function updateToolbar(svcs) {
    counts = { all: svcs.length, attention: 0, pending: 0, published: 0, unpublished: 0 };
    svcs.forEach((x) => FILTERS.forEach((f) => { if (f.id !== "all" && matches(x, f.id, "", "")) counts[f.id]++; }));
    segBtns.forEach((b) => {
      const f = FILTERS.find((x) => x.id === b.dataset.f);
      replace(b, f.label, h("span", { class: ["seg-count", f.id === "attention" && counts.attention ? "seg-count-bad" : ""] }, String(counts[f.id])));
    });
    const sources = Array.from(new Set(svcs.map((x) => x.source))).sort();
    const cur = st.source;
    replace(sourceSel, h("option", { value: "" }, "All sources"), sources.map((x) => h("option", { value: x, selected: x === cur }, x)));
    if (cur && !sources.includes(cur)) st.source = "";
  }

  function renderList(svcs) {
    const shown = svcs.filter((x) => matches(x, st.filter, st.q, st.source));
    if (!svcs.length) return replace(list, empty("No services yet", "Doorwarden lists containers and apps here as soon as a source reports them. Check Settings for the configured sources."));
    if (!shown.length) return replace(list, empty("Nothing matches", "Clear the search or pick another filter."));
    replace(list, h("ul", { class: "ledger", role: "list", "aria-label": "Services" }, shown.map(row)));
  }

  function row(svc) {
    const s = stateOf(svc);
    const ov = svc.overrides || {};
    const tags = [badge(svc.source, "source")];
    if (svc.websockets) tags.push(badge("WebSockets"));
    if (ov.rename) tags.push(badge("Renamed", "info", "Hostname label set here: " + ov.rename));
    if (ov.port) tags.push(badge("Port " + ov.port, "info", "Backend port set here"));
    if (ov.skip === true) tags.push(badge("Unpublished here", "info"));
    if (ov.skip === false) tags.push(badge("Published here", "info"));
    if (svc.backend && svc.backend.SkipVerify) tags.push(badge("TLS not verified", "warn", "Doorwarden does not check this backend's certificate"));
    (svc.middlewares || []).forEach((m) => tags.push(badge(m, "", "Middleware")));
    const issues = (svc.issues || []).map((i) => {
      const t = ISSUE[i.kind] || { label: i.kind, tone: "warn" };
      return h("li", { class: "issue tone-" + t.tone }, h("strong", null, t.label + ". "), i.reason || "No reason given.");
    });
    return h("li", { class: ["ledger-row", needsAttention(svc) ? "row-bad" : "", svc.state === "pending" ? "row-wait" : ""] },
      h("div", { class: "row-door" }, doorGlyph(s.door, s.label)),
      h("div", { class: "row-main" },
        h("div", { class: "row-title" },
          h("h3", { class: "row-name" }, svc.name || svc.key),
          h("span", { class: "state tone-" + (s.tone || "muted") }, s.label)),
        svc.hostname ? h("p", { class: "row-host" }, hostLink(svc)) : h("p", { class: "row-host muted" }, "No hostname"),
        h("p", { class: "row-backend" }, h("span", { class: "row-k" }, "to "), mono(backendText(svc.backend))),
        h("div", { class: "tags" }, tags),
        issues.length ? h("ul", { class: "issues", role: "list" }, issues) : null),
      ctx.canEdit ? h("div", { class: "row-actions" }, rowActions(svc)) : null);
  }

  function hostLink(svc) {
    const host = svc.hostname;
    if (svc.state === "published" && /^[a-z0-9.-]+$/i.test(host)) {
      return h("a", { href: "https://" + host + "/", class: "mono host-link", target: "_blank", rel: "noopener noreferrer" }, host);
    }
    return mono(host);
  }

  function rowActions(svc) {
    const ov = svc.overrides || {};
    const out = [];
    if (svc.state === "pending" && svc.fingerprint) {
      out.push(button("Review and approve", { kind: "primary", small: true, on: { click: () => approve(svc) } }));
    }
    if (ov.skip === true || svc.state === "skipped") {
      out.push(button(ov.skip === true ? "Publish" : "Publish anyway", { small: true, on: { click: (e) => publish(e.currentTarget, svc) } }));
    } else if (svc.state !== "off") {
      out.push(button("Unpublish", { small: true, on: { click: () => unpublish(svc) } }));
    }
    out.push(button("Rename", { small: true, kind: "quiet", on: { click: () => rename(svc) } }));
    out.push(button("Port", { small: true, kind: "quiet", on: { click: () => port(svc) } }));
    if (svc.backend && svc.backend.Scheme === "https") {
      out.push(button("TLS check", { small: true, kind: "quiet", on: { click: () => skipVerify(svc) } }));
    }
    return out;
  }

  // ---- actions

  async function act(path, body, done) {
    const r = await post("/services/" + seg(path.key) + "/" + path.action, body);
    if (done) toast(done, "ok");
    load();
    return r;
  }

  function approve(svc) {
    modal("Approve " + (svc.name || svc.key), (close, rerender) => approveBody(svc, null, close, rerender), { wide: true });
  }

  function approveBody(svc, before, close, rerender) {
    const out = h("div", { "aria-live": "polite" });
    const go = button(before ? "Approve the new version" : "Approve and publish", before ? { kind: "primary" } : { kind: "primary", "data-autofocus": "" });
    go.addEventListener("click", async () => {
      clear(out);
      try {
        await busy(go, "Approving…", () => post("/services/" + seg(svc.key) + "/approve", { fingerprint: svc.fingerprint }));
        close(true);
        toast((svc.name || svc.key) + " approved. It is published on the next cycle.", "ok");
        load();
      } catch (e) {
        if (e.status === 409 && e.body && e.body.service) {
          const fresh = e.body.service;
          if (fresh.fingerprint) rerender((c, r) => approveBody(fresh, svc, c, r));
          else out.appendChild(errorBox({ message: "This service changed and no longer waits for approval. Close this and check its state." }));
          load();
        } else {
          out.appendChild(errorBox(e));
        }
      }
    });
    return h("div", null,
      before
        ? h("div", { class: "alert alert-warn", role: "alert", tabindex: "-1", "data-autofocus": "" },
            h("p", { class: "alert-title" }, "This service changed while you were looking."),
            h("p", null, "Doorwarden approves exactly what you saw, so nothing was approved. Review what changed, then approve the new version or cancel."),
            diffTable(before, svc))
        : h("p", null, "Approving publishes this service exactly as shown. If anything about it changes later, doorwarden asks again."),
      h("dl", { class: "facts" },
        fact("Hostname", svc.hostname ? mono(svc.hostname) : h("span", { class: "muted" }, "none")),
        fact("Backend", mono(backendText(svc.backend))),
        fact("Source", svc.source + " (" + svc.key + ")"),
        fact("Middlewares", (svc.middlewares || []).length ? svc.middlewares.join(", ") : "none"),
        fact("WebSockets", svc.websockets ? "yes" : "no"),
        fact("Fingerprint", fingerprint(svc.fingerprint))),
      out,
      actions(button("Cancel", { kind: "quiet", on: { click: () => close(null) } }), go));
  }

  function fact(k, v) {
    return [h("dt", null, k), h("dd", null, v)];
  }

  function diffTable(a, b) {
    const fields = [
      ["Hostname", (x) => x.hostname || "none"],
      ["Backend", (x) => backendText(x.backend)],
      ["TLS verification", (x) => (x.backend && x.backend.SkipVerify ? "skipped" : "checked")],
      ["Middlewares", (x) => (x.middlewares || []).join(", ") || "none"],
      ["WebSockets", (x) => (x.websockets ? "yes" : "no")],
      ["State", (x) => stateOf(x).label],
      ["Fingerprint", (x) => x.fingerprint || "none"],
    ];
    const rows = fields.filter(([, f]) => f(a) !== f(b)).map(([k, f]) =>
      h("tr", null, h("th", { scope: "row" }, k), h("td", { "data-label": "You saw" }, h("del", { class: "mono" }, f(a))), h("td", { "data-label": "Now" }, h("ins", { class: "mono" }, f(b)))));
    return h("div", { class: "table-wrap" },
      h("table", { class: "diff" },
        h("caption", { class: "sr-only" }, "What changed"),
        h("thead", null, h("tr", null, h("th", { scope: "col" }, "Field"), h("th", { scope: "col" }, "You saw"), h("th", { scope: "col" }, "Now"))),
        h("tbody", null, rows)));
  }

  async function publish(btn, svc) {
    try {
      await busy(btn, "Publishing…", () => act({ key: svc.key, action: "publish" }, {}, (svc.name || svc.key) + " will be published on the next cycle."));
    } catch (e) {
      toast(e.message, "danger");
    }
  }

  async function unpublish(svc) {
    const ok = await confirmDialog({
      title: "Unpublish " + (svc.name || svc.key) + "?",
      message: ["Doorwarden stops routing " + (svc.hostname || "this service") + ". The route and its DNS record are removed after the grace period, so publishing it again before then is instant.",
        "The container or app itself keeps running."],
      confirm: "Unpublish",
      danger: true,
    });
    if (!ok) return;
    try {
      await act({ key: svc.key, action: "unpublish" }, {}, (svc.name || svc.key) + " unpublished.");
    } catch (e) {
      toast(e.message, "danger");
    }
  }

  function rename(svc) {
    const ov = svc.overrides || {};
    promptDialog({
      title: "Rename " + (svc.name || svc.key),
      label: "Hostname label",
      value: ov.rename || "",
      hint: "The first part of the hostname: lowercase letters, digits and hyphens. Leave it empty to use the discovered name. A renamed service is approved again before it is published.",
      confirm: "Save name",
      inputProps: { class: "mono", maxlength: "63", pattern: "[a-z0-9]([a-z0-9-]*[a-z0-9])?" },
      submit: (v) => act({ key: svc.key, action: "rename" }, { name: v.trim() }, v.trim() ? "Renamed to " + v.trim() + "." : "Rename cleared."),
    });
  }

  function port(svc) {
    const ov = svc.overrides || {};
    promptDialog({
      title: "Backend port for " + (svc.name || svc.key),
      label: "Port",
      type: "number",
      value: ov.port || "",
      hint: "Use this when the source reports the wrong port. Leave it empty to use the discovered port" + (svc.backend && svc.backend.Port ? " (now " + svc.backend.Port + ")." : "."),
      confirm: "Save port",
      inputProps: { min: "1", max: "65535", inputmode: "numeric", class: "mono input-short" },
      submit: (v) => {
        const n = v.trim() === "" ? 0 : Number(v);
        if (!Number.isInteger(n) || n < 0 || n > 65535) throw { message: "Enter a port from 1 to 65535, or leave it empty." };
        return act({ key: svc.key, action: "port" }, { port: n }, n ? "Port set to " + n + "." : "Port override cleared.");
      },
    });
  }

  function skipVerify(svc) {
    const cur = (svc.overrides || {}).skip_verify;
    modal("TLS check for " + (svc.name || svc.key), (close) => {
      const opts = [
        { v: "default", label: "Use the source's setting", hint: "Labels or config decide." },
        { v: "verify", label: "Always check the certificate", hint: "Recommended." },
        { v: "skip", label: "Do not check the certificate", hint: "For a backend with a self-signed certificate, such as many TrueNAS apps. Anyone who can intercept traffic between Traefik and the backend could read it." },
      ];
      const sel = cur === true ? "skip" : cur === false ? "verify" : "default";
      const out = h("div", { "aria-live": "polite" });
      const radios = opts.map((o) => h("label", { class: "radio" },
        h("input", { type: "radio", name: "sv", value: o.v, checked: o.v === sel, "data-autofocus": o.v === sel ? "" : undefined }),
        h("span", null, h("strong", null, o.label), h("span", { class: "hint" }, o.hint))));
      const ack = h("label", { class: "check check-warn", hidden: sel !== "skip" },
        h("input", { type: "checkbox", checked: sel === "skip" }), h("span", null, "I understand the backend's certificate will not be checked. This service is approved again first."));
      const save = button("Save", { kind: "primary" });
      const form = h("fieldset", { class: "radios", on: { change: () => { ack.hidden = value() !== "skip"; } } }, h("legend", { class: "sr-only" }, "TLS check"), radios);
      const value = () => (form.querySelector("input[name=sv]:checked") || {}).value;
      save.addEventListener("click", async () => {
        clear(out);
        const v = value();
        if (v === "skip" && !ack.querySelector("input").checked) {
          out.appendChild(errorBox({ message: "Tick the box to confirm skipping the check." }));
          return;
        }
        const body = { skip_verify: v === "skip" ? true : v === "verify" ? false : null };
        try {
          await busy(save, "Saving…", () => act({ key: svc.key, action: "skip-verify" }, body, "TLS check updated."));
          close(true);
        } catch (e) {
          out.appendChild(errorBox(e));
        }
      });
      return h("div", null, form, ack, out, actions(button("Cancel", { kind: "quiet", on: { click: () => close(null) } }), save));
    });
  }

  // ---- last plan

  function planPanel(p) {
    const acts = (p && p.actions) || [];
    const groups = {};
    acts.forEach((a) => { (groups[a.kind] = groups[a.kind] || []).push(a); });
    const summary = Object.keys(groups).sort().map((k) => k + " " + groups[k].length).join(", ");
    return section("Last plan", null,
      h("details", { class: "plan" },
        h("summary", null,
          p && p.at ? ["Planned ", timeEl(p.at), p.dry_run ? " in dry run" : "", ": ", acts.length ? plural(acts.length, "action") : "nothing to change"] : "No cycle has run yet",
          acts.length ? h("span", { class: "muted plan-sum" }, " (" + summary + ")") : null),
        acts.length
          ? h("div", { class: "table-wrap" }, h("table", { class: "plan-table" },
              h("thead", null, h("tr", null, ["Action", "Host or zone", "Detail"].map((t) => h("th", { scope: "col" }, t)))),
              h("tbody", null, acts.map((a) => h("tr", { class: ISSUE[a.kind] ? "plan-issue tone-" + ISSUE[a.kind].tone : "" },
                h("td", null, h("span", { class: "mono" }, a.kind)),
                h("td", null, mono(a.host || a.zone || a.key || "")),
                h("td", null, [a.record ? mono(a.record.type + " " + a.record.name + " " + a.record.value) : null, a.record && a.reason ? " " : null, a.reason || (a.provider ? "at " + a.provider : "")]))))))
          : h("p", { class: "muted" }, "The last cycle found nothing to do.")));
  }

  render();
  load();
  return {
    refresh: load,
    dispose: () => { alive = false; },
  };
}
