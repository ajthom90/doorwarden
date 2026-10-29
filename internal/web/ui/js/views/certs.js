// Certificates: status, expiry, staging or production, renew now, and the
// switch of an issuer from staging to production.

import { h, replace } from "../dom.js";
import { get, post, seg } from "../api.js";
import { badge, mono, pageHead, section, button, busy, toast, confirmDialog, errorBox, empty, loading, fmtDate, parseTime, icon } from "../ui.js";

const DAY = 86400000;

const STATUS = {
  valid: "issued by doorwarden",
  imported: "imported",
  failed: "never issued successfully",
  unwanted: "no longer needed by any zone",
};

function expiry(c) {
  const d = parseTime(c.not_after);
  if (!d) return { text: "Not issued yet", tone: "muted" };
  const days = Math.floor((d.getTime() - Date.now()) / DAY);
  if (days < 0) return { text: "Expired on " + fmtDate(d), tone: "danger" };
  if (days === 0) return { text: "Expires today", tone: "danger" };
  const text = "Expires in " + days + (days === 1 ? " day" : " days") + ", " + fmtDate(d);
  return { text, tone: days < 7 ? "danger" : days < 14 ? "warn" : "ok" };
}

export function mount(root, ctx) {
  const st = { certs: null, error: null };
  const body = h("div", { class: "page-body" });
  root.appendChild(pageHead("Certificates", "Doorwarden issues and renews these itself; Traefik only serves them.",
    button([icon("refresh"), h("span", null, "Reload")], { kind: "quiet", small: true, on: { click: () => load() } })));
  root.appendChild(body);
  let alive = true;

  async function load() {
    try {
      const r = await get("/certs");
      st.certs = r.certs || [];
      st.error = null;
    } catch (e) {
      st.error = e;
    }
    if (alive) render();
  }

  function render() {
    if (st.error && !st.certs) return replace(body, errorBox(st.error));
    if (!st.certs) return replace(body, loading("Loading certificates…"));
    const staging = {};
    st.certs.filter((c) => c.staging && c.managed && c.issuer).forEach((c) => { (staging[c.issuer] = staging[c.issuer] || []).push(c); });
    replace(body,
      st.error ? errorBox(st.error) : null,
      Object.keys(staging).sort().map((iss) => stagingNotice(iss, staging[iss])),
      section("All certificates", null, list()));
  }

  function stagingNotice(issuer, certs) {
    const btn = ctx.canEdit ? button("Switch to production…", { kind: "primary" }) : null;
    if (btn) btn.addEventListener("click", () => switchProd(btn, issuer, certs));
    return h("div", { class: "alert alert-staging" },
      h("h2", { class: "alert-title" }, "Issuer ", mono(issuer), " uses the Let's Encrypt staging CA"),
      h("p", null, "Browsers do not trust staging certificates, which is the point: you can check that issuing works without using up production rate limits. ",
        certs.length === 1 ? "1 certificate comes from it." : certs.length + " certificates come from it."),
      btn ? h("div", { class: "row-actions" }, btn) : null);
  }

  async function switchProd(btn, issuer, certs) {
    const ok = await confirmDialog({
      title: "Switch " + issuer + " to production?",
      message: [
        "Doorwarden moves the issuer to the Let's Encrypt production CA and issues a new certificate for each of these from production:",
        h("ul", { class: "plain-list" }, certs.map((c) => h("li", null, mono((c.domains || []).join(", ") || c.id)))),
        "Production has rate limits (for example 5 duplicate certificates a week). Switch only once a staging certificate has been issued without errors.",
      ],
      confirm: "Switch to production",
      ack: "Re-issue every staging certificate of " + issuer + " from production.",
    });
    if (!ok) return;
    try {
      await busy(btn, "Starting…", () => post("/certs/switch-production", { issuer, confirm: true }));
      toast("Switch started. Progress appears in Activity.", "ok");
      setTimeout(load, 1500);
    } catch (e) {
      toast(e.message, "danger");
    }
  }

  function list() {
    if (!st.certs.length) return empty("No certificates yet", "Doorwarden requests one for each zone that has an issuer once a service in it is published.");
    const rows = st.certs.slice().sort((a, b) => (a.zone + a.id).localeCompare(b.zone + b.id));
    return h("ul", { class: "ledger", role: "list" }, rows.map((c) => {
      const ex = expiry(c);
      // without an issuer there is nothing to renew with (an imported cert in
      // a zone that has no issuer configured)
      const renew = ctx.canEdit && c.issuer ? button(c.renewing ? "Renewing…" : "Renew now", { small: true, disabled: c.renewing }) : null;
      if (renew) renew.addEventListener("click", () => renewNow(renew, c));
      const failed = c.last_result && !["ok", "imported"].includes(c.last_result);
      return h("li", { class: ["ledger-row", ex.tone === "danger" || c.last_error ? "row-bad" : ""] },
        h("div", { class: "row-main" },
          h("div", { class: "row-title" },
            h("h3", { class: "row-name mono" }, (c.domains || [])[0] || c.id),
            c.staging ? badge("Staging", "staging", "Issued by the Let's Encrypt staging CA; browsers do not trust it") : badge("Production", "ok"),
            c.managed ? null : badge("Imported", "", "Imported from files; renewed by doorwarden once its zone has an issuer")),
          (c.domains || []).length > 1 ? h("p", null, h("span", { class: "row-k" }, "Also "), (c.domains || []).slice(1).map((d, i) => [i ? ", " : "", mono(d)])) : null,
          h("p", { class: "tone-" + ex.tone + " expiry" }, ex.text),
          h("p", { class: "muted" }, "Zone ", mono(c.zone), c.issuer ? [", issuer ", mono(c.issuer)] : ", no issuer", c.status ? [", ", STATUS[c.status] || c.status] : null),
          failed || c.last_error ? h("p", { class: "issue tone-danger" }, h("strong", null, "Last attempt failed. "), c.last_error || c.last_result) : null),
        renew ? h("div", { class: "row-actions" }, renew)
          : ctx.canEdit && !c.issuer ? h("p", { class: "row-actions hint" }, "Give the zone an issuer to renew this.") : null);
    }));
  }

  async function renewNow(btn, c) {
    try {
      await busy(btn, "Starting…", () => post("/certs/" + seg(c.id) + "/renew"));
      toast("Renewal started. The result appears in Activity.", "ok");
      load();
    } catch (e) {
      toast(e.message, "danger");
    }
  }

  render();
  load();
  return { refresh: load, dispose: () => { alive = false; } };
}
