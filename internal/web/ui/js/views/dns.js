// DNS: providers (credential test), the mass-repair breaker, records
// doorwarden did not create (adopt or ignore) and the records it owns.

import { h, replace, clear } from "../dom.js";
import { get, post, seg } from "../api.js";
import { badge, mono, pageHead, section, button, busy, toast, confirmDialog, errorBox, empty, loading, timeEl, fmtDate, icon } from "../ui.js";

export function mount(root, ctx) {
  const st = { providers: null, owned: null, conflicts: null, breakers: [], error: null };
  const body = h("div", { class: "page-body" });
  root.appendChild(pageHead("DNS", "The providers doorwarden manages records with, and every record it knows about.",
    button([icon("refresh"), h("span", null, "Reload")], { kind: "quiet", small: true, on: { click: () => load() } })));
  root.appendChild(body);
  let alive = true;
  // test results survive a refresh
  const results = {};

  async function load() {
    try {
      const [p, r, plan] = await Promise.all([get("/dns/providers"), get("/dns/records"), get("/plan")]);
      st.providers = p.providers || [];
      st.owned = r.owned || [];
      st.conflicts = r.conflicts || [];
      st.breakers = ((plan && plan.actions) || []).filter((a) => a.alert === "dns-mass-missing");
      st.error = null;
    } catch (e) {
      st.error = e;
    }
    if (alive) render();
  }

  function render() {
    if (st.error && !st.providers) return replace(body, errorBox(st.error));
    if (!st.providers) return replace(body, loading("Loading DNS…"));
    replace(body,
      st.error ? errorBox(st.error) : null,
      st.breakers.map(breaker),
      section("Providers", "Credentials are never shown here. Test checks that doorwarden can read the zone.", providers()),
      section("Records doorwarden did not create", "Doorwarden never changes or deletes a record it does not own. Adopt one to let doorwarden manage it, or ignore it.", conflicts()),
      section("Records doorwarden owns", "Created by doorwarden and removed by it when the service goes away.", owned()));
  }

  function breaker(a) {
    const zone = a.zone || a.host;
    const btn = ctx.canEdit ? button("Acknowledge and allow repair", { kind: "danger", on: { click: () => ack(btn, a.provider, zone) } }) : null;
    return h("div", { class: "alert alert-danger", role: "alert" },
      h("h2", { class: "alert-title" }, "Repairs paused for ", mono(zone), " at ", mono(a.provider)),
      h("p", null, a.reason || "Most of the records doorwarden owns in this zone are missing at the provider."),
      h("p", null, "When many owned records vanish at once, the usual cause is a change at the provider (a zone was reset, or the wrong account is configured), not a real need to recreate them. Doorwarden stopped recreating records for this zone so it does not fill the wrong account or fight a change you made."),
      h("p", null, "Check the zone at the provider. If the records should exist, acknowledge to let doorwarden recreate them on the next cycle."),
      btn ? h("div", { class: "row-actions" }, btn) : h("p", { class: "hint" }, "An administrator can acknowledge this."));
  }

  async function ack(btn, provider, zone) {
    const ok = await confirmDialog({
      title: "Allow repair of " + zone + "?",
      message: ["Doorwarden recreates every missing record it owns in " + zone + " at " + provider + " on the next cycle."],
      confirm: "Allow repair",
      danger: true,
      ack: "I checked the zone at the provider and the records should exist.",
    });
    if (!ok) return;
    try {
      await busy(btn, "Acknowledging…", () => post("/dns/repair/ack", { provider, zone }));
      toast("Repair allowed for " + zone + ".", "ok");
      ctx.bannersChanged();
      load();
    } catch (e) {
      toast(e.message, "danger");
    }
  }

  function providers() {
    if (!st.providers.length) return empty("No DNS providers configured", "Add one under providers: in the config file (Settings).");
    return h("ul", { class: "ledger", role: "list" }, st.providers.map((p) => {
      const out = h("div", { class: "test-result", "aria-live": "polite" });
      if (results[p.name]) out.appendChild(results[p.name]());
      const zones = [];
      if (p.record_zones.length) zones.push(h("p", null, h("span", { class: "row-k" }, "Records for "), p.record_zones.map((z, i) => [i ? ", " : "", mono(z)])));
      if (p.challenge_zones.length) zones.push(h("p", null, h("span", { class: "row-k" }, "Certificate challenges for "), p.challenge_zones.map((z, i) => [i ? ", " : "", mono(z)])));
      if (!zones.length) zones.push(h("p", { class: "muted" }, "Not used by any zone."));
      const test = p.testable && ctx.canEdit ? button("Test credentials", { small: true }) : null;
      if (test) test.addEventListener("click", () => runTest(test, p.name, out));
      return h("li", { class: "ledger-row" },
        h("div", { class: "row-main" },
          h("div", { class: "row-title" }, h("h3", { class: "row-name mono" }, p.name), badge(p.type, "source"), p.wildcard_a ? badge("Wildcard records", "", "This provider supports wildcard A records") : null),
          zones,
          out),
        h("div", { class: "row-actions" }, test || (p.testable ? null : h("span", { class: "hint" }, "Challenge only; tested when a certificate is issued."))));
    }));
  }

  async function runTest(btn, name, out) {
    clear(out);
    let make;
    try {
      const r = await busy(btn, "Testing…", () => post("/dns/providers/" + seg(name) + "/test"));
      make = r.ok
        ? () => h("p", { class: "result tone-ok" }, "Credentials work. Doorwarden can read the zone.")
        : () => h("p", { class: "result tone-danger" }, (r.error || "The test failed") + ".");
    } catch (e) {
      if (e.status === 429) {
        const wait = e.retryAfter || 10;
        make = () => h("p", { class: "result tone-warn" }, "Tested moments ago. Try again in " + wait + " seconds.");
        btn.disabled = true;
        setTimeout(() => { btn.disabled = false; }, wait * 1000);
      } else {
        make = () => h("p", { class: "result tone-danger" }, e.message);
      }
    }
    results[name] = make;
    replace(out, make());
  }

  function conflicts() {
    if (!st.conflicts.length) return empty("No foreign records in the way", "When a record doorwarden wants already exists at a provider, it shows up here.");
    return h("ul", { class: "ledger", role: "list" }, st.conflicts.map((c) => {
      const rec = c.record || {};
      const t = (rec.type || "").toUpperCase();
      const adoptable = c.owner && (t === "A" || t === "AAAA");
      const acts = [];
      if (ctx.canEdit) {
        if (adoptable) {
          const b = button("Adopt", { small: true, kind: "primary" });
          b.addEventListener("click", () => conflictAct(b, c, "adopt"));
          acts.push(b);
        }
        if (!c.skipped) {
          const b = button("Ignore", { small: true });
          b.addEventListener("click", () => conflictAct(b, c, "skip"));
          acts.push(b);
        }
      }
      return h("li", { class: ["ledger-row", c.skipped ? "row-muted" : "row-bad"] },
        h("div", { class: "row-main" },
          h("div", { class: "row-title" },
            h("h3", { class: "row-name mono" }, rec.name || c.host),
            badge("Foreign", "danger", "Doorwarden did not create this record"),
            c.skipped ? badge("Ignored") : null),
          h("p", null, mono(t + " " + (rec.value || ""))),
          h("p", { class: "muted" }, "At ", mono(c.provider), " in ", mono(c.zone), c.owner ? [", wanted by ", mono(c.owner)] : null),
          c.reason ? h("p", null, c.reason) : null,
          !adoptable && ctx.canEdit && !c.skipped ? h("p", { class: "hint" }, t && t !== "A" && t !== "AAAA" ? "Only A and AAAA records can be adopted. Remove this " + t + " record at the provider if doorwarden should manage the name." : "No service claims this name, so it cannot be adopted.") : null),
        acts.length ? h("div", { class: "row-actions" }, acts) : null);
    }));
  }

  async function conflictAct(btn, c, action) {
    const rec = c.record || {};
    if (action === "adopt") {
      const ok = await confirmDialog({
        title: "Adopt " + (rec.name || c.host) + "?",
        message: ["Doorwarden takes ownership of this " + (rec.type || "") + " record for " + c.owner + ". From then on it updates the record and deletes it when the service goes away."],
        confirm: "Adopt record",
      });
      if (!ok) return;
    }
    try {
      await busy(btn, action === "adopt" ? "Adopting…" : "Ignoring…", () => post("/dns/conflicts/" + seg(c.id) + "/" + action));
      toast(action === "adopt" ? "Record adopted." : "Record ignored. Doorwarden stops reporting it.", "ok");
      load();
    } catch (e) {
      if (e.status === 409) load();
      toast(e.message, "danger");
    }
  }

  function owned() {
    if (!st.owned.length) return empty("Doorwarden owns no records yet", "Records appear here once a published service needs one.");
    const rows = st.owned.slice().sort((a, b) => (a.zone + a.name).localeCompare(b.zone + b.name));
    return h("div", { class: "table-wrap" }, h("table", { class: "records" },
      h("caption", { class: "sr-only" }, "Records doorwarden owns"),
      h("thead", null, h("tr", null, ["Name", "Type", "Value", "Provider and zone", "Service", "Created"].map((t) => h("th", { scope: "col" }, t)))),
      h("tbody", null, rows.map((r) => h("tr", { class: r.removed_after ? "row-muted" : "" },
        h("td", { "data-label": "Name" }, mono(r.name), " ", badge("Owned", "ok")),
        h("td", { "data-label": "Type" }, mono(r.type)),
        h("td", { "data-label": "Value" }, mono(r.value)),
        h("td", { "data-label": "Provider" }, mono(r.provider + " / " + r.zone)),
        h("td", { "data-label": "Service" }, mono(r.owner)),
        h("td", { "data-label": "Created" }, timeEl(r.created_at), r.removed_after ? h("div", { class: "hint" }, "Removed after " + fmtDate(r.removed_after)) : null))))));
  }

  render();
  load();
  return { refresh: load, dispose: () => { alive = false; } };
}
