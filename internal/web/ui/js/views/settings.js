// Settings: global dry run, the config file, the password, appearance and
// signing out.

import { h, replace, clear } from "../dom.js";
import { get, post, put, setCSRF } from "../api.js";
import { pageHead, section, button, busy, toast, confirmDialog, errorBox, loading } from "../ui.js";

export function mount(root, ctx) {
  const body = h("div", { class: "page-body" });
  root.appendChild(pageHead("Settings", null));
  root.appendChild(body);
  let alive = true;
  const dry = h("div");
  const cfg = h("div");
  body.appendChild(section("Dry run", "In dry run doorwarden plans every change and logs it, but does not touch DNS, certificates or routes. Use it to see what doorwarden would do.", dry));
  if (ctx.me.role === "admin") {
    body.appendChild(section("Config file", "The YAML file doorwarden started with. Secrets are masked: leave a masked value as it is to keep it, or replace it to change it. Changes apply after a restart.", cfg));
  }
  if (ctx.me.method === "session") body.appendChild(section("Password", null, passwordForm()));
  body.appendChild(section("Appearance", null, appearance()));
  body.appendChild(section("Session", null, session()));

  // ---- dry run

  async function loadDry() {
    let r;
    try {
      r = await get("/settings/dry-run");
    } catch (e) {
      return alive && replace(dry, errorBox(e));
    }
    if (!alive) return;
    const on = !!r.enabled;
    const sw = h("button", { type: "button", role: "switch", class: "switch", "aria-checked": String(on), id: "dry-switch",
      disabled: !ctx.canEdit || r.forced_by_config },
      h("span", { class: "switch-track", "aria-hidden": "true" }, h("span", { class: "switch-thumb" })),
      h("span", { class: "switch-label" }, on ? "Dry run is on" : "Dry run is off"));
    sw.addEventListener("click", async () => {
      const next = sw.getAttribute("aria-checked") !== "true";
      if (!next) {
        const ok = await confirmDialog({
          title: "Turn dry run off?",
          message: ["Doorwarden applies its plan on the next cycle: it creates DNS records, requests certificates and writes routes. Check the last plan on the Services page first."],
          confirm: "Turn off and apply",
          danger: true,
        });
        if (!ok) return;
      }
      try {
        await post("/settings/dry-run", { enabled: next });
        toast(next ? "Dry run is on." : "Dry run is off. Doorwarden applies changes from the next cycle.", "ok");
        ctx.bannersChanged();
        loadDry();
      } catch (e) {
        toast(e.message, "danger");
      }
    });
    replace(dry, sw,
      r.forced_by_config ? h("p", { class: "hint" }, "Set by settings.dry_run in the config file, so it cannot be turned off here.") : null,
      !ctx.canEdit ? h("p", { class: "hint" }, "Read-only access: an administrator can change this.") : null);
  }

  // ---- config file

  async function loadConfig() {
    replace(cfg, loading("Loading the config file…"));
    let r;
    try {
      r = await get("/config");
    } catch (e) {
      return alive && replace(cfg, errorBox(e));
    }
    if (!alive) return;
    const ta = h("textarea", { class: "code-editor", spellcheck: "false", autocapitalize: "none", autocomplete: "off", rows: "22",
      "aria-label": "Config file (YAML)", wrap: "off" });
    ta.value = r.yaml || "";
    const original = ta.value;
    const out = h("div", { "aria-live": "polite" });
    const save = button("Save config", { kind: "primary" });
    const reset = button("Discard changes", { kind: "quiet", on: { click: () => { ta.value = original; clear(out); } } });
    save.addEventListener("click", async () => {
      clear(out);
      try {
        await busy(save, "Checking…", () => put("/config", { yaml: ta.value }));
        replace(out, h("p", { class: "result tone-ok", role: "status" }, "Saved. Restart doorwarden to apply the new config."));
      } catch (e) {
        // validation errors are plain text from the server, scrubbed of values
        out.appendChild(h("div", { class: "form-error", role: "alert" }, h("p", null, "The config was not saved."), h("pre", { class: "error-pre" }, e.message)));
      }
    });
    replace(cfg,
      h("p", { class: "hint" }, "Masked values read ", h("code", null, r.masked_placeholder || "<masked>"), ". Comments in the file are not kept."),
      ta, out, h("div", { class: "row-actions" }, reset, save));
  }

  // ---- password

  function passwordForm() {
    const cur = h("input", { type: "password", id: "pw-cur", autocomplete: "current-password", required: true });
    const nw = h("input", { type: "password", id: "pw-new", autocomplete: "new-password", required: true, minlength: "12", "aria-describedby": "pw-new-hint" });
    const again = h("input", { type: "password", id: "pw-again", autocomplete: "new-password", required: true });
    const out = h("div", { "aria-live": "polite" });
    const go = button("Change password", { kind: "primary", type: "submit" });
    return h("form", { class: "stack narrow", on: { submit: async (e) => {
      e.preventDefault();
      clear(out);
      if (nw.value.length < 12) return out.appendChild(errorBox({ message: "Use at least 12 characters." }));
      if (nw.value !== again.value) return out.appendChild(errorBox({ message: "The new passwords do not match." }));
      try {
        const r = await busy(go, "Changing…", () => post("/auth/password", { current: cur.value, new: nw.value }));
        setCSRF(r.csrf_token);
        cur.value = nw.value = again.value = "";
        replace(out, h("p", { class: "result tone-ok", role: "status" }, "Password changed. Every other session was signed out."));
      } catch (x) {
        cur.value = "";
        if (x.status === 409) {
          toast("The password changed elsewhere. Sign in again.", "warn");
          ctx.signOut();
          return;
        }
        out.appendChild(errorBox(x.status === 429 && x.retryAfter ? { message: "Too many attempts. Try again in " + x.retryAfter + " seconds." } : x));
      }
    } } },
      // lets password managers tie the new password to this account
      h("input", { type: "text", name: "username", autocomplete: "username", value: ctx.me.user, hidden: true, readonly: true, tabindex: "-1", "aria-hidden": "true" }),
      h("div", { class: "field" }, h("label", { for: "pw-cur", class: "field-label" }, "Current password"), cur),
      h("div", { class: "field" }, h("label", { for: "pw-new", class: "field-label" }, "New password"), nw, h("p", { id: "pw-new-hint", class: "hint" }, "At least 12 characters. Changing it signs out every other session.")),
      h("div", { class: "field" }, h("label", { for: "pw-again", class: "field-label" }, "Repeat the new password"), again),
      out,
      h("div", null, go));
  }

  // ---- appearance

  function appearance() {
    const cur = ctx.getTheme();
    const opts = [{ v: "system", label: "Match the system" }, { v: "light", label: "Light" }, { v: "dark", label: "Dark" }];
    const fs = h("fieldset", { class: "radios radios-inline" },
      h("legend", { class: "field-label" }, "Theme"),
      opts.map((o) => h("label", { class: "radio" }, h("input", { type: "radio", name: "theme", value: o.v, checked: o.v === cur }), h("span", null, o.label))));
    fs.addEventListener("change", (e) => ctx.setTheme(e.target.value));
    return h("div", null, fs, h("p", { class: "hint" }, "Saved in this browser only."));
  }

  // ---- session

  function session() {
    const how = ctx.me.method === "header" ? "through your sign-in proxy" : "with the local password";
    return h("div", { class: "session" },
      h("p", null, "Signed in as ", h("strong", null, ctx.me.user), " ", how, ", ", ctx.me.role === "admin" ? "with full access." : "with read-only access."),
      ctx.me.method === "session"
        ? button("Sign out", { on: { click: () => ctx.signOut() } })
        : h("p", { class: "hint" }, "Sign out at your sign-in proxy."));
  }

  replace(dry, loading());
  loadDry();
  if (ctx.me.role === "admin") loadConfig();
  return { refresh: loadDry, dispose: () => { alive = false; } };
}
