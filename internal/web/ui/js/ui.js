// Shared interface pieces: badges, the door glyph, dialogs, toasts and
// formatting. All built with dom.js.

import { h, s, clear } from "./dom.js";

// ---- formatting

export function plural(n, one, many) {
  return n + " " + (n === 1 ? one : many || one + "s");
}

export function parseTime(v) {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) || d.getUTCFullYear() < 1971 ? null : d;
}

export function relTime(v, now) {
  const d = parseTime(v);
  if (!d) return "never";
  const sec = Math.round(((now || Date.now()) - d.getTime()) / 1000);
  const abs = Math.abs(sec);
  const fmt = (n, unit) => (sec >= 0 ? plural(n, unit) + " ago" : "in " + plural(n, unit));
  if (abs < 45) return sec >= 0 ? "just now" : "in a moment";
  if (abs < 3600) return fmt(Math.round(abs / 60), "minute");
  if (abs < 86400) return fmt(Math.round(abs / 3600), "hour");
  return fmt(Math.round(abs / 86400), "day");
}

const dateFmt = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric" });
const timeFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });

export function fmtDate(v) {
  const d = parseTime(v);
  return d ? dateFmt.format(d) : "unknown";
}

export function fmtTime(v) {
  const d = parseTime(v);
  return d ? timeFmt.format(d) : "";
}

export function timeEl(v, text) {
  const d = parseTime(v);
  if (!d) return h("span", { class: "muted" }, text || "never");
  return h("time", { datetime: d.toISOString(), title: d.toLocaleString() }, text || relTime(d));
}

// backendText renders a model.Backend (keys are capitalized: no json tags).
export function backendText(b) {
  if (!b || !b.Host) return "no backend";
  return (b.Scheme || "http") + "://" + b.Host + (b.Port ? ":" + b.Port : "");
}

// ---- small pieces

export function badge(text, tone, title) {
  return h("span", { class: ["badge", tone ? "tone-" + tone : ""], title }, text);
}

export function mono(text, cls) {
  return h("span", { class: ["mono", cls] }, text);
}

// doorGlyph draws the service's state as a door: swung open (published),
// ajar (waiting), shut (not published), shut and barred (a problem).
export function doorGlyph(kind, label) {
  const frame = s("path", { d: "M3 17V2.5h12V17", class: "door-frame" });
  const panels = {
    open: "M3 2.5l5 1.6v13.4l-5-.5z",
    ajar: "M3 2.5l8 1v13.5l-8-.5z",
    shut: "M3.6 3h10.8v14H3.6z",
    barred: "M3.6 3h10.8v14H3.6z",
  };
  const panel = s("path", { d: panels[kind] || panels.shut, class: "door-panel" });
  const parts = [frame, panel];
  if (kind === "barred") parts.push(s("path", { d: "M1.5 10h15", class: "door-bar" }));
  else parts.push(s("circle", { cx: kind === "open" ? 6.6 : kind === "ajar" ? 9.2 : 12, cy: 10.5, r: 0.9, class: "door-knob" }));
  return s("svg", { viewBox: "0 0 18 19", class: "door door-" + kind, role: "img", "aria-label": label, focusable: "false" },
    s("title", null, label), ...parts);
}

export function icon(name) {
  const paths = {
    menu: "M3 5h14M3 10h14M3 15h14",
    close: "M5 5l10 10M15 5L5 15",
    sun: "M10 3v1.5M10 15.5V17M3 10h1.5M15.5 10H17M5 5l1 1M14 14l1 1M5 15l1-1M14 6l1-1M10 7a3 3 0 1 0 0 6a3 3 0 1 0 0-6z",
    moon: "M15.5 12.5A6 6 0 0 1 7.5 4.5a6 6 0 1 0 8 8z",
    search: "M8.5 3a5.5 5.5 0 1 0 0 11a5.5 5.5 0 1 0 0-11zM12.5 12.5L17 17",
    refresh: "M16 10a6 6 0 1 1-1.8-4.3M16 3.5v3.2h-3.2",
  };
  return s("svg", { viewBox: "0 0 20 20", class: "icon", "aria-hidden": "true", focusable: "false" },
    s("path", { d: paths[name] || "" }));
}

export function errorText(err) {
  return err && err.message ? err.message : "Something went wrong.";
}

export function errorBox(err) {
  return h("p", { class: "form-error", role: "alert" }, errorText(err));
}

export function empty(title, detail) {
  return h("div", { class: "empty" }, h("p", { class: "empty-title" }, title), detail ? h("p", { class: "muted" }, detail) : null);
}

export function loading(label) {
  return h("p", { class: "loading", role: "status" }, label || "Loading…");
}

export function section(title, intro, ...body) {
  const id = "s-" + title.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return h("section", { class: "section", "aria-labelledby": id },
    h("div", { class: "section-head" }, h("h2", { id }, title), intro ? h("p", { class: "muted" }, intro) : null),
    ...body);
}

export function pageHead(title, intro, ...extra) {
  return h("header", { class: "page-head" },
    h("div", null, h("h1", { tabindex: "-1", class: "page-title" }, title), intro ? h("p", { class: "lede" }, intro) : null),
    extra.length ? h("div", { class: "page-tools" }, ...extra) : null);
}

export function button(label, props) {
  const p = Object.assign({ type: "button" }, props || {});
  const cls = ["btn", p.kind ? "btn-" + p.kind : "", p.small ? "btn-small" : "", p.class];
  delete p.kind;
  delete p.small;
  p.class = cls;
  return h("button", p, label);
}

// busy disables btn while promise runs and shows a working label.
export async function busy(btn, label, fn) {
  const old = btn.textContent;
  btn.disabled = true;
  btn.setAttribute("aria-busy", "true");
  if (label) btn.textContent = label;
  try {
    return await fn();
  } finally {
    btn.disabled = false;
    btn.removeAttribute("aria-busy");
    btn.textContent = old;
  }
}

// ---- toasts

export function toast(text, tone) {
  const host = document.getElementById("toasts");
  if (!host) return;
  const t = h("div", { class: ["toast", tone ? "tone-" + tone : ""] }, text);
  host.appendChild(t);
  setTimeout(() => t.classList.add("toast-out"), 4600);
  setTimeout(() => t.remove(), 5000);
}

// ---- dialogs

const FOCUSABLE = "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";

// modal opens an accessible dialog (native <dialog>, modal, Escape closes)
// and keeps Tab inside it. body is a Node or a function (close) => Node;
// actions are built by the caller inside body. It resolves with the value
// passed to close(), or null when dismissed. Focus returns to the opener.
export function modal(title, body, opts) {
  const o = opts || {};
  const opener = document.activeElement;
  return new Promise((resolve) => {
    const titleId = "dlg-" + Math.random().toString(36).slice(2);
    let done = false;
    const dlg = h("dialog", { class: ["dialog", o.wide ? "dialog-wide" : "", o.tone ? "dialog-" + o.tone : ""], "aria-labelledby": titleId });
    const close = (v) => {
      if (done) return;
      done = true;
      dlg.close();
      dlg.remove();
      if (opener && typeof opener.focus === "function" && document.contains(opener)) opener.focus();
      resolve(v === undefined ? null : v);
    };
    const content = h("div", { class: "dialog-body" });
    let mounted = false;
    const focusInitial = () => {
      const auto = content.querySelector("[data-autofocus]") || content.querySelector(FOCUSABLE);
      if (auto) auto.focus();
    };
    const render = (node) => {
      clear(content);
      content.appendChild(typeof node === "function" ? node(close, render) : node);
      // a re-render replaced whatever had focus: put it back inside
      if (mounted) focusInitial();
    };
    dlg.appendChild(h("div", { class: "dialog-head" },
      h("h2", { id: titleId }, title),
      h("button", { type: "button", class: "icon-btn", "aria-label": "Close", on: { click: () => close(null) } }, icon("close"))));
    dlg.appendChild(content);
    render(body);
    dlg.addEventListener("cancel", (e) => {
      e.preventDefault();
      close(null);
    });
    dlg.addEventListener("keydown", (e) => {
      if (e.key !== "Tab") return;
      const f = Array.from(dlg.querySelectorAll(FOCUSABLE)).filter((x) => x.offsetParent !== null);
      if (!f.length) return;
      const first = f[0];
      const last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    });
    document.body.appendChild(dlg);
    dlg.showModal();
    mounted = true;
    focusInitial();
  });
}

export function actions(...btns) {
  return h("div", { class: "dialog-actions" }, ...btns);
}

// confirmDialog asks a yes/no question. With ack, a checkbox with that
// text must be ticked before the confirm button works.
export function confirmDialog({ title, message, confirm, danger, ack, detail }) {
  return modal(title, (close) => {
    const go = button(confirm || "Confirm", { kind: danger ? "danger" : "primary", disabled: !!ack, on: { click: () => close(true) } });
    const box = ack
      ? h("label", { class: "check" },
          h("input", { type: "checkbox", "data-autofocus": "", on: { change: (e) => { go.disabled = !e.target.checked; } } }),
          h("span", null, ack))
      : null;
    return h("div", null,
      ...(Array.isArray(message) ? message : [message]).map((m) => (m instanceof Node ? m : h("p", null, m))),
      detail || null,
      box,
      actions(button("Cancel", { kind: "quiet", "data-autofocus": ack ? undefined : "", on: { click: () => close(false) } }), go));
  }, { tone: danger ? "danger" : "" }).then((v) => v === true);
}

// promptDialog asks for one value; submit(value) may throw an ApiError
// whose message is shown in the dialog. Resolves with submit's result.
export function promptDialog({ title, label, hint, value, type, confirm, submit, inputProps }) {
  return modal(title, (close) => {
    const err = h("div", { "aria-live": "polite" });
    const id = "f-" + Math.random().toString(36).slice(2);
    const input = h("input", Object.assign({ id, type: type || "text", value: value == null ? "" : String(value), "data-autofocus": "",
      autocomplete: "off", spellcheck: "false", "aria-describedby": id + "-hint" }, inputProps || {}));
    const ok = button(confirm || "Save", { kind: "primary", type: "submit" });
    const form = h("form", { class: "stack", on: { submit: async (e) => {
      e.preventDefault();
      clear(err);
      try {
        const r = await busy(ok, "Saving…", () => submit(input.value));
        close(r === undefined ? true : r);
      } catch (x) {
        err.appendChild(errorBox(x));
        input.focus();
      }
    } } },
      h("label", { for: id, class: "field-label" }, label),
      input,
      hint ? h("p", { id: id + "-hint", class: "hint" }, hint) : null,
      err,
      actions(button("Cancel", { kind: "quiet", on: { click: () => close(null) } }), ok));
    return form;
  });
}

// fingerprint renders a fingerprint in groups of four for reading aloud.
export function fingerprint(fp) {
  const groups = String(fp || "").match(/.{1,4}/g) || [];
  return h("code", { class: "fingerprint", "aria-label": "fingerprint " + groups.join(" ") }, groups.join(" "));
}
