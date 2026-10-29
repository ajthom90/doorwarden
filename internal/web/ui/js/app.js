// Doorwarden's web UI: boot, sign-in, the shell (navigation, banners) and
// the fragment router (#/services ...). Views live in views/*.js and
// export mount(root, ctx) -> {refresh?, dispose?}.

import { h, replace, clear } from "./dom.js";
import { get, post, request, setCSRF, onUnauthorized } from "./api.js";
import * as events from "./events.js";
import { icon, button, errorText } from "./ui.js";
import { renderLogin, renderSetup } from "./views/auth.js";
import * as services from "./views/services.js";
import * as dns from "./views/dns.js";
import * as certs from "./views/certs.js";
import * as zones from "./views/zones.js";
import * as activity from "./views/activity.js";
import * as settings from "./views/settings.js";

const ROUTES = [
  { path: "services", label: "Services", view: services },
  { path: "dns", label: "DNS", view: dns },
  { path: "certificates", label: "Certificates", view: certs },
  { path: "zones", label: "Zones", view: zones },
  { path: "activity", label: "Activity", view: activity },
  { path: "settings", label: "Settings", view: settings },
];

const root = document.getElementById("app");
const app = { me: null, current: null, shell: null, banners: null, main: null, nav: null, live: null, refreshTimer: 0 };

// ---- theme (stored per browser; storage may be unavailable)

const THEME_KEY = "doorwarden.theme";

export function getTheme() {
  try {
    const t = window.localStorage.getItem(THEME_KEY);
    return t === "light" || t === "dark" ? t : "system";
  } catch (e) {
    return "system";
  }
}

export function setTheme(t) {
  try {
    if (t === "system") window.localStorage.removeItem(THEME_KEY);
    else window.localStorage.setItem(THEME_KEY, t);
  } catch (e) {
    // private mode or blocked storage: the choice lasts for this page only
  }
  if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  else document.documentElement.removeAttribute("data-theme");
  document.dispatchEvent(new CustomEvent("doorwarden:theme"));
}

function effectiveDark() {
  const t = document.documentElement.getAttribute("data-theme");
  if (t) return t === "dark";
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function themeToggle() {
  const btn = h("button", { type: "button", class: "icon-btn theme-toggle" });
  const paint = () => {
    const dark = effectiveDark();
    replace(btn, icon(dark ? "sun" : "moon"));
    btn.setAttribute("aria-label", dark ? "Use the light theme" : "Use the dark theme");
    btn.setAttribute("title", dark ? "Light theme" : "Dark theme");
  };
  btn.addEventListener("click", () => setTheme(effectiveDark() ? "light" : "dark"));
  document.addEventListener("doorwarden:theme", paint);
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", paint);
  paint();
  return btn;
}

// ---- boot and auth

async function boot() {
  root.classList.remove("boot");
  let status;
  try {
    status = await get("/auth/status");
  } catch (e) {
    return showFatal(e);
  }
  if (status.setup_required) return showSetup();
  if (!status.authenticated) return showLogin();
  try {
    const me = await get("/auth/me");
    return enter(me);
  } catch (e) {
    if (e.status === 401) return showLogin();
    return showFatal(e);
  }
}

function showFatal(err) {
  leave();
  replace(root, h("main", { class: "auth-wrap" },
    h("div", { class: "auth-card" },
      h("h1", null, "Doorwarden is not answering"),
      h("p", null, errorText(err)),
      button("Try again", { kind: "primary", on: { click: () => boot() } }))));
}

function showLogin(notice) {
  leave();
  renderLogin(root, { notice, onDone: (me) => enter(me) });
}

function showSetup() {
  leave();
  renderSetup(root, { onDone: (me) => enter(me, true) });
}

// leave tears the shell down (sign-out, expired session).
function leave() {
  events.stop();
  if (app.current && app.current.dispose) app.current.dispose();
  app.current = null;
  app.shell = null;
  app.me = null;
  setCSRF("");
}

onUnauthorized(() => {
  if (app.shell) showLogin("Your session ended. Sign in again to continue.");
});

export async function signOut() {
  try {
    await post("/auth/logout");
  } catch (e) {
    // the session may already be gone; the sign-in screen is right either way
  }
  showLogin("You are signed out.");
}

function enter(me, fresh) {
  setCSRF(me.csrf_token);
  app.me = { user: me.user, role: me.role, method: me.method || "session" };
  buildShell();
  if (fresh && !location.hash) location.hash = "#/services";
  route();
  events.start(async () => {
    const st = await get("/auth/status");
    if (!st.authenticated) {
      showLogin("Your session ended. Sign in again to continue.");
      return false;
    }
    return true;
  });
  refreshBanners();
}

// ---- shell

function navLink(r) {
  return h("a", { href: "#/" + r.path, class: "nav-link", data: { route: r.path } }, r.label);
}

function buildShell() {
  const menuBtn = h("button", { type: "button", class: "icon-btn menu-btn", "aria-label": "Menu", "aria-expanded": "false", "aria-controls": "nav" }, icon("menu"));
  const nav = h("nav", { id: "nav", class: "nav", "aria-label": "Main" }, h("ul", { role: "list" }, ROUTES.map((r) => h("li", null, navLink(r)))));
  const setOpen = (open) => {
    menuBtn.setAttribute("aria-expanded", String(open));
    nav.classList.toggle("nav-open", open);
    if (nav.parentNode) nav.parentNode.classList.toggle("rail-open", open);
  };
  menuBtn.addEventListener("click", () => setOpen(menuBtn.getAttribute("aria-expanded") !== "true"));
  nav.addEventListener("click", (e) => {
    if (e.target.closest("a")) setOpen(false);
  });
  const live = h("span", { class: "live", role: "status" });
  app.live = live;
  events.on("state", (st) => {
    live.dataset.state = st;
    live.textContent = st === "live" ? "Live" : st === "off" ? "" : "Reconnecting";
    live.setAttribute("title", st === "live" ? "Receiving live updates" : "Live updates paused; reconnecting");
  });
  const who = h("div", { class: "who" },
    h("span", { class: "who-name" }, app.me.user),
    h("span", { class: "who-role" }, app.me.role === "admin" ? "Administrator" : "Read-only"));
  const rail = h("div", { class: "rail" },
    h("div", { class: "rail-top" },
      h("a", { href: "#/services", class: "wordmark", "aria-label": "Doorwarden home" }, wordmarkGlyph(), h("span", null, "doorwarden")),
      menuBtn),
    nav,
    h("div", { class: "rail-foot" }, who, h("div", { class: "rail-tools" }, live, themeToggle())));
  app.banners = h("div", { class: "banners" });
  app.main = h("main", { id: "main", class: "main", tabindex: "-1" });
  app.nav = nav;
  app.shell = h("div", { class: "shell" },
    h("a", { href: "#main", class: "skip-link", on: { click: (e) => { e.preventDefault(); app.main.focus(); } } }, "Skip to content"),
    rail,
    h("div", { class: "content" }, app.banners, app.main));
  replace(root, app.shell);
}

function wordmarkGlyph() {
  const img = h("img", { src: "/favicon.svg", alt: "", width: "26", height: "26", class: "wordmark-glyph" });
  return img;
}

// ---- banners (every page): dry run and degraded sources

async function refreshBanners() {
  if (!app.banners) return;
  const [dry, health] = await Promise.all([
    get("/settings/dry-run").catch(() => null),
    request("GET", "/healthz").catch((e) => (e && e.body ? e.body : null)),
  ]);
  if (!app.banners) return;
  const out = [];
  if (dry && dry.enabled) {
    out.push(h("div", { class: "banner banner-dry", role: "status" },
      h("strong", null, "Dry run is on."),
      " Doorwarden plans changes and records them in Activity, but does not touch DNS, certificates or routes.",
      dry.forced_by_config ? " It is set in the config file." : h("a", { href: "#/settings" }, "Change in Settings")));
  }
  if (health) {
    const down = Object.keys(health.sources || {}).filter((k) => health.sources[k] === false).sort();
    if (health.status === "fail") {
      out.push(h("div", { class: "banner banner-danger", role: "alert" },
        h("strong", null, "The database is not usable."), " Doorwarden cannot record changes until it is. Check the server log."));
    }
    if (down.length) {
      out.push(h("div", { class: "banner banner-warn", role: "status" },
        h("strong", null, down.length === 1 ? "A source is unavailable." : "Some sources are unavailable."),
        " Doorwarden could not list ", down.map((d, i) => [i ? ", " : "", h("span", { class: "mono" }, d)]),
        " on the last cycle and is not removing anything it published from ", down.length === 1 ? "it." : "them."));
    } else if (health.degraded && health.last_result === "error") {
      out.push(h("div", { class: "banner banner-warn", role: "status" },
        h("strong", null, "The last cycle ended with an error."), " ", h("a", { href: "#/activity" }, "See Activity")));
    }
  }
  replace(app.banners, out);
}

export function bannersChanged() {
  refreshBanners();
}

// ---- router

function currentRoute() {
  const p = (location.hash || "").replace(/^#\/?/, "").split(/[/?]/)[0];
  return ROUTES.find((r) => r.path === p) || null;
}

function route() {
  if (!app.shell) return;
  const r = currentRoute();
  if (!r) {
    history.replaceState(null, "", "#/services");
    return route();
  }
  if (app.current && app.current.dispose) app.current.dispose();
  clear(app.main);
  app.nav.querySelectorAll("a").forEach((a) => {
    if (a.dataset.route === r.path) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  document.title = r.label + " | Doorwarden";
  const ctx = { me: app.me, canEdit: app.me.role === "admin", bannersChanged, signOut, getTheme, setTheme };
  app.current = r.view.mount(app.main, ctx) || null;
  const heading = app.main.querySelector(".page-title");
  if (heading && document.activeElement && document.activeElement.closest && document.activeElement.closest(".nav")) heading.focus();
}

window.addEventListener("hashchange", route);

// A finished cycle refreshes the banners and the page in view (debounced:
// several cycles in a burst cause one refresh).
events.on("cycle", () => {
  if (app.refreshTimer) clearTimeout(app.refreshTimer);
  app.refreshTimer = setTimeout(() => {
    app.refreshTimer = 0;
    refreshBanners();
    if (app.current && app.current.refresh) app.current.refresh();
  }, 400);
});

boot();
