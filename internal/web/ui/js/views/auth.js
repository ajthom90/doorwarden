// Sign-in and the first-run setup wizard.

import { h, replace, clear } from "../dom.js";
import { post } from "../api.js";
import { button, busy, errorBox } from "../ui.js";

const MIN_PASSWORD = 12;

function field(id, label, input, hint) {
  input.id = id;
  if (hint) input.setAttribute("aria-describedby", id + "-hint");
  return h("div", { class: "field" },
    h("label", { for: id, class: "field-label" }, label),
    input,
    hint ? h("p", { id: id + "-hint", class: "hint" }, hint) : null);
}

function brand() {
  return h("div", { class: "auth-brand" },
    h("img", { src: "/favicon.svg", alt: "", width: "36", height: "36" }),
    h("span", null, "doorwarden"));
}

// countdown disables btn for sec seconds, showing the time left in out.
function countdown(btn, out, sec, verb) {
  let left = Math.max(1, sec);
  btn.disabled = true;
  const tick = () => {
    replace(out, h("p", { class: "form-error", role: "alert" },
      "Too many attempts. You can " + verb + " again in " + left + (left === 1 ? " second." : " seconds.")));
    if (left <= 0) {
      btn.disabled = false;
      clear(out);
      return;
    }
    left -= 1;
    setTimeout(tick, 1000);
  };
  tick();
}

export function renderLogin(root, { notice, onDone }) {
  const user = h("input", { type: "text", name: "username", autocomplete: "username", required: true, autocapitalize: "none", spellcheck: "false" });
  const pass = h("input", { type: "password", name: "password", autocomplete: "current-password", required: true });
  const out = h("div", { "aria-live": "polite" });
  const go = button("Sign in", { kind: "primary", type: "submit", class: "btn-block" });
  const form = h("form", { class: "stack", on: { submit: async (e) => {
    e.preventDefault();
    clear(out);
    try {
      const r = await busy(go, "Signing in…", () => post("/auth/login", { username: user.value.trim(), password: pass.value }));
      pass.value = "";
      onDone({ user: r.user, role: r.role, method: "session", csrf_token: r.csrf_token });
    } catch (err) {
      pass.value = "";
      if ((err.status === 429 || err.status === 503) && err.retryAfter) countdown(go, out, err.retryAfter, "sign in");
      else out.appendChild(errorBox(err));
      pass.focus();
    }
  } } },
    field("login-user", "User name", user),
    field("login-pass", "Password", pass),
    out,
    go);
  replace(root, h("main", { class: "auth-wrap" },
    h("div", { class: "auth-card" },
      brand(),
      h("h1", null, "Sign in"),
      notice ? h("p", { class: "notice", role: "status" }, notice) : null,
      form)));
  user.focus();
}

// renderSetup is the first-run wizard: the setup token from the server's
// start-up log, then the administrator account.
export function renderSetup(root, { onDone }) {
  const state = { token: "" };
  const card = h("div", { class: "auth-card auth-card-wide" });
  replace(root, h("main", { class: "auth-wrap" }, card));

  const steps = (n) => h("ol", { class: "steps", "aria-label": "Setup progress" },
    ["Setup token", "Administrator", "Done"].map((t, i) =>
      h("li", { class: i + 1 === n ? "step-current" : i + 1 < n ? "step-done" : "", "aria-current": i + 1 === n ? "step" : undefined }, t)));

  function tokenStep() {
    const tok = h("input", { type: "text", autocomplete: "off", spellcheck: "false", autocapitalize: "none", required: true, class: "mono", value: state.token });
    const next = button("Continue", { kind: "primary", type: "submit" });
    replace(card,
      brand(),
      steps(1),
      h("h1", null, "Set up doorwarden"),
      h("p", null, "No administrator exists yet. To prove you run this server, enter the one-time setup token it printed when it started."),
      h("div", { class: "callout" },
        h("p", null, "Find it in the container log, on the line that starts with:"),
        h("pre", { class: "logline" }, "no administrator yet: first-run setup token"),
        h("p", { class: "hint" }, "For example ", h("code", null, "docker logs doorwarden 2>&1 | grep setup_token"), ". The token changes on every restart until setup is done.")),
      h("form", { class: "stack", on: { submit: (e) => {
        e.preventDefault();
        state.token = tok.value.trim();
        if (state.token) accountStep();
      } } },
        field("setup-token", "Setup token", tok),
        next));
    tok.focus();
  }

  function accountStep() {
    const user = h("input", { type: "text", autocomplete: "username", required: true, value: "admin", autocapitalize: "none", spellcheck: "false" });
    const pass = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: String(MIN_PASSWORD) });
    const again = h("input", { type: "password", autocomplete: "new-password", required: true });
    const out = h("div", { "aria-live": "polite" });
    const go = button("Create administrator", { kind: "primary", type: "submit" });
    const back = button("Back", { kind: "quiet", on: { click: () => tokenStep() } });
    replace(card,
      brand(),
      steps(2),
      h("h1", null, "Create the administrator"),
      h("p", null, "This is the only local account. You can also sign in through a forward-auth proxy later (see web.trusted_header in the docs)."),
      h("form", { class: "stack", on: { submit: async (e) => {
        e.preventDefault();
        clear(out);
        if (pass.value.length < MIN_PASSWORD) {
          out.appendChild(errorBox({ message: "Use at least " + MIN_PASSWORD + " characters for the password." }));
          pass.focus();
          return;
        }
        if (pass.value !== again.value) {
          out.appendChild(errorBox({ message: "The two passwords do not match." }));
          again.focus();
          return;
        }
        try {
          const r = await busy(go, "Creating…", () => post("/auth/setup", { username: user.value.trim(), password: pass.value, token: state.token }));
          pass.value = again.value = "";
          doneStep(r);
        } catch (err) {
          if (err.status === 403) {
            state.token = "";
            out.appendChild(errorBox({ message: "The setup token was not accepted. Check the log for the current token (it changes on restart)." }));
            const fix = button("Enter the token again", { kind: "quiet", on: { click: () => tokenStep() } });
            out.appendChild(fix);
          } else if (err.status === 409) {
            out.appendChild(errorBox({ message: "Setup is already done. Reload the page to sign in." }));
          } else if ((err.status === 429 || err.status === 503) && err.retryAfter) {
            countdown(go, out, err.retryAfter, "try");
          } else {
            out.appendChild(errorBox(err));
          }
        }
      } } },
        field("setup-user", "User name", user, "Letters, digits and . _ - @"),
        field("setup-pass", "Password", pass, "At least " + MIN_PASSWORD + " characters. A passphrase of a few words works well."),
        field("setup-again", "Repeat the password", again),
        out,
        h("div", { class: "row-actions" }, back, go)));
    pass.focus();
  }

  function doneStep(r) {
    const go = button("Open doorwarden", { kind: "primary", on: { click: () => onDone({ user: r.user, role: r.role, method: "session", csrf_token: r.csrf_token }) } });
    replace(card,
      brand(),
      steps(3),
      h("h1", null, "You are signed in"),
      h("p", null, "Doorwarden starts safely: certificates come from the Let's Encrypt staging CA until you switch an issuer to production, and services from sources in approve mode wait for you on the Services page."),
      h("ul", { class: "next-list" },
        h("li", null, "Check ", h("strong", null, "Zones"), " and ", h("strong", null, "DNS"), " to confirm doorwarden sees your providers. The Test button checks the credentials."),
        h("li", null, "Approve the services you want to publish."),
        h("li", null, "When a staging certificate works, switch its issuer to production on ", h("strong", null, "Certificates"), ".")),
      go);
    go.focus();
  }

  tokenStep();
}
