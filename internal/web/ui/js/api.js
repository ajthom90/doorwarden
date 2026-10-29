// JSON API client. Holds the CSRF token in memory only (it comes from
// /auth/me, login, setup and a password change) and turns every failure
// into an ApiError with a message that is safe and useful to show.

let csrf = "";
const unauthorized = new Set();

export function setCSRF(token) {
  csrf = typeof token === "string" ? token : "";
}

// onUnauthorized registers fn to run when a call answers 401 (the session
// ended): the app shows the sign-in screen.
export function onUnauthorized(fn) {
  unauthorized.add(fn);
}

export class ApiError extends Error {
  constructor(status, message, body, retryAfter) {
    super(message);
    this.status = status;
    this.body = body || null;
    this.retryAfter = retryAfter || 0;
  }
}

const FALLBACK = {
  0: "Doorwarden did not answer. Check that the server is running and reachable.",
  400: "The request was not accepted.",
  401: "Your session has ended. Sign in again.",
  403: "You do not have permission to do that.",
  404: "That item no longer exists. Reload to see the current state.",
  409: "Something changed in the meantime. Reload and try again.",
  413: "That is too large to send.",
  415: "The request was not accepted.",
  429: "Too many attempts. Wait a moment and try again.",
  500: "Something went wrong on the server. The details are in the server log.",
  503: "The server is busy. Try again shortly.",
};

function message(status, serverText) {
  // Server error texts are short fixed sentences written for operators;
  // 5xx details stay in the server log.
  if (serverText && status < 500) {
    const t = serverText.length > 400 ? serverText.slice(0, 400) + "…" : serverText;
    return t.charAt(0).toUpperCase() + t.slice(1);
  }
  if (status === 503 && serverText) return FALLBACK[503];
  return FALLBACK[status] || (status >= 500 ? FALLBACK[500] : FALLBACK[400]);
}

// paths where a 401 means "wrong credentials", not "session over"
const CREDENTIAL_PATHS = new Set(["/api/v1/auth/login", "/api/v1/auth/password", "/api/v1/auth/setup"]);

// request calls an absolute same-origin path.
export async function request(method, path, body) {
  const headers = { Accept: "application/json" };
  const opts = { method, headers, credentials: "same-origin", cache: "no-store" };
  if (method !== "GET" && method !== "HEAD") {
    if (csrf) headers["X-Doorwarden-CSRF"] = csrf;
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body === undefined ? {} : body);
  }
  let res;
  try {
    res = await fetch(path, opts);
  } catch (e) {
    throw new ApiError(0, FALLBACK[0]);
  }
  let data = null;
  if ((res.headers.get("Content-Type") || "").includes("application/json")) {
    try {
      data = await res.json();
    } catch (e) {
      data = null;
    }
  }
  if (res.ok) return data || {};
  const ra = parseInt(res.headers.get("Retry-After") || "", 10);
  const text = data && typeof data.error === "string" ? data.error : "";
  const err = new ApiError(res.status, message(res.status, text), data, Number.isFinite(ra) ? ra : 0);
  if (res.status === 401 && !CREDENTIAL_PATHS.has(path)) {
    unauthorized.forEach((fn) => fn());
  }
  throw err;
}

// api calls /api/v1<path>.
export function api(method, path, body) {
  return request(method, "/api/v1" + path, body);
}

export const get = (path) => api("GET", path);
export const post = (path, body) => api("POST", path, body);
export const put = (path, body) => api("PUT", path, body);

// seg encodes one path segment (service keys contain ':').
export function seg(v) {
  return encodeURIComponent(String(v));
}
