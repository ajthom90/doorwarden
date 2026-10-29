// The one live event stream (/api/v1/events) for the whole app. The server
// caps streams per user, so views subscribe here instead of opening their
// own. On any error the stream is closed and reopened with capped,
// jittered backoff; before reopening, check() can veto (the session ended).

const listeners = { cycle: new Set(), activity: new Set(), state: new Set() };
let es = null;
let timer = 0;
let delay = 1000;
let running = false;
let state = "off";
let check = async () => true;

function setState(v) {
  state = v;
  listeners.state.forEach((fn) => fn(v));
}

function parse(data) {
  try {
    const v = JSON.parse(data);
    return v && typeof v === "object" ? v : {};
  } catch (e) {
    return {};
  }
}

function open() {
  if (!running) return;
  es = new EventSource("/api/v1/events");
  es.addEventListener("open", () => {
    delay = 1000;
    setState("live");
  });
  es.addEventListener("cycle", (e) => listeners.cycle.forEach((fn) => fn(parse(e.data))));
  es.addEventListener("activity", (e) => listeners.activity.forEach((fn) => fn(parse(e.data))));
  es.addEventListener("error", () => {
    es.close();
    es = null;
    if (!running) return;
    setState("reconnecting");
    const wait = delay + Math.floor(Math.random() * 400);
    delay = Math.min(delay * 2, 30000);
    timer = setTimeout(async () => {
      timer = 0;
      let ok = false;
      try {
        ok = await check();
      } catch (x) {
        ok = true; // unreachable server: keep trying
      }
      if (ok) open();
      else stop();
    }, wait);
  });
}

// start opens the stream; checkFn() resolves false when it should stop.
export function start(checkFn) {
  if (running) return;
  if (checkFn) check = checkFn;
  running = true;
  delay = 1000;
  setState("connecting");
  open();
}

export function stop() {
  running = false;
  if (timer) clearTimeout(timer);
  timer = 0;
  if (es) es.close();
  es = null;
  setState("off");
}

// on subscribes to "cycle", "activity" or "state"; it returns the
// unsubscribe function.
export function on(name, fn) {
  listeners[name].add(fn);
  if (name === "state") fn(state);
  return () => listeners[name].delete(fn);
}
