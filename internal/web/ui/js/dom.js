// Tiny DOM builder. Everything the UI shows goes through here, and it only
// ever uses createElement, createTextNode, textContent and setAttribute, so
// server data (which is untrusted) can never become markup. The HTML
// parsing sinks are banned in this tree by a Go test (ui_test.go).

const SVG_NS = "http://www.w3.org/2000/svg";

// Attributes that could run code or bypass the CSP. Event handlers are
// attached with the `on` prop instead.
const BANNED = /^(on.*|style|srcdoc|formaction)$/i;
const URL_ATTRS = new Set(["href", "src", "action", "xlink:href"]);
const PROPS = new Set(["value", "checked", "disabled", "selected", "indeterminate"]);

// safeURL accepts in-app fragments, same-origin absolute paths and
// http(s) URLs only.
export function safeURL(v) {
  const s = String(v);
  if (s.startsWith("#") || (s.startsWith("/") && !s.startsWith("//"))) return true;
  try {
    const u = new URL(s);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch (e) {
    return false;
  }
}

function setProps(el, props) {
  if (!props) return;
  for (const k of Object.keys(props)) {
    const v = props[k];
    if (v === undefined || v === null || v === false) continue;
    if (k === "on") {
      for (const ev of Object.keys(v)) el.addEventListener(ev, v[ev]);
      continue;
    }
    if (k === "class") {
      const c = Array.isArray(v) ? v.filter(Boolean).join(" ") : String(v);
      if (c) el.setAttribute("class", c);
      continue;
    }
    if (k === "text") {
      el.textContent = String(v);
      continue;
    }
    if (k === "data") {
      for (const d of Object.keys(v)) {
        if (v[d] !== undefined && v[d] !== null) el.dataset[d] = String(v[d]);
      }
      continue;
    }
    if (k === "ref") {
      v(el);
      continue;
    }
    if (BANNED.test(k)) throw new Error("dom: attribute not allowed: " + k);
    if (URL_ATTRS.has(k) && !safeURL(v)) throw new Error("dom: unsafe URL");
    if (PROPS.has(k) && !(el instanceof SVGElement)) {
      el[k] = v;
      continue;
    }
    el.setAttribute(k, v === true ? "" : String(v));
  }
}

function addChildren(el, children) {
  for (const c of children) {
    if (c === undefined || c === null || c === false || c === true) continue;
    if (Array.isArray(c)) {
      addChildren(el, c);
    } else if (c instanceof Node) {
      el.appendChild(c);
    } else {
      el.appendChild(document.createTextNode(String(c)));
    }
  }
}

// h builds an HTML element: h("p", {class: "x"}, "text", child, [more]).
export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  setProps(el, props);
  addChildren(el, children);
  return el;
}

// s builds an SVG element.
export function s(tag, props, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  setProps(el, props);
  addChildren(el, children);
  return el;
}

// clear removes every child of el.
export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

// replace swaps el's children for the given ones.
export function replace(el, ...children) {
  clear(el);
  addChildren(el, children);
  return el;
}
