// Zones: how each zone gets its DNS records and certificate.

import { h, replace } from "../dom.js";
import { get } from "../api.js";
import { badge, mono, pageHead, errorBox, empty, loading } from "../ui.js";

const MODES = {
  wildcard: "One wildcard record for the zone",
  "per-host": "One record per published host",
  off: "Records are not managed",
};

const STRATEGIES = {
  wildcard: "Wildcard certificate",
  "per-host": "One certificate per host",
  san: "One certificate with every host",
};

export function mount(root) {
  const body = h("div", { class: "page-body" });
  root.appendChild(pageHead("Zones", "The domains services are published under. These come from the config file."));
  root.appendChild(body);
  let alive = true;

  async function load() {
    let zones;
    try {
      zones = (await get("/zones")).zones || [];
    } catch (e) {
      if (alive) replace(body, errorBox(e));
      return;
    }
    if (!alive) return;
    if (!zones.length) return replace(body, empty("No zones configured", "Add a zone under zones: in the config file (Settings) so services get a hostname."));
    replace(body, h("ul", { class: "ledger", role: "list" }, zones.map((z) => h("li", { class: "ledger-row" },
      h("div", { class: "row-main" },
        h("div", { class: "row-title" },
          h("h3", { class: "row-name mono" }, z.name),
          z.default ? badge("Default", "info", "Traefik serves this zone's certificate when a request matches no other") : null),
        h("dl", { class: "facts facts-inline" },
          h("dt", null, "Points to"), h("dd", null, z.target_ip ? mono(z.target_ip) : h("span", { class: "muted" }, "not set")),
          h("dt", null, "DNS records"), h("dd", null, MODES[z.records_mode] || z.records_mode, z.records_provider ? [" at ", mono(z.records_provider)] : null),
          h("dt", null, "Certificate"), h("dd", null,
            z.issuer ? [STRATEGIES[z.cert_strategy] || z.cert_strategy || "Certificate", " from ", mono(z.issuer)] : h("span", { class: "muted" }, "No issuer, so no certificate is requested")),
          z.issuer ? [h("dt", null, "Challenge"), h("dd", null, (z.challenge || "dns-01").toUpperCase(), z.challenge_provider ? [" through ", mono(z.challenge_provider)] : null)] : null))))));
  }

  replace(body, loading("Loading zones…"));
  load();
  return { refresh: load, dispose: () => { alive = false; } };
}
