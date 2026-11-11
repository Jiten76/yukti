/* Platinum — tiny shared helpers used by the Yukti dashboard.
   IIFE keeps the global namespace clean; everything hangs off `window.Platinum`. */
(function () {
  "use strict";

  const Platinum = {
    /** Short SHA (12 chars) for display. */
    shortSha(sha) {
      if (!sha) return "—";
      return String(sha).slice(0, 12);
    },

    /** Format an epoch-seconds timestamp as a wall-clock time string. */
    formatTime(epochSeconds) {
      if (!epochSeconds) return "—";
      const d = new Date(epochSeconds * 1000);
      return d.toLocaleTimeString();
    },

    /** Pretty-print a JSON-compatible value with stable key order. */
    formatJson(value, indent = 2) {
      try {
        return JSON.stringify(value, null, indent);
      } catch (_e) {
        return String(value);
      }
    },

    /** querySelector with throw-on-missing for required elements. */
    must(selector) {
      const el = document.querySelector(selector);
      if (!el) throw new Error(`required element not found: ${selector}`);
      return el;
    },

    /** Build an HTML element from a template literal — minimal helper. */
    el(html) {
      const t = document.createElement("template");
      t.innerHTML = html.trim();
      const node = t.content.firstChild;
      if (!(node instanceof HTMLElement)) {
        throw new Error("Platinum.el: template did not produce an HTMLElement");
      }
      return node;
    },

    /** Briefly toggle a CSS class to trigger an animation, then remove it. */
    pulse(el, className, ms = 600) {
      if (!el) return;
      el.classList.add(className);
      setTimeout(() => el.classList.remove(className), ms);
    },

    /** "2s ago" / "1m ago" / "3h ago" for epoch-seconds timestamps. */
    timeAgo(epochSeconds, nowSeconds = Date.now() / 1000) {
      if (!epochSeconds) return "—";
      const d = Math.max(0, nowSeconds - epochSeconds);
      if (d < 1) return "just now";
      if (d < 60) return `${Math.floor(d)}s ago`;
      if (d < 3600) return `${Math.floor(d / 60)}m ago`;
      if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
      return `${Math.floor(d / 86400)}d ago`;
    },

    /** Parse the SimplePredicatePolicyEngine rationale string
     *  "p1 -> allow; p2 -> gate; p3 -> deny" -> {policies: [{name, decision}], decisive: {name, decision}}.
     *  Decisive = the most-restrictive policy (matches the final decision precedence). */
    parseRationale(rationale, finalDecision) {
      if (!rationale || typeof rationale !== "string") return { policies: [], decisive: null };
      const policies = rationale.split(";").map(s => s.trim()).filter(Boolean).map(s => {
        const m = s.match(/^(\S+)\s*->\s*(\S+)$/);
        return m ? { name: m[1], decision: m[2] } : null;
      }).filter(Boolean);
      // Decisive: the first policy whose decision matches finalDecision.
      const decisive = policies.find(p => p.decision === finalDecision) || policies[0] || null;
      return { policies, decisive };
    },

    /** Bind a click handler with delegated dispatch on a container. */
    delegate(container, selector, handler) {
      container.addEventListener("click", (ev) => {
        const target = ev.target instanceof Element ? ev.target.closest(selector) : null;
        if (target && container.contains(target)) handler(target, ev);
      });
    },
  };

  window.Platinum = Platinum;
})();
