// Helpers for the extension's pages (popup, in-page menu, save bar).

export const t = (key, ...subs) => chrome.i18n.getMessage(key, subs.map(String)) || key;

/// Ask the background worker (which talks to VaultRust).
export function send(message) {
  return chrome.runtime.sendMessage(message).catch(() => ({ error: "no_reply" }));
}

export function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "html") e.innerHTML = v; // only for our own icons
    else if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v === true ? "" : v);
  }
  e.append(...children.flat().filter((c) => c !== null && c !== undefined && c !== false));
  return e;
}

// Small line icons (24×24, drawn with the current colour).
const PATHS = {
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M14 9l2 2"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
  open: '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
  dice: '<rect x="4" y="4" width="16" height="16" rx="3"/><circle cx="9" cy="9" r="1"/><circle cx="15" cy="15" r="1"/><circle cx="15" cy="9" r="1"/><circle cx="9" cy="15" r="1"/>',
  fill: '<path d="M5 12h11M12 7l5 5-5 5M20 5v14"/>',
  close: '<path d="M6 6l12 12M18 6L6 18"/>',
  check: '<path d="M5 12l5 5 9-10"/>',
};

export function icon(name) {
  return `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${PATHS[name]}</svg>`;
}

export function iconButton(name, title, onclick) {
  return el("button", { class: "icon-btn", title, "aria-label": title, html: icon(name), onclick });
}

// The colours of VaultRust's item tiles.
const TILES = ["#3f7d5c", "#4f6aa8", "#8a5a9e", "#a3583e", "#5f7f2e", "#2f7f86", "#9a6b1f", "#7a4f4f"];

export function tile(title) {
  const letter = (title.trim()[0] ?? "?").toUpperCase();
  let h = 0;
  for (const c of title) h = (h * 31 + c.codePointAt(0)) >>> 0;
  return el("span", { class: "tile", style: `background:${TILES[h % TILES.length]}` }, letter);
}

/// A login / item row: tile, title, username, then action buttons.
export function itemRow(item, { onclick, actions = [] } = {}) {
  const who = el(
    "span",
    { class: "who" },
    el("span", { class: "title" }, item.title),
    el("span", { class: "sub" }, item.username || item.site || t("noUsername")),
  );
  const main = onclick
    ? el("button", { class: "row-main", onclick, title: t("fillThis") }, tile(item.title), who)
    : el("div", { class: "row-main" }, tile(item.title), who);
  return el("div", { class: "row" }, main, el("span", { class: "actions" }, ...actions));
}

/// What to say for an error from VaultRust, as [title, text].
export function explain(error) {
  switch (error) {
    case "no_host":
      return [t("notSetUpTitle"), t("notSetUp")];
    case "not_running":
      return [t("notRunningTitle"), t("notRunning")];
    case "disabled":
      return [t("disabledTitle"), t("disabled")];
    case "unpaired":
      return [t("unpairedTitle"), t("unpaired")];
    case "locked":
      return [t("lockedTitle"), t("locked")];
    case "busy":
      return [t("busyTitle"), t("busy")];
    default:
      return [t("noReplyTitle"), t("noReply")];
  }
}
