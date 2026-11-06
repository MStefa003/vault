import { ask, browserName, currentTab, fill, pairingCode, t } from "./vaultrust.js";

const main = document.getElementById("main");
let tab = null;
let poll = null;

function el(tag, props = {}, ...children) {
  const e = Object.assign(document.createElement(tag), props);
  e.append(...children.filter((c) => c != null));
  return e;
}

function message(title, text, cls = "") {
  return el("p", { className: `message ${cls}` }, title ? el("strong", {}, title) : null, text);
}

function button(label, onclick, cls = "primary") {
  return el("button", { className: cls, onclick }, label);
}

function show(...nodes) {
  main.replaceChildren(...nodes);
}

/// Ask again every `ms` while the popup is open (waiting for an unlock, a
/// pairing approval or VaultRust starting).
function again(ms) {
  clearTimeout(poll);
  poll = setTimeout(refresh, ms);
}

async function refresh() {
  if (!tab) {
    show(message(null, t("noSite")));
    return;
  }
  const reply = await ask({ type: "logins", url: tab.url });
  switch (reply.error) {
    case undefined:
      return showLogins(reply.logins ?? []);
    case "no_host":
      return show(message(t("notSetUpTitle"), t("notSetUp")));
    case "not_running":
      return show(
        message(t("notRunningTitle"), t("notRunning")),
        button(t("start"), async () => {
          show(message(null, t("starting")));
          await ask({ type: "launch" });
          again(1500);
        }),
      );
    case "disabled":
      return show(message(t("disabledTitle"), t("disabled")));
    case "unpaired":
      return showPairing();
    case "locked":
      again(1500);
      return show(
        message(t("lockedTitle"), t("locked")),
        button(t("unlock"), () => ask({ type: "show" })),
      );
    default:
      return show(
        message(t("noReplyTitle"), t("noReply"), "error"),
        button(t("tryAgain"), refresh),
      );
  }
}

async function showPairing() {
  const { pairAsked } = await chrome.storage.local.get("pairAsked");
  // Asked in the last two minutes: VaultRust is (probably) showing the
  // question right now.
  if (pairAsked && Date.now() - pairAsked < 120000) {
    again(1500);
    return show(
      message(t("confirmTitle"), t("confirm")),
      el("div", { className: "code" }, await pairingCode()),
      button(t("askAgain"), pair, "link"),
    );
  }
  show(message(t("connectTitle"), t("connect")), button(t("connectButton"), pair));
}

async function pair() {
  const reply = await ask({ type: "pair", browser: browserName() });
  if (reply.error && reply.error !== "unpaired") return refresh();
  await chrome.storage.local.set({ pairAsked: Date.now() });
  showPairing();
}

function showLogins(logins) {
  const host = new URL(tab.url).hostname.replace(/^www\./, "");
  if (!logins.length) {
    return show(
      message(null, t("noLogins", host)),
      button(t("openApp"), () => ask({ type: "show" }), "link"),
    );
  }
  const list = el(
    "div",
    { className: "logins" },
    ...logins.map((l) =>
      el(
        "button",
        { className: "login", onclick: () => choose(l.id) },
        el("span", { className: "tile" }, (l.title.trim()[0] ?? "?").toUpperCase()),
        el(
          "span",
          { className: "who" },
          el("div", { className: "title" }, l.title),
          el("div", { className: "user" }, l.username || t("noUsername")),
        ),
      ),
    ),
  );
  show(list, el("div", { className: "hint" }, t("shortcutHint")));
  list.querySelector("button")?.focus();
}

async function choose(id) {
  const err = await fill(tab, id);
  if (!err) return window.close();
  if (err === "no_form") {
    show(message(null, t("noForm"), "error"), button(t("tryAgain"), refresh, "link"));
  } else {
    refresh();
  }
}

tab = await currentTab();
document.getElementById("site").textContent = tab ? new URL(tab.url).hostname : "";
refresh();
