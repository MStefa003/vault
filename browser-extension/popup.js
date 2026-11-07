// The toolbar popup: the current site's logins, a search of the vault and
// the password generator.
import { el, explain, icon, iconButton, itemRow, send, t } from "./shared.js";

const main = document.getElementById("main");
const ask = (request) => send({ type: "ask", request });

let tab = null;
let page = "site";
let poll = null;

const [current] = await chrome.tabs.query({ active: true, currentWindow: true });
if (current?.url && /^https?:/i.test(current.url)) tab = current;
const host = tab ? new URL(tab.url).hostname.replace(/^www\./, "") : "";
document.getElementById("site").textContent = host;

function toast(text) {
  const box = document.getElementById("toast");
  box.textContent = text;
  box.classList.add("on");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => box.classList.remove("on"), 2200);
}

function show(...nodes) {
  main.replaceChildren(...nodes.filter(Boolean));
}

function tabs() {
  const pages = [
    ["site", t("tabSite")],
    ["vault", t("tabVault")],
    ["generator", t("tabGenerator")],
  ];
  document.getElementById("tabs").replaceChildren(
    ...pages.map(([id, label]) =>
      el(
        "button",
        {
          role: "tab",
          "aria-selected": String(page === id),
          onclick: () => {
            page = id;
            render();
          },
        },
        label,
      ),
    ),
  );
}

/// What to show instead of the page when VaultRust can't answer.
async function problem(error) {
  clearTimeout(poll);
  const [title, text] = explain(error);
  const nodes = [el("p", { class: "message" }, el("strong", {}, title), text)];
  switch (error) {
    case "not_running":
      nodes.push(
        el(
          "button",
          {
            class: "primary",
            onclick: async () => {
              show(el("p", { class: "message" }, t("starting")));
              await ask({ type: "launch" });
              poll = setTimeout(render, 1500);
            },
          },
          t("start"),
        ),
      );
      break;
    case "unpaired":
      return pairing();
    case "locked":
      nodes.push(el("button", { class: "primary", onclick: () => ask({ type: "show" }) }, t("unlock")));
      poll = setTimeout(render, 1500);
      break;
    case "no_reply":
    case "busy":
      nodes.push(el("button", { class: "secondary", onclick: render }, t("tryAgain")));
      break;
  }
  show(...nodes);
}

async function pairingCode() {
  const { token } = await chrome.storage.local.get("token");
  const data = new TextEncoder().encode(token ?? "");
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  const n = ((h[0] << 16) | (h[1] << 8) | h[2]) % 1000000;
  const s = String(n).padStart(6, "0");
  return `${s.slice(0, 3)} ${s.slice(3)}`;
}

function browserName() {
  const brands = navigator.userAgentData?.brands?.map((b) => b.brand) ?? [];
  for (const name of ["Microsoft Edge", "Brave", "Opera", "Vivaldi", "Google Chrome"]) {
    if (brands.includes(name)) return name.replace("Google ", "");
  }
  return "Chromium";
}

async function pairing() {
  const { pairAsked } = await chrome.storage.local.get("pairAsked");
  // Asked in the last two minutes: VaultRust is (probably) showing the
  // question right now.
  if (pairAsked && Date.now() - pairAsked < 120000) {
    poll = setTimeout(render, 1500);
    return show(
      el("p", { class: "message" }, el("strong", {}, t("confirmTitle")), t("confirm")),
      el("div", { class: "code" }, await pairingCode()),
      el("button", { class: "link", onclick: pair }, t("askAgain")),
    );
  }
  show(
    el("p", { class: "message" }, el("strong", {}, t("connectTitle")), t("connect")),
    el("button", { class: "primary", onclick: pair }, t("connectButton")),
  );
}

async function pair() {
  const reply = await ask({ type: "pair", browser: browserName() });
  if (reply.error && reply.error !== "unpaired") return problem(reply.error);
  await chrome.storage.local.set({ pairAsked: Date.now() });
  render();
}

/// Copy buttons for an item; VaultRust copies (and clears the clipboard
/// later), so the secret never comes to the browser.
function copyButtons(item) {
  const copy = (what, label) => async () => {
    const r = await ask({ type: "copy", id: item.id, what });
    if (r.error) return problem(r.error);
    toast(t("copied", label));
  };
  return [
    item.username ? iconButton("user", t("copyUsername"), copy("username", t("username"))) : null,
    item.password ? iconButton("key", t("copyPassword"), copy("password", t("password"))) : null,
    item.code ? iconButton("clock", t("copyCode"), copy("code", t("code"))) : null,
  ];
}

async function lockButton(unlocked) {
  document
    .getElementById("lock")
    .replaceChildren(
      unlocked
        ? iconButton("lock", t("lock"), async () => {
            await ask({ type: "lock" });
            render();
          })
        : "",
    );
}

// --- This site -----------------------------------------------------------------

async function sitePage() {
  if (!tab) return show(el("p", { class: "message" }, t("noSite")));
  const reply = await ask({ type: "logins", url: tab.url });
  lockButton(!reply.error);
  if (reply.error) return problem(reply.error);
  const logins = reply.logins ?? [];
  const add = el("button", { class: "link", onclick: () => ask({ type: "new", url: tab.url }), html: `${icon("plus")} ` }, t("addLogin"));
  if (!logins.length) return show(el("p", { class: "message" }, t("noLogins", host)), add);
  show(
    el(
      "div",
      { class: "rows" },
      ...logins.map((l) => itemRow(l, { onclick: () => choose(l.id), actions: copyButtons(l) })),
    ),
    el("div", { class: "more" }, add),
    el("p", { class: "faint note" }, t("shortcutHint")),
  );
  main.querySelector(".row-main")?.focus();
}

async function choose(id) {
  const r = await send({ type: "fillTab", tabId: tab.id, id });
  if (!r.error) return window.close();
  if (r.error === "no_form") show(el("p", { class: "message error" }, t("noForm")), el("button", { class: "link", onclick: render }, t("tryAgain")));
  else problem(r.error);
}

// --- Vault search ------------------------------------------------------------------

async function vaultPage() {
  const input = el("input", { type: "search", placeholder: t("searchVault"), "aria-label": t("searchVault") });
  const results = el("div", { class: "rows" });
  show(el("label", { class: "search", html: icon("search") }, input), results);
  let timer = null;
  const search = async () => {
    const reply = await ask({ type: "search", query: input.value });
    lockButton(!reply.error);
    if (reply.error) return problem(reply.error);
    const items = reply.items ?? [];
    results.replaceChildren(
      ...(items.length
        ? items.map((item) => itemRow(item, { actions: copyButtons(item) }))
        : [el("p", { class: "message" }, t("nothingFound"))]),
    );
  };
  input.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(search, 150);
  });
  input.focus();
  search();
}

// --- Generator ------------------------------------------------------------------

async function generatorPage() {
  const reply = await ask({ type: "generate", url: tab?.url ?? "" });
  lockButton(!reply.error);
  if (reply.error) return problem(reply.error);
  const password = reply.password;
  show(
    el("div", { class: "password" }, password),
    el(
      "div",
      { class: "buttons" },
      el("button", { class: "secondary", onclick: generatorPage, html: `${icon("refresh")} ` }, t("regenerate")),
      el(
        "button",
        {
          class: "secondary",
          onclick: async () => {
            await navigator.clipboard.writeText(password);
            toast(t("copied", t("password")));
          },
          html: `${icon("copy")} `,
        },
        t("copy"),
      ),
      tab
        ? el(
            "button",
            {
              class: "primary",
              onclick: async () => {
                const r = await send({ type: "fillPassword", tabId: tab.id, password });
                if (r.filled) window.close();
                else toast(t("noPasswordField"));
              },
            },
            t("fillPassword"),
          )
        : null,
    ),
    el("p", { class: "faint note" }, t("generatorHint")),
  );
}

function render() {
  clearTimeout(poll);
  tabs();
  if (page === "site") return sitePage();
  if (page === "vault") return vaultPage();
  return generatorPage();
}

if (tab) send({ type: "refresh", tabId: tab.id });
render();
