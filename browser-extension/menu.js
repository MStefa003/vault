// The menu under a login, card or address field: the site's logins, a
// generated password for sign-up forms, the vault's cards or identities, or
// what to do when VaultRust can't answer.
import { el, explain, icon, itemRow, send, t } from "./shared.js";

const main = document.getElementById("main");
let poll = null;

function resize() {
  send({ type: "menuSize", height: Math.ceil(document.body.scrollHeight) + 2 });
}

function show(...nodes) {
  main.replaceChildren(...nodes);
  resize();
}

function action(iconName, label, onclick) {
  return el("button", { class: "link", onclick, html: `${icon(iconName)} ` }, label);
}

async function refresh() {
  clearTimeout(poll);
  const data = await send({ type: "menuData" });
  if (data.host) document.getElementById("head").textContent = `VaultRust · ${data.host}`;
  if (data.error) {
    const [title, text] = explain(data.error);
    const nodes = [el("p", { class: "message" }, el("strong", {}, title), text)];
    if (data.error === "locked") {
      nodes.push(el("div", { class: "foot" }, action("lock", t("unlock"), () => send({ type: "menuShow" }))));
      poll = setTimeout(refresh, 1500);
    }
    return show(...nodes);
  }
  if (data.form) return showForms(data);
  const rows = [];
  if (data.newPassword) {
    rows.push(
      el(
        "div",
        { class: "row gen" },
        el(
          "button",
          { class: "row-main", onclick: generate },
          el("span", { class: "tile", html: icon("dice") }),
          el(
            "span",
            { class: "who" },
            el("span", { class: "title" }, t("generate")),
            el("span", { class: "sub" }, t("generateHint")),
          ),
        ),
      ),
    );
  }
  for (const login of data.logins ?? []) {
    rows.push(itemRow(login, { onclick: () => choose(login.id) }));
  }
  const nodes = [el("div", { class: "rows" }, ...rows)];
  if (!data.logins?.length && !data.newPassword) {
    nodes.unshift(el("p", { class: "message" }, t("noLogins", data.host ?? "")));
  }
  nodes.push(el("div", { class: "foot" }, action("plus", t("addLogin"), () => send({ type: "menuNew" }))));
  show(...nodes);
}

/// Cards (in a payment form) or identities (in an address form).
function showForms(data) {
  const card = data.form === "card";
  const items = data.items ?? [];
  const nodes = [];
  if (data.insecure) {
    const [title, text] = explain("insecure");
    nodes.push(el("p", { class: "message" }, el("strong", {}, title), text));
  } else if (!items.length) {
    nodes.push(el("p", { class: "message" }, t(card ? "noCards" : "noIdentities")));
  } else {
    nodes.push(el("div", { class: "rows" }, ...items.map((item) => itemRow(item, { onclick: () => chooseForm(item.id) }))));
  }
  nodes.push(
    el("div", { class: "foot" }, action("plus", t(card ? "addCard" : "addIdentity"), () => send({ type: "menuNew" }))),
  );
  show(...nodes);
}

async function chooseForm(id) {
  const r = await send({ type: "menuFillForm", id });
  if (r.error) {
    const [title, text] = explain(r.error);
    show(el("p", { class: "message error" }, el("strong", {}, title), text));
  }
}

async function choose(id) {
  const r = await send({ type: "menuFill", id });
  if (r.error === "no_form") show(el("p", { class: "message error" }, t("noForm")));
}

async function generate() {
  const r = await send({ type: "menuGenerate" });
  if (r.error) {
    const [title, text] = explain(r.error);
    show(el("p", { class: "message" }, el("strong", {}, title), text));
  }
}

document.addEventListener("keydown", (e) => {
  const buttons = [...document.querySelectorAll("button")];
  const i = buttons.indexOf(document.activeElement);
  if (e.key === "Escape") send({ type: "menuClose" });
  else if (e.key === "ArrowDown") buttons[(i + 1) % buttons.length]?.focus();
  else if (e.key === "ArrowUp") buttons[(i - 1 + buttons.length) % buttons.length]?.focus();
  else return;
  e.preventDefault();
});
window.addEventListener("focus", () => document.querySelector("button")?.focus());

refresh();
