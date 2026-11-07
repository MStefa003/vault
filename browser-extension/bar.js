// The bar offering to save a login the user just signed in with (or to
// update its password).
import { el, explain, iconButton, send, t } from "./shared.js";

const main = document.getElementById("main");

function resize() {
  send({ type: "barSize", height: Math.ceil(document.body.scrollHeight) + 2 });
}

function show(title, text, buttons = []) {
  main.replaceChildren(
    el(
      "div",
      { class: "top" },
      el("img", { src: "icons/icon-32.png", alt: "" }),
      el("div", { class: "text" }, el("strong", {}, title), text ? el("span", {}, text) : null),
      iconButton("close", t("close"), () => send({ type: "barClose" })),
    ),
    buttons.length ? el("div", { class: "buttons" }, ...buttons) : null,
  );
  resize();
}

async function start() {
  const p = await send({ type: "barData" });
  if (p.error) return send({ type: "barClose" });
  const who = p.username || t("noUsername");
  const save = el("button", { class: "primary", onclick: () => save_(p) }, p.state === "update" ? t("update") : t("save"));
  const never =
    p.state === "update" ? null : el("button", { class: "link", onclick: () => send({ type: "barNever" }) }, t("never"));
  const later = el("button", { class: "secondary", onclick: () => send({ type: "barClose" }) }, t("notNow"));
  if (p.state === "update") {
    show(t("updateTitle", p.title), t("updateText", who), [save, later]);
  } else {
    show(t("saveTitle", p.host), who, [save, later, never]);
  }
  if (p.state === "locked") main.querySelector(".text span").textContent = `${who} · ${t("saveLocked")}`;
}

async function save_(p) {
  const r = await send({ type: "barSave" });
  if (r.error === "locked") {
    return show(t("lockedTitle"), t("saveAfterUnlock"), [
      el("button", { class: "primary", onclick: () => save_(p) }, t("save")),
    ]);
  }
  if (r.error) {
    const [title, text] = explain(r.error);
    return show(title, text);
  }
  show(p.state === "update" ? t("updated") : t("saved"), null);
  main.querySelector("strong").classList.add("done");
  setTimeout(() => send({ type: "barClose" }), 1800);
}

start();
