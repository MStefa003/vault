// VaultRust's script in web pages: the icon and menu in login fields,
// filling in, and noticing when a login form is submitted (to offer saving
// it). It never sees the vault: logins arrive from the background worker
// only when the user picks one, and the menu and save bar are extension
// pages in frames the page can't read.

(() => {
  if (window.__vaultrust) return;
  window.__vaultrust = true;

  const send = (message) => chrome.runtime.sendMessage(message).catch(() => ({}));
  const ICON = chrome.runtime.getURL("icons/icon-32.png");

  // --- Which fields are login fields ---------------------------------------

  const TEXTUAL = new Set(["text", "email", "tel", ""]);
  const USERISH = /user|login|email|e-mail|account|identifier|ident|benutzer|χρήστ/i;
  const attrs = (el) => `${el.name} ${el.id} ${el.autocomplete} ${el.placeholder} ${el.getAttribute("aria-label") ?? ""}`;

  const visible = (el) => {
    if (el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 30 || r.height < 12) return false;
    const s = getComputedStyle(el);
    return s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0";
  };

  const isPassword = (el) => el instanceof HTMLInputElement && el.type === "password";

  const scope = (el) => el.form ?? document;

  const inputsIn = (root) => [...root.querySelectorAll("input")].filter(visible);

  const isUsername = (el) =>
    el instanceof HTMLInputElement &&
    TEXTUAL.has(el.type) &&
    (/username|email/.test(el.autocomplete) || el.type === "email" || USERISH.test(attrs(el)));

  /// A field VaultRust can help with: a password, or a username next to
  /// one (or on its own, as on the first page of a two-step login).
  function isLoginField(el) {
    if (!(el instanceof HTMLInputElement) || !visible(el)) return false;
    if (/one-time-code/.test(el.autocomplete)) return false;
    if (isPassword(el)) return true;
    if (!isUsername(el)) return false;
    const fields = inputsIn(scope(el));
    return fields.some(isPassword) || fields.filter((f) => TEXTUAL.has(f.type)).length <= 2;
  }

  /// A field for a new password (sign-up or change-password forms).
  function isNewPassword(el) {
    if (!isPassword(el)) return false;
    if (/new-password/.test(el.autocomplete)) return true;
    if (/current-password/.test(el.autocomplete)) return false;
    return inputsIn(scope(el)).filter(isPassword).length >= 2 || /new|confirm|repeat|signup|register/i.test(attrs(el));
  }

  // --- Filling ------------------------------------------------------------------

  function set(el, value) {
    el.focus();
    // Through the prototype's setter, so frameworks (React…) notice.
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  /// The username field that belongs with `pw`: the last text field before
  /// it, preferably in the same form.
  function usernameFor(pw, fields) {
    const before = fields.filter(
      (el) => TEXTUAL.has(el.type) && pw.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_PRECEDING,
    );
    const sameForm = before.filter((el) => el.form && el.form === pw.form);
    return (sameForm.length ? sameForm : before).at(-1);
  }

  function fillLogin({ host, username, password, code }) {
    // The page may have moved on to another site since VaultRust checked it.
    if (location.hostname.toLowerCase().replace(/^www\./, "") !== host) return { filled: 0 };
    const around = lastField && document.contains(lastField) ? scope(lastField) : document;
    let fields = inputsIn(around);
    if (!fields.some((f) => isPassword(f) || isUsername(f))) fields = inputsIn(document);
    const passwords = fields.filter((el) => isPassword(el) && !/new-password/.test(el.autocomplete));
    let filled = 0;

    if (passwords.length && password) {
      const pw = lastField && passwords.includes(lastField) ? lastField : passwords[0];
      const user = usernameFor(pw, fields);
      if (user && username) {
        set(user, username);
        filled++;
      }
      set(pw, password);
      return { filled: filled + 1 };
    }

    // A page asking only for the one-time code.
    const otp = fields.find(
      (el) =>
        ["text", "tel", "number", ""].includes(el.type) &&
        (/one-time-code/.test(el.autocomplete) ||
          /\b(otp|totp|2fa|mfa|one.?time|verification.?code|auth.?code)\b/i.test(attrs(el))),
    );
    if (otp && code) {
      set(otp, code);
      return { filled: 1 };
    }

    // The first page of a two-step login: only the username.
    const user = (lastField && isUsername(lastField) && lastField) || fields.find(isUsername);
    if (user && username) {
      set(user, username);
      filled++;
    }
    return { filled };
  }

  function fillPassword(password) {
    const target = lastField && isPassword(lastField) ? lastField : null;
    let fields = inputsIn(target ? scope(target) : document).filter(isPassword);
    const fresh = fields.filter(isNewPassword);
    if (fresh.length) fields = fresh;
    // Change-password forms: the current password comes first.
    if (fields.length === 3) fields = fields.slice(1);
    for (const f of fields) set(f, password);
    return { filled: fields.length };
  }

  // --- The icon and menu in login fields --------------------------------------

  let host = null; // our element on the page (its contents are closed off)
  let root = null;
  let iconEl = null;
  let menuFrame = null;
  let lastField = null;
  let dismissed = null; // a field whose menu the user closed

  function ensureHost() {
    if (host && document.documentElement.contains(host)) return;
    host = document.createElement("vaultrust-ui");
    host.style.cssText = "all:initial;position:absolute;top:0;left:0;width:0;height:0;z-index:2147483647;";
    root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      .icon { position:absolute; width:18px; height:18px; padding:3px; border-radius:5px; cursor:pointer;
              background:rgba(127,127,127,.12); box-sizing:content-box; }
      .icon:hover { background:rgba(127,127,127,.28); }
      iframe { position:absolute; border:0; border-radius:10px; color-scheme:normal;
               box-shadow:0 8px 28px rgba(0,0,0,.28); background:transparent; }
    `;
    root.append(style);
    document.documentElement.append(host);
  }

  function place(el, field, { below = false, width } = {}) {
    const r = field.getBoundingClientRect();
    const x = r.left + window.scrollX;
    const y = r.top + window.scrollY;
    if (below) {
      el.style.left = `${Math.max(4, x)}px`;
      el.style.top = `${y + r.height + 4}px`;
      el.style.width = `${width}px`;
    } else {
      el.style.left = `${x + r.width - 30}px`;
      el.style.top = `${y + (r.height - 24) / 2}px`;
    }
  }

  function showIcon(field) {
    ensureHost();
    if (!iconEl) {
      iconEl = document.createElement("img");
      iconEl.className = "icon";
      iconEl.src = ICON;
      iconEl.alt = "VaultRust";
      iconEl.title = "VaultRust";
      iconEl.addEventListener("mousedown", (e) => {
        e.preventDefault(); // keep the focus in the field
        e.stopPropagation();
        if (menuFrame) closeMenu();
        else if (lastField) openMenu(lastField);
      });
      root.append(iconEl);
    }
    place(iconEl, field);
  }

  function hideIcon() {
    iconEl?.remove();
    iconEl = null;
  }

  function openMenu(field) {
    ensureHost();
    closeMenu();
    dismissed = null;
    send({ type: "openMenu", newPassword: isNewPassword(field) });
    menuFrame = document.createElement("iframe");
    menuFrame.src = chrome.runtime.getURL("menu.html");
    menuFrame.style.height = "64px";
    const width = Math.min(380, Math.max(280, field.getBoundingClientRect().width));
    place(menuFrame, field, { below: true, width });
    root.append(menuFrame);
  }

  function closeMenu() {
    menuFrame?.remove();
    menuFrame = null;
  }

  function reposition() {
    if (!lastField || !document.contains(lastField) || !visible(lastField)) {
      hideIcon();
      closeMenu();
      return;
    }
    if (iconEl) place(iconEl, lastField);
    if (menuFrame) place(menuFrame, lastField, { below: true, width: parseFloat(menuFrame.style.width) });
  }

  document.addEventListener(
    "focusin",
    async (e) => {
      const field = e.target;
      if (!isLoginField(field)) return;
      if (field !== lastField) closeMenu();
      lastField = field;
      const how = await send({ type: "field" });
      if (document.activeElement !== field) return;
      if (how?.icon) showIcon(field);
      if (how?.open && !menuFrame && dismissed !== field && !field.value) openMenu(field);
    },
    true,
  );

  document.addEventListener(
    "focusout",
    () => {
      setTimeout(() => {
        const active = document.activeElement;
        if (active === lastField) return;
        // The menu frame itself has the focus while it's being used.
        if (menuFrame && active === host) return;
        hideIcon();
        closeMenu();
      }, 150);
    },
    true,
  );

  document.addEventListener(
    "keydown",
    (e) => {
      if (e.target !== lastField) return;
      if (e.key === "ArrowDown" && !e.altKey && iconEl) {
        if (!menuFrame) openMenu(lastField);
        setTimeout(() => menuFrame?.focus(), 50);
        e.preventDefault();
      } else if (e.key === "Escape" && menuFrame) {
        dismissed = lastField;
        closeMenu();
      }
    },
    true,
  );

  document.addEventListener(
    "mousedown",
    (e) => {
      if (menuFrame && e.target !== host && e.target !== lastField) {
        dismissed = lastField;
        closeMenu();
      }
    },
    true,
  );

  window.addEventListener("scroll", reposition, true);
  window.addEventListener("resize", reposition);

  // --- Noticing a sign-in, to offer saving it --------------------------------

  let lastCapture = { key: "", time: 0 };

  const filledIn = (root) => inputsIn(root).some((f) => (isPassword(f) || isUsername(f)) && f.value);

  /// The form around `el`, or (pages without forms) the nearest element
  /// around it holding a filled-in login field.
  function around(el) {
    if (el.form) return el.form;
    const form = el.closest?.("form");
    if (form) return form;
    let c = el.parentElement;
    while (c && c !== document.documentElement && !filledIn(c)) c = c.parentElement;
    return c ?? document;
  }

  function capture(root) {
    const fields = inputsIn(root);
    const passwords = fields.filter((f) => isPassword(f) && f.value);
    if (!passwords.length) {
      // Two-step logins: remember the username for the password page.
      const user = fields.find((f) => isUsername(f) && f.value);
      if (user) send({ type: "username", value: user.value.trim() });
      return;
    }
    let password = passwords[0].value;
    // Sign-up (new + repeat) or change (current + new + repeat) forms: the
    // new password.
    if (passwords.length >= 2) {
      const last = passwords.at(-1).value;
      if (passwords.at(-2).value === last) password = last;
    }
    const username = usernameFor(passwords[0], fields)?.value.trim() ?? "";
    // A submit button's click and the form's submit event both arrive.
    const key = `${username}\n${password}`;
    if (key === lastCapture.key && Date.now() - lastCapture.time < 1000) return;
    lastCapture = { key, time: Date.now() };
    send({ type: "captured", username, password });
  }

  document.addEventListener("submit", (e) => capture(e.target), true);
  document.addEventListener(
    "click",
    (e) => {
      const button = e.target.closest?.('button, input[type="submit"], input[type="button"], [role="button"]');
      if (!button) return;
      const root = around(button);
      if (filledIn(root)) capture(root);
    },
    true,
  );
  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key === "Enter" && e.target instanceof HTMLInputElement && (isPassword(e.target) || isUsername(e.target))) {
        capture(around(e.target));
      }
    },
    true,
  );

  // --- The bar offering to save -------------------------------------------------

  let bar = null;

  function showBar() {
    if (window !== window.top || bar) return;
    ensureHost();
    bar = document.createElement("iframe");
    bar.src = chrome.runtime.getURL("bar.html");
    bar.style.cssText = "position:fixed;top:12px;right:12px;width:380px;height:120px;";
    root.append(bar);
  }

  function closeBar() {
    bar?.remove();
    bar = null;
  }

  // --- Messages from the background worker ---------------------------------

  chrome.runtime.onMessage.addListener((msg, sender, respond) => {
    if (sender.id !== chrome.runtime.id) return;
    switch (msg.type) {
      case "fill":
        respond(fillLogin(msg));
        break;
      case "fillPassword":
        respond(fillPassword(msg.password));
        break;
      case "closeMenu":
        closeMenu();
        lastField?.focus();
        respond({});
        break;
      case "menuSize":
        if (menuFrame) menuFrame.style.height = `${Math.min(360, msg.height)}px`;
        respond({});
        break;
      case "showBar":
        showBar();
        respond({});
        break;
      case "closeBar":
        closeBar();
        respond({});
        break;
      case "barSize":
        if (bar) bar.style.height = `${Math.min(240, msg.height)}px`;
        respond({});
        break;
    }
  });

  if (window === window.top) {
    send({ type: "ready" }).then((r) => r?.showBar && showBar());
  }
})();
