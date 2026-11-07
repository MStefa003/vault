// VaultRust's script in web pages: the icon and menu in login, payment and
// address fields, filling them in, and noticing when a login form is
// submitted (to offer saving it). It never sees the vault: logins arrive from the background worker
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

  // --- Which fields are card and address fields --------------------------------

  const FORM_TAGS = "input, select, textarea";
  const fieldsIn = (root) =>
    [...root.querySelectorAll(FORM_TAGS)].filter(
      (el) => visible(el) && !(el instanceof HTMLInputElement && !TEXTUAL.has(el.type) && el.type !== "number"),
    );

  /// The text of the <label> for `el`, if any.
  function labelText(el) {
    const label = el.labels?.[0] ?? el.closest?.("label");
    return label?.textContent?.slice(0, 80) ?? "";
  }

  // [role, autocomplete tokens, words in the field's name, id, placeholder or label]
  const CARD_ROLES = [
    ["number", ["cc-number"], /card.?(num|no\b)|cc.?num|cardnumber|acct.?num|kartennummer|numéro de carte|αριθμός κάρτας/i],
    ["name", ["cc-name"], /(card|cc).?(holder|name|owner)|name.?on.?card|holder.?name|karteninhaber|titulaire|κάτοχ/i],
    ["given", ["cc-given-name"], null],
    ["family", ["cc-family-name"], null],
    ["month", ["cc-exp-month"], /(exp|expiry|expiration|valid).{0,8}(month|mm\b)|cc.?month|card.?month/i],
    ["year", ["cc-exp-year"], /(exp|expiry|expiration|valid).{0,8}(year|yy)|cc.?year|card.?year/i],
    ["expiry", ["cc-exp"], /expir|exp.?date|\bexp\b|valid.?(thru|until)|mm.?\/.?yy|gültig|λήξη/i],
    ["code", ["cc-csc"], /cvv|cvc|csc|cvn|security.?code|card.?code|card.?verification|sicherheitscode|κωδικός ασφαλείας/i],
    ["brand", ["cc-type"], /card.?type|cc.?type|card.?brand/i],
  ];

  const ADDRESS_ROLES = [
    ["given", ["given-name"], /first.?name|given.?name|\bfname|vorname|prénom|(^|\s)όνομα(\s|$)/i],
    ["family", ["family-name"], /last.?name|family.?name|surname|\blname|nachname|επώνυμο/i],
    ["middle", ["additional-name"], /middle.?name/i],
    ["name", ["name"], /full.?name|your.?name|(^|\s)name(\s|$)|ονοματεπώνυμο/i],
    ["email", ["email"], /e.?mail/i],
    ["phone", ["tel", "tel-national"], /phone|mobile|\btel\b|telefon|τηλέφωνο|κινητό/i],
    ["street", ["street-address"], null],
    ["line2", ["address-line2", "address-line3"], /address.?(line)?.?[23]|addr.?[23]|apartment|suite|\bapt\b|adresszusatz/i],
    ["line1", ["address-line1"], /address.?(line)?.?1|addr.?1|street|(^|\s)address(\s|$)|billing.?address|shipping.?address|adresse|straße|strasse|διεύθυνση|οδός/i],
    ["city", ["address-level2"], /city|town|locality|stadt|\bort\b|ville|πόλη/i],
    ["region", ["address-level1"], /state|province|region|county|bundesland|νομός|περιφέρεια/i],
    ["postcode", ["postal-code"], /zip|postal|post.?code|\bplz\b|code.?postal|ταχυδρομικός/i],
    ["country", ["country", "country-name"], /country|pays|χώρα/i],
  ];

  /// The token that names the field ("shipping street-address" -> "street-address").
  const autocompleteToken = (el) => (el.getAttribute("autocomplete") ?? "").trim().toLowerCase().split(/\s+/).at(-1);

  function roleIn(table, el) {
    const token = autocompleteToken(el);
    for (const [role, tokens] of table) if (tokens.includes(token)) return role;
    // A field that says what it is, and it's something else.
    if (token && token !== "on" && token !== "off") return null;
    const text = `${el.name} ${el.id} ${el.getAttribute("placeholder") ?? ""} ${el.getAttribute("aria-label") ?? ""} ${labelText(el)}`.trim();
    for (const [role, , words] of table) {
      // "E-mail address" is not a street.
      if (words?.test(text) && !(role === "line1" && /e.?mail|\bip\b/i.test(text))) return role;
    }
    return null;
  }

  const cardRole = (el) => (isPassword(el) || /one-time-code/.test(el.autocomplete) ? null : roleIn(CARD_ROLES, el));
  const addressRole = (el) => (isPassword(el) ? null : roleIn(ADDRESS_ROLES, el));

  /// "card" when `el` is a payment card field, "identity" when it's part of
  /// an address or contact form (two or more such fields, at least one of
  /// them more than a name or an email address), or null.
  function formKind(el) {
    if (!(el instanceof HTMLElement) || !el.matches(FORM_TAGS) || !visible(el)) return null;
    const fields = fieldsIn(scope(el));
    if (cardRole(el) && fields.some((f) => ["number", "code"].includes(cardRole(f)))) return "card";
    // Sign-up forms are filled from logins.
    if (!addressRole(el) || inputsIn(scope(el)).some(isPassword)) return null;
    const roles = new Set(fields.map(addressRole).filter(Boolean));
    const postal = ["street", "line1", "city", "postcode", "region", "country", "phone"].some((r) => roles.has(r));
    return roles.size >= 2 && postal ? "identity" : null;
  }

  // --- Filling ------------------------------------------------------------------

  const PROTOS = [HTMLInputElement, HTMLSelectElement, HTMLTextAreaElement].map((c) => c.prototype);

  function set(el, value) {
    el.focus();
    // Through the prototype's setter, so frameworks (React…) notice.
    const proto = PROTOS.find((p) => p.isPrototypeOf(el)) ?? HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  const MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
  const norm = (s) =>
    s
      .normalize("NFD")
      .replace(/[̀-ͯ]/g, "")
      .toLowerCase()
      .replace(/[^\p{L}\p{N}]+/gu, " ")
      .trim();

  /// Pick the option of a <select> that means one of `wanted` ("08", "8",
  /// "aug"…). Returns whether one was found.
  function pick(select, wanted) {
    const want = wanted.filter(Boolean).map((w) => norm(String(w)));
    if (!want.length) return false;
    const options = [...select.options].filter((o) => !o.disabled);
    const hit =
      options.find((o) => want.includes(norm(o.value)) || want.includes(norm(o.text))) ??
      options.find((o) => want.some((w) => w.length >= 3 && norm(o.text).startsWith(w)));
    if (!hit) return false;
    set(select, hit.value);
    return true;
  }

  /// Put `value` in a field; for a drop-down, the option matching it (or
  /// one of `alternatives`).
  function put(el, value, ...alternatives) {
    if (!value) return false;
    if (el instanceof HTMLSelectElement) return pick(el, [value, ...alternatives]);
    set(el, value);
    return true;
  }

  /// "MM/YY", "MM/YYYY" or "MMYY", as the field seems to want it.
  function expiryText(el, month, year) {
    const hint = `${el.placeholder ?? ""} ${el.getAttribute("aria-label") ?? ""} ${labelText(el)}`.toLowerCase();
    const max = el.maxLength > 0 ? el.maxLength : 0;
    if (/yyyy|εεεε|jjjj|aaaa/.test(hint) || max === 7) return `${month}/${year}`;
    if (max === 4) return `${month}${year.slice(2)}`;
    return `${month}/${year.slice(2)}`;
  }

  /// The fields to fill: those around the field the menu was opened from,
  /// or (from the toolbar popup) around the first field of the right kind.
  function formFields(kind) {
    if (lastField && document.contains(lastField) && formKind(lastField) === kind) return fieldsIn(scope(lastField));
    const first = fieldsIn(document).find((el) => formKind(el) === kind);
    return first ? fieldsIn(scope(first)) : [];
  }

  function fillCard(c) {
    const [given, ...rest] = (c.name ?? "").split(/\s+/);
    const month = Number(c.month);
    let filled = 0;
    for (const el of formFields("card")) {
      const select = el instanceof HTMLSelectElement;
      const done = {
        number: () => put(el, c.number),
        name: () => put(el, c.name),
        given: () => put(el, given),
        family: () => put(el, rest.join(" ")),
        month: () => put(el, c.month, String(month), MONTHS[month - 1]),
        year: () => put(el, select || el.maxLength !== 2 ? c.year : c.year.slice(2), c.year.slice(2)),
        expiry: () => !!c.month && put(el, expiryText(el, c.month, c.year)),
        code: () => put(el, c.code),
        brand: () => put(el, c.brand, { amex: "american express", mastercard: "master card", diners: "diners club" }[c.brand]),
      }[cardRole(el)]?.();
      if (done) filled++;
    }
    return filled;
  }

  function fillIdentity(id) {
    const fields = formFields("identity");
    const roles = new Set(fields.map(addressRole));
    const street = id.street ?? [];
    let filled = 0;
    for (const el of fields) {
      const value = {
        name: id.name,
        // No separate middle-name field: keep it with the first name.
        given: roles.has("middle") || !id.middle ? id.given : `${id.given} ${id.middle}`,
        middle: id.middle,
        family: id.family,
        email: id.email,
        phone: id.phone,
        street: street.join(el instanceof HTMLTextAreaElement ? "\n" : ", "),
        line1: roles.has("line2") ? street[0] : street.join(", "),
        line2: street.slice(1).join(", "),
        city: id.city,
        region: id.region,
        postcode: id.postcode,
        country: id.country,
      }[addressRole(el)];
      if (put(el, value)) filled++;
    }
    return filled;
  }

  function fillForm(data) {
    // The page may have moved on to another site since VaultRust checked it.
    if (location.hostname.toLowerCase().replace(/^www\./, "") !== data.host) return { filled: 0 };
    return { filled: data.kind === "card" ? fillCard(data) : fillIdentity(data) };
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
    send({ type: "openMenu", newPassword: isNewPassword(field), form: isLoginField(field) ? null : formKind(field) });
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
      // Drop-downs (country, expiry month) are filled with the rest.
      const form = isLoginField(field) || field instanceof HTMLSelectElement ? null : formKind(field);
      if (!form && !isLoginField(field)) return;
      if (field !== lastField) closeMenu();
      lastField = field;
      const how = await send({ type: "field", form });
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
      case "fillForm":
        respond(fillForm(msg.data ?? {}));
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
