// Talking to VaultRust and filling in forms; shared by the popup and the
// background worker.
//
// The browser starts VaultRust.exe as a "native messaging host" for each
// message; it passes the message on to the running VaultRust app, which
// answers only if this browser was approved there (the token below) and the
// vault is unlocked. Passwords are never stored by the extension.

export const HOST = "com.vaultrust.browser";

export const t = (key, ...subs) => chrome.i18n.getMessage(key, subs) || key;

/// This browser's pairing token: random, created once, kept in the
/// extension's local storage. VaultRust stores only its SHA-256.
export async function token() {
  const { token } = await chrome.storage.local.get("token");
  if (token) return token;
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const fresh = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  await chrome.storage.local.set({ token: fresh });
  return fresh;
}

/// The six-digit code VaultRust shows when this browser asks to connect, so
/// the user can check both sides belong together.
export async function pairingCode() {
  const data = new TextEncoder().encode(await token());
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  const n = ((h[0] << 16) | (h[1] << 8) | h[2]) % 1000000;
  const s = String(n).padStart(6, "0");
  return `${s.slice(0, 3)} ${s.slice(3)}`;
}

/// Send one request to VaultRust. Always resolves: failures come back as
/// `{ error: "..." }`.
export async function ask(message) {
  try {
    const reply = await chrome.runtime.sendNativeMessage(HOST, {
      v: 1,
      token: await token(),
      ...message,
    });
    return reply ?? { error: "no_reply" };
  } catch (e) {
    const text = String(e?.message ?? e);
    // The helper isn't registered for this browser (or was removed).
    if (/not found|forbidden/i.test(text)) return { error: "no_host" };
    return { error: "no_reply" };
  }
}

export function browserName() {
  const brands = navigator.userAgentData?.brands?.map((b) => b.brand) ?? [];
  for (const name of ["Microsoft Edge", "Brave", "Opera", "Vivaldi", "Google Chrome"]) {
    if (brands.includes(name)) return name.replace("Google ", "");
  }
  return "Chromium";
}

/// The active tab, if it shows a web page.
export async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:/i.test(tab.url)) return null;
  return tab;
}

/// Ask VaultRust for the login `id` on the tab's site and fill it in.
/// Returns null on success, or an error code.
export async function fill(tab, id) {
  const reply = await ask({ type: "fill", url: tab.url, id });
  if (reply.error) return reply.error;
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillPage,
      args: [reply.host, reply.username ?? "", reply.password ?? "", reply.code ?? ""],
    });
    return result?.result?.filled ? null : "no_form";
  } catch {
    return "no_form";
  }
}

// Runs inside the page. Must not use anything from outside the function.
function fillPage(host, username, password, code) {
  const here = location.hostname.toLowerCase().replace(/^www\./, "");
  // The tab may have moved on to another site since VaultRust checked it.
  if (here !== host) return { filled: false };

  const usable = (el) => {
    if (el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
  };
  const set = (el, value) => {
    el.focus();
    // Through the prototype's setter, so frameworks (React…) notice.
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const attrs = (el) => `${el.name} ${el.id} ${el.autocomplete} ${el.placeholder}`.toLowerCase();
  const textual = (el) => ["text", "email", "tel", ""].includes(el.type);

  const inputs = [...document.querySelectorAll("input")].filter(usable);
  const passwords = inputs.filter(
    (el) => el.type === "password" && !/new-password/.test(el.autocomplete),
  );
  let filled = 0;

  if (passwords.length && password) {
    const pw = passwords[0];
    // The username is the last text field before the password, preferably
    // in the same form.
    const before = inputs.filter(
      (el) => textual(el) && pw.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_PRECEDING,
    );
    const sameForm = before.filter((el) => el.form && el.form === pw.form);
    const user = (sameForm.length ? sameForm : before).at(-1);
    if (user && username) {
      set(user, username);
      filled++;
    }
    set(pw, password);
    filled++;
    return { filled };
  }

  // A page asking only for the one-time code.
  const otp = inputs.find(
    (el) =>
      ["text", "tel", "number", ""].includes(el.type) &&
      (/one-time-code/.test(el.autocomplete) ||
        /\b(otp|totp|2fa|mfa|one.?time|verification.?code|auth.?code)\b/.test(attrs(el))),
  );
  if (otp && code) {
    set(otp, code);
    return { filled: 1 };
  }

  // The first page of a two-step login: only the username.
  const user =
    inputs.find((el) => textual(el) && /username|email/.test(el.autocomplete)) ??
    inputs.find((el) => el.type === "email") ??
    inputs.find((el) => textual(el) && /user|login|email|account|identifier/.test(attrs(el)));
  if (user && username) {
    set(user, username);
    filled++;
  }
  return { filled };
}
