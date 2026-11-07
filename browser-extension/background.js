// The extension's background worker: the only part that talks to VaultRust.
//
// The browser starts VaultRust.exe as a "native messaging host" and keeps
// it running while this worker is connected; it passes each message on to
// the running VaultRust app, which answers only if this browser was
// approved there (the token below) and the vault is unlocked. The pages and
// the script in each web page talk to this worker, never to VaultRust.
//
// Nothing from the vault is stored here. A password the user just signed in
// with is kept in memory (session storage) until they choose to save it or
// not, for at most a few minutes.

const HOST = "com.vaultrust.browser";
const ANSWER_TIMEOUT = 8000;
const PENDING_FOR = 3 * 60 * 1000;

// --- Talking to VaultRust ---------------------------------------------------

/// The connection to the helper; answers come back in order.
let link = null;

function connect() {
  const port = chrome.runtime.connectNative(HOST);
  const conn = { port, queue: [], closed: false };
  port.onMessage.addListener((msg) => conn.queue.shift()?.(msg));
  port.onDisconnect.addListener(() => {
    const why = chrome.runtime.lastError?.message ?? "";
    // The helper isn't registered for this browser (or was removed).
    const error = /not found|forbidden|access/i.test(why) ? "no_host" : "no_reply";
    conn.closed = true;
    for (const answer of conn.queue.splice(0)) answer({ error });
    if (link === conn) link = null;
  });
  return conn;
}

async function token() {
  const { token } = await chrome.storage.local.get("token");
  if (token) return token;
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const fresh = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  await chrome.storage.local.set({ token: fresh });
  return fresh;
}

/// Send one request to VaultRust. Always resolves: failures come back as
/// `{ error: "..." }`.
async function ask(message) {
  const tok = await token();
  if (!link || link.closed) link = connect();
  const conn = link;
  return new Promise((resolve) => {
    let done = false;
    const answer = (reply) => {
      if (done) return;
      done = true;
      resolve(reply ?? { error: "no_reply" });
    };
    conn.queue.push(answer);
    try {
      conn.port.postMessage({ v: 1, token: tok, ...message });
    } catch {
      conn.closed = true;
      answer({ error: "no_reply" });
    }
    setTimeout(() => {
      if (done) return;
      // Out of step now: start again with a fresh connection.
      answer({ error: "no_reply" });
      conn.closed = true;
      try {
        conn.port.disconnect();
      } catch {}
      if (link === conn) link = null;
    }, ANSWER_TIMEOUT);
  });
}

// --- Helpers ----------------------------------------------------------------

const isWeb = (url) => /^https?:/i.test(url ?? "");
const hostOf = (url) => {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
};

/// Ask the script in a frame to do something; inject it first into pages
/// that were open before the extension was installed.
async function toFrame(tabId, frameId, message) {
  try {
    return await chrome.tabs.sendMessage(tabId, message, { frameId });
  } catch {
    try {
      await chrome.scripting.executeScript({ target: { tabId, frameIds: [frameId] }, files: ["content.js"] });
      return await chrome.tabs.sendMessage(tabId, message, { frameId });
    } catch {
      return null;
    }
  }
}

/// Fill login `id` into a frame of a tab. VaultRust checks again that the
/// login belongs to the frame's site. Returns null or an error code.
async function fill(tabId, frameId, url, id) {
  const reply = await ask({ type: "fill", url, id });
  if (reply.error) return reply.error;
  const done = await toFrame(tabId, frameId, {
    type: "fill",
    host: reply.host,
    username: reply.username ?? "",
    password: reply.password ?? "",
    code: reply.code ?? "",
  });
  updateBadge(tabId);
  return done?.filled ? null : "no_form";
}

// --- The toolbar badge: how many logins the current site has ---------------

const counts = new Map();
let lastState = "unknown";

async function updateBadge(tabId) {
  let tab;
  try {
    tab = await chrome.tabs.get(tabId);
  } catch {
    return;
  }
  let text = "";
  if (isWeb(tab.url)) {
    const reply = await ask({ type: "logins", url: tab.url });
    lastState = reply.error ?? "unlocked";
    const n = reply.logins?.length ?? 0;
    counts.set(tabId, n);
    text = n ? String(n) : "";
  } else {
    counts.set(tabId, 0);
  }
  chrome.action.setBadgeText({ tabId, text }).catch(() => {});
}

chrome.action.setBadgeBackgroundColor({ color: "#237f58" }).catch(() => {});
chrome.tabs.onActivated.addListener(({ tabId }) => updateBadge(tabId));
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "complete") updateBadge(tabId);
});
chrome.tabs.onRemoved.addListener((tabId) => {
  counts.delete(tabId);
  menus.delete(tabId);
  chrome.storage.session.remove(`pending:${tabId}`);
});

// Pages open before the extension was installed get its script too.
chrome.runtime.onInstalled.addListener(async () => {
  for (const tab of await chrome.tabs.query({ url: ["http://*/*", "https://*/*"] })) {
    chrome.scripting
      .executeScript({ target: { tabId: tab.id, allFrames: true }, files: ["content.js"] })
      .catch(() => {});
  }
});

// --- The menu in login fields -----------------------------------------------

/// Per tab: the frame whose field the menu belongs to.
const menus = new Map();

async function menuData(tabId) {
  const m = menus.get(tabId);
  if (!m) return { error: "no_reply" };
  const reply = await ask({ type: "logins", url: m.url });
  return { ...reply, host: hostOf(m.url), newPassword: m.newPassword };
}

// --- Offering to save a login -------------------------------------------------

async function neverFor(host) {
  const { never = [] } = await chrome.storage.local.get("never");
  return never.includes(host);
}

async function pending(tabId) {
  const key = `pending:${tabId}`;
  const p = (await chrome.storage.session.get(key))[key];
  if (p && Date.now() - p.time < PENDING_FOR) return p;
  if (p) chrome.storage.session.remove(key);
  return null;
}

/// The user submitted a login form: offer to save the login if VaultRust
/// doesn't have it yet (or has another password for it).
async function captured(tab, frameUrl, username, password) {
  const host = hostOf(frameUrl);
  if (!password || !host || (await neverFor(host))) return;
  if (!username) {
    // The first page of a two-step login asked for it.
    const remembered = (await chrome.storage.session.get(`user:${tab.id}`))[`user:${tab.id}`];
    if (remembered?.host === host && Date.now() - remembered.time < PENDING_FOR) username = remembered.value;
  }
  const check = await ask({ type: "check", url: frameUrl, username, password });
  let state = check.state;
  if (check.error === "locked") state = "locked";
  if (state !== "new" && state !== "update" && state !== "locked") return;
  await chrome.storage.session.set({
    [`pending:${tab.id}`]: {
      url: frameUrl,
      host,
      username,
      password,
      state,
      id: check.id ?? "",
      title: check.title ?? "",
      time: Date.now(),
    },
  });
  // Pages that stay put (no new page loads) show the bar right away.
  setTimeout(() => toFrame(tab.id, 0, { type: "showBar" }), 600);
}

async function saveCaptured(tabId) {
  const p = await pending(tabId);
  if (!p) return { error: "not_found" };
  let { id } = p;
  if (p.state === "locked") {
    // Unlocked since: find out whether it's new after all.
    const check = await ask({ type: "check", url: p.url, username: p.username, password: p.password });
    if (check.error) return check;
    if (check.state === "same") {
      chrome.storage.session.remove(`pending:${tabId}`);
      return { ok: true };
    }
    id = check.id ?? "";
  }
  const reply = await ask({ type: "save", url: p.url, username: p.username, password: p.password, id });
  if (!reply.error) {
    chrome.storage.session.remove(`pending:${tabId}`);
    updateBadge(tabId);
  }
  return reply;
}

// --- Messages from the pages and the web page script --------------------------

const own = (sender) => sender.id === chrome.runtime.id && sender.url?.startsWith(chrome.runtime.getURL(""));
const ownPage = (sender, page) => own(sender) && new URL(sender.url).pathname === `/${page}`;

chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  handle(msg, sender).then(respond, () => respond({ error: "no_reply" }));
  return true;
});

async function handle(msg, sender) {
  const tabId = sender.tab?.id;

  // The popup: any request, about the tab it was opened on.
  if (ownPage(sender, "popup.html")) {
    switch (msg.type) {
      case "ask":
        return ask(msg.request);
      case "fillTab": {
        const tab = await chrome.tabs.get(msg.tabId);
        return { error: await fill(tab.id, 0, tab.url, msg.id) };
      }
      case "fillPassword":
        return (await toFrame(msg.tabId, 0, { type: "fillPassword", password: msg.password })) ?? { filled: 0 };
      case "refresh":
        updateBadge(msg.tabId);
        return {};
    }
    return { error: "bad_request" };
  }

  // The menu shown under a login field.
  if (ownPage(sender, "menu.html") && tabId !== undefined) {
    const m = menus.get(tabId);
    switch (msg.type) {
      case "menuData":
        return menuData(tabId);
      case "menuFill":
        if (!m) return { error: "no_reply" };
        toFrame(tabId, m.frameId, { type: "closeMenu" });
        return { error: await fill(tabId, m.frameId, m.url, msg.id) };
      case "menuGenerate": {
        if (!m) return { error: "no_reply" };
        const reply = await ask({ type: "generate", url: m.url });
        if (reply.error) return reply;
        await toFrame(tabId, m.frameId, { type: "fillPassword", password: reply.password });
        toFrame(tabId, m.frameId, { type: "closeMenu" });
        return {};
      }
      case "menuShow":
        return ask({ type: "show" });
      case "menuNew":
        if (m) toFrame(tabId, m.frameId, { type: "closeMenu" });
        return ask({ type: "new", url: m?.url ?? "" });
      case "menuSize":
        if (m) toFrame(tabId, m.frameId, { type: "menuSize", height: msg.height });
        return {};
      case "menuClose":
        if (m) toFrame(tabId, m.frameId, { type: "closeMenu" });
        return {};
    }
    return { error: "bad_request" };
  }

  // The bar offering to save a login.
  if (ownPage(sender, "bar.html") && tabId !== undefined) {
    switch (msg.type) {
      case "barData": {
        const p = await pending(tabId);
        return p ? { state: p.state, host: p.host, username: p.username, title: p.title } : { error: "not_found" };
      }
      case "barSave": {
        const reply = await saveCaptured(tabId);
        if (reply.error === "locked") ask({ type: "show" });
        return reply;
      }
      case "barNever": {
        const p = await pending(tabId);
        if (p) {
          const { never = [] } = await chrome.storage.local.get("never");
          await chrome.storage.local.set({ never: [...new Set([...never, p.host])] });
        }
        chrome.storage.session.remove(`pending:${tabId}`);
        toFrame(tabId, 0, { type: "closeBar" });
        return {};
      }
      case "barClose":
        chrome.storage.session.remove(`pending:${tabId}`);
        toFrame(tabId, 0, { type: "closeBar" });
        return {};
      case "barSize":
        toFrame(tabId, 0, { type: "barSize", height: msg.height });
        return {};
    }
    return { error: "bad_request" };
  }

  // The script in web pages: only about its own frame, whose address comes
  // from the browser (sender.url), not from the page.
  if (sender.id === chrome.runtime.id && tabId !== undefined && isWeb(sender.url)) {
    switch (msg.type) {
      case "field":
        // A login field got focus: show the icon (if VaultRust is set up)
        // and open the menu straight away when the site has logins.
        return {
          icon: lastState === "unlocked" || lastState === "locked" || lastState === "unknown",
          open: lastState === "unlocked" && (counts.get(tabId) ?? 0) > 0 && hostOf(sender.url) !== "",
        };
      case "openMenu":
        menus.set(tabId, { frameId: sender.frameId, url: sender.url, newPassword: !!msg.newPassword });
        return {};
      case "captured":
        captured(sender.tab, sender.url, msg.username ?? "", msg.password ?? "");
        return {};
      case "username":
        if (msg.value) {
          chrome.storage.session.set({
            [`user:${tabId}`]: { host: hostOf(sender.url), value: msg.value, time: Date.now() },
          });
        }
        return {};
      case "ready":
        if (sender.frameId !== 0) return {};
        return { showBar: !!(await pending(tabId)) };
    }
  }
  return { error: "bad_request" };
}

// --- The fill shortcut ------------------------------------------------------------

// Alt+Shift+L: fill the most recently used login for the site; anything
// that needs a choice or an answer opens the popup instead.
chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "fill-login") return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !isWeb(tab.url)) return;
  const reply = await ask({ type: "logins", url: tab.url });
  const first = reply.logins?.[0];
  if (first && !(await fill(tab.id, 0, tab.url, first.id))) return;
  try {
    await chrome.action.openPopup();
  } catch {
    // Older browsers can't open the popup from here.
  }
});
