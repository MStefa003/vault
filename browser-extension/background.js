import { ask, currentTab, fill } from "./vaultrust.js";

// The fill shortcut (Alt+Shift+L by default): fill the most recently used
// login for the site. Anything that needs a choice or an answer (several
// accounts are fine; locked, not connected…) opens the popup instead.
chrome.commands.onCommand.addListener(async (command) => {
  if (command !== "fill-login") return;
  const tab = await currentTab();
  if (!tab) return;
  const reply = await ask({ type: "logins", url: tab.url });
  const first = reply.logins?.[0];
  if (first && !(await fill(tab, first.id))) return;
  try {
    await chrome.action.openPopup();
  } catch {
    // Older browsers can't open the popup from here.
  }
});
