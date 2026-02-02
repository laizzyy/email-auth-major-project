chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  /* ===============================
     Open extension popup
  =============================== */
  if (msg?.type === "CERTI_OPEN_POPUP") {
    const windowId = sender?.tab?.windowId;

    // Try to open toolbar popup
    chrome.action.openPopup(windowId ? { windowId } : undefined)
      .then(() => sendResponse({ ok: true, opened: "popup" }))
      .catch(() => {
        // Fallback → open popup.html in tab
        chrome.tabs.create(
          { url: chrome.runtime.getURL("popup.html"), active: true },
          () => sendResponse({ ok: true, opened: "tab" })
        );
      });

    return true; // async response
  }

  /* ===============================
     Fallback: open report tab directly
  =============================== */
  if (msg?.type === "CERTI_OPEN_REPORT_TAB") {
    chrome.tabs.create(
      { url: chrome.runtime.getURL("popup.html"), active: true },
      () => sendResponse?.({ ok: true })
    );
    return true;
  }

});
