(() => {
  const done = (payload) => {
    chrome.storage.local.set({
      certi_last_header_fetch: {
        pending: false,
        fetchedAt: Date.now(),
        ...payload
      }
    });
  };

  const pre = document.querySelector("pre");
  if (!pre) return done({ ok: false, error: "No <pre> found on Show original page." });

  const raw = (pre.innerText || "").trim();
  if (!raw || raw.length < 80) return done({ ok: false, error: "Header content looks empty." });

  done({ ok: true, rawHeader: raw });
})();
