(() => {
  const BANNER_ID = "certi-banner";
  let lastSignature = "";
  let observer = null;
  let scanEnabled = true;

  /* ===============================
     SETTINGS
  =============================== */

  // Load setting (default ON)
  chrome.storage.local.get(["certi_scan_enabled"], (res) => {
    scanEnabled = (typeof res.certi_scan_enabled === "boolean")
      ? res.certi_scan_enabled
      : true;

    if (scanEnabled) boot();
  });

  chrome.storage.onChanged.addListener((changes) => {
    if ("certi_scan_enabled" in changes) {
      scanEnabled = !!changes.certi_scan_enabled.newValue;
      if (scanEnabled) boot();
      else removeBanner();
    }
  });

  /* ===============================
     BOOTSTRAP
  =============================== */
  function boot() {
    if (observer) return;

    observer = new MutationObserver(throttle(() => {
      if (!scanEnabled) return;

      const data = extractGmailEmailData();
      if (!data) return;

      const sig = makeSignature(data);
      if (sig === lastSignature) return;
      lastSignature = sig;

      runScanAndRender(data);
    }, 700));

    observer.observe(document.body, { childList: true, subtree: true });
  }

  function makeSignature(data) {
    return [
      data.subject,
      data.senderEmail,
      data.senderName,
      data.links.length
    ].join("|");
  }

  function runScanAndRender(data) {
    if (!window.CertiScan?.analyze) return;

    const res = window.CertiScan.analyze(data);
    if (!res?.ok) return;

    injectOrUpdateBanner(res, data);
  }

  /* ===============================
     EXTRACTION HELPERS (GMAIL DOM)
  =============================== */
  function extractGmailEmailData() {
    // Subject
    const subjectEl = document.querySelector("h2.hP") || document.querySelector(".ha h2");
    const subject = subjectEl ? subjectEl.textContent.trim() : "";

    // Sender
    const fromNameEl = document.querySelector("span.gD") || document.querySelector(".go span[email]");
    const senderName = fromNameEl
      ? (fromNameEl.getAttribute("name") || fromNameEl.textContent || "").trim()
      : "";

    let senderEmail = "";
    if (fromNameEl) {
      senderEmail =
        (fromNameEl.getAttribute("email") ||
         fromNameEl.getAttribute("data-hovercard-id") ||
         "").trim();
    }

    // Body
    const bodies = Array.from(document.querySelectorAll("div.a3s"));
    const visibleBodies = bodies.filter(el => el.offsetParent !== null);
    const bodyRoot = visibleBodies[visibleBodies.length - 1] || visibleBodies[0] || null;

    if (!subject && !senderEmail && !bodyRoot) return null;

    const bodyText = bodyRoot
      ? (bodyRoot.innerText || "").trim().slice(0, 5000)
      : "";

    const links = bodyRoot
      ? Array.from(bodyRoot.querySelectorAll("a[href]"))
          .map(a => a.getAttribute("href") || "")
          .filter(Boolean)
          .slice(0, 60)
      : [];

    return { senderName, senderEmail, subject, bodyText, links };
  }

  /* ===============================
     BANNER INJECTION
  =============================== */
  function injectOrUpdateBanner(scanRes, data) {
    const mount = findBannerMount();
    if (!mount) return;

    let banner = document.getElementById(BANNER_ID);
    if (!banner) {
      banner = document.createElement("div");
      banner.id = BANNER_ID;
      mount.prepend(banner);
    }

    banner.dataset.level = scanRes.level;

    const badgeText =
      scanRes.level === "safe" ? "🟢 Likely Safe" :
      scanRes.level === "caution" ? "🟡 Caution" :
      "🔴 High Risk";

    const reasons = (scanRes.findings || []).slice(0, 3);

banner.innerHTML = `
    <div class="certi-title-stack">
      <div class="certi-title">Certimailer Passive Scan</div>
      <div class="certi-badge">
        ${badgeText} · Score ${scanRes.score}/100
      </div>
    </div>
  </div>

  <div class="certi-body">
    ${reasons.length ? `
      <div><b>Reasons:</b></div>
      <ul>
        ${reasons.map(r => `<li>${escapeHtml(r.title)}</li>`).join("")}
      </ul>
    ` : `<div><b>Reasons:</b> No obvious red flags detected.</div>`}

    <div class="certi-actions">
      <button type="button" id="certi-open" class="primary">
        Open Certimailer report
      </button>
      <button type="button" id="certi-dismiss" class="secondary">
        Dismiss
      </button>
    </div>
  </div>
`;


    /* ===============================
       OPEN REPORT HANDLER
    =============================== */
    banner.querySelector("#certi-open")?.addEventListener("click", () => {

      const payload = {
        source: "gmail",
        scannedAt: Date.now(),
        scan: scanRes,
        emailContext: {
          senderName: data.senderName,
          senderEmail: data.senderEmail,
          subject: data.subject,
          links: data.links.slice(0, 30)
        }
      };

      // Save scan so popup.js can load it
      chrome.storage.local.set({ certi_last_scan: payload }, () => {

        // 1️⃣ Try to open EXTENSION POPUP (preferred UX)
        chrome.runtime.sendMessage({ type: "CERTI_OPEN_POPUP" }, (reply) => {

          // 2️⃣ Fallback: open popup.html in tab if Chrome blocks popup
          if (!reply?.ok) {
            chrome.runtime.sendMessage({ type: "CERTI_OPEN_REPORT_TAB" });
          }

        });
      });
    });

    banner.querySelector("#certi-dismiss")?.addEventListener("click", () => {
      removeBanner();
    });
  }

  function findBannerMount() {
    // Near subject line
    const subjectEl = document.querySelector("h2.hP");
    if (subjectEl && subjectEl.parentElement) return subjectEl.parentElement;

    // Fallback
    const pane =
      document.querySelector("div.nH.oy8Mbf") ||
      document.querySelector("div.nH.aHU") ||
      document.body;

    return pane || null;
  }

  function removeBanner() {
    const banner = document.getElementById(BANNER_ID);
    if (banner) banner.remove();
  }

  /* ===============================
     UTILS
  =============================== */
  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function throttle(fn, ms) {
    let t = 0;
    let timer = null;
    return (...args) => {
      const now = Date.now();
      if (now - t >= ms) {
        t = now;
        fn(...args);
      } else {
        clearTimeout(timer);
        timer = setTimeout(() => {
          t = Date.now();
          fn(...args);
        }, ms);
      }
    };
  }

})();
