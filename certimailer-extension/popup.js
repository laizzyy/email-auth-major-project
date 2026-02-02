document.addEventListener("DOMContentLoaded", () => {

  /* ===============================
     ELEMENTS
  =============================== */
  const raw = document.getElementById("raw");
  const analyzeBtn = document.getElementById("analyze");
  const clearBtn = document.getElementById("clearBtn");
  const sampleBtn = document.getElementById("sampleBtn");
  const exportBtn = document.getElementById("exportBtn");
  const homeBtn = document.getElementById("homeBtn");


  const results = document.getElementById("results");
  const actionPanel = document.getElementById("actionPanel");

  // Modes
  const modeQuick = document.getElementById("modeQuick");
  const modeGuided = document.getElementById("modeGuided");
  const modeAdvanced = document.getElementById("modeAdvanced");
  const guidedPanel = document.getElementById("guidedPanel");

  // Guided checkboxes
  const gUnexpected = document.getElementById("gUnexpected");
  const gUrgent = document.getElementById("gUrgent");
  const gLinkOrFile = document.getElementById("gLinkOrFile");
  const gSensitive = document.getElementById("gSensitive");

  // Advanced (technical)
  const advCollapse = document.getElementById("advancedCollapse");
  const toggleAdvanced = document.getElementById("toggleAdvanced");

  // Error box
  const errorBox = document.getElementById("errorBox");
  const errorText = document.getElementById("errorText");
  const errorTip = document.getElementById("errorTip");

  // Optional fetch UI
  const fetchHeadersBtn = document.getElementById("fetchHeadersBtn");
  const fetchStatus = document.getElementById("fetchStatus");

  let lastExportPayload = null;

  if (!raw || !analyzeBtn || !results) {
    console.error("Popup missing required elements");
    return;
  }

  /* ===============================
     STATE
  =============================== */
  const LS_MODE = "certi_mode";
  let currentMode = loadMode();
  applyModeUI(currentMode);

  /* ===============================
     PASSIVE SCAN AUTO LOAD
  =============================== */
  chrome.storage.local.get(["certi_last_scan"], (res) => {
    const last = res.certi_last_scan;
    if (!last || last.source !== "gmail") return;
    renderPassiveScanReport(last);
  });

  /* ===============================
     EVENTS
  =============================== */
  analyzeBtn.addEventListener("click", () => {
    hideError();
    if (currentMode === "guided") runGuidedCheck();
    else runHeaderCheck(); // quick + advanced share same engine
  });

  clearBtn?.addEventListener("click", () => {
    raw.value = "";
    results.style.display = "none";
    lastExportPayload = null;
    hideError();

    // reset guided
    if (gUnexpected) gUnexpected.checked = false;
    if (gUrgent) gUrgent.checked = false;
    if (gLinkOrFile) gLinkOrFile.checked = false;
    if (gSensitive) gSensitive.checked = false;

    applyModeUI(currentMode);
  });

  homeBtn?.addEventListener("click", () => {
  chrome.tabs.create({ url: "https://YOUR-WEBSITE-URL-HERE", active: true });
  });


  sampleBtn?.addEventListener("click", () => {
    raw.value = SAMPLE_HEADER;
    hideError();
  });

  exportBtn?.addEventListener("click", () => {
    if (!lastExportPayload) {
      showError("Nothing to export.", "Run a check first.");
      return;
    }
    exportPDF(lastExportPayload, `certimailer-report-${new Date().toISOString().slice(0,10)}.pdf`);
  });

  // Mode switching
  modeQuick?.addEventListener("click", () => setMode("quick"));
  modeGuided?.addEventListener("click", () => setMode("guided"));
  modeAdvanced?.addEventListener("click", () => setMode("advanced"));

  toggleAdvanced?.addEventListener("click", () => {
    if (!advCollapse) return;
    const open = advCollapse.getAttribute("aria-expanded") === "true";
    advCollapse.setAttribute("aria-expanded", open ? "false" : "true");
  });

  /* ===============================
     MODE CONTROL
  =============================== */
  function setMode(mode) {
    currentMode = mode;
    localStorage.setItem(LS_MODE, mode);
    applyModeUI(mode);
  }

  function applyModeUI(mode) {
    // button states
    modeQuick?.setAttribute("aria-pressed", mode === "quick");
    modeGuided?.setAttribute("aria-pressed", mode === "guided");
    modeAdvanced?.setAttribute("aria-pressed", mode === "advanced");

    // guided panel
    if (guidedPanel) guidedPanel.style.display = (mode === "guided") ? "block" : "none";

    // mark mode on body for CSS gating
    document.body.dataset.mode = mode;

    // technical visibility
    if (advCollapse) {
      if (mode === "advanced") {
        advCollapse.style.display = "block";
        advCollapse.setAttribute("aria-expanded", "true");
      } else {
        advCollapse.style.display = "none";
        advCollapse.setAttribute("aria-expanded", "false");
      }
    }
  }

  function loadMode() {
    const m = localStorage.getItem(LS_MODE);
    return (m === "guided" || m === "advanced") ? m : "quick";
  }

  /* ===============================
     VALIDATION
  =============================== */
  function isValidHeader(text) {
    const required = /(From:|Return-Path:|Received:|Message-ID:|Authentication-Results:)/i;
    return required.test(text);
  }

  /* ===============================
     HEADER CHECK (Quick + Advanced)
  =============================== */
  function runHeaderCheck() {
    const text = (raw.value || "").trim();
    if (!text) return showError("No input.", "Paste a full email header first.");

    if (!isValidHeader(text)) {
      return showError(
        "Invalid header format.",
        "Gmail: Open email → ⋮ → Show original → copy headers."
      );
    }

    if (!window.CertiHeaderAnalyzer?.buildReport) {
      return showError("Analyzer not loaded.", "analyzer-core.js missing.");
    }

    const report = window.CertiHeaderAnalyzer.buildReport(text);
    if (!report?.ok) return showError("Analysis failed.", "Unable to parse this header.");

    renderFullReport(report, text);
    applyModeUI(currentMode);
  }

  /* ===============================
     GUIDED CHECK
  =============================== */
  function runGuidedCheck() {
    const flags = [
      gUnexpected?.checked,
      gUrgent?.checked,
      gLinkOrFile?.checked,
      gSensitive?.checked
    ].filter(Boolean).length;

    const base = 100 - flags * 18;
    const score = Math.max(5, Math.min(100, base));

    let level = "low";
    if (score < 50) level = "high";
    else if (score < 80) level = "medium";

    results.style.display = "block";

    setText("trustScore", score);
    setText("verdictTitle",
      level === "low" ? "Low Risk (Guided Check)" :
      level === "medium" ? "Caution (Guided Check)" :
      "High Risk (Guided Check)"
    );

    setText("plainSummary",
      level === "low" ? "No strong social-engineering signals selected." :
      level === "medium" ? "Some risky social-engineering patterns selected." :
      "Multiple high-risk phishing indicators selected."
    );

    renderConfidence(level === "low" ? "high" : level === "medium" ? "medium" : "low");

    renderActions({ verdict: { level } });

    renderFindings([
      gUnexpected?.checked && { title: "Unexpected email", severity: "medium" },
      gUrgent?.checked && { title: "Urgency/pressure language", severity: "medium" },
      gLinkOrFile?.checked && { title: "Link/file request", severity: "medium" },
      gSensitive?.checked && { title: "Sensitive data request", severity: "high" }
    ].filter(Boolean));

    lastExportPayload = buildGuidedExport(score, level);
    if (exportBtn) exportBtn.disabled = false;

    applyModeUI("guided");
  }

  /* ===============================
     FULL REPORT RENDER
  =============================== */
  function renderFullReport(report, text) {
    results.style.display = "block";
    hideError();

    setText("trustScore", report.score);
    setText("verdictTitle", report.verdict?.label || "—");
    setText("plainSummary", buildUserSummary(report));

    renderConfidence(report.verdict?.level || "medium");

    renderActions(report);
    renderFindings(report.findings || []);

    // technical data (only visible in advanced mode)
    setStatus("spfStatus", report.auth?.spf);
    setStatus("dkimStatus", report.auth?.dkim);
    setStatus("dmarcStatus", report.auth?.dmarc);

    setText("spfExplain", explainAuth("SPF", report.auth?.spf));
    setText("dkimExplain", explainAuth("DKIM", report.auth?.dkim));
    setText("dmarcExplain", explainAuth("DMARC", report.auth?.dmarc));
    setText("rawHeader", text);

    lastExportPayload = buildFullExport(report, text);
    if (exportBtn) exportBtn.disabled = false;
  }

  /* ===============================
     PASSIVE REPORT
  =============================== */
  function renderPassiveScanReport(last) {
    const scan = last.scan;
    if (!scan) return;

    results.style.display = "block";

    setText("trustScore", scan.score);
    setText("verdictTitle",
      scan.level === "safe" ? "Low Risk (Passive Scan)" :
      scan.level === "caution" ? "Caution (Passive Scan)" :
      "High Risk (Passive Scan)"
    );

    setText("plainSummary",
      scan.level === "safe" ? "No obvious phishing indicators detected." :
      scan.level === "caution" ? "Some phishing indicators detected." :
      "High-risk phishing signals detected."
    );

    renderConfidence("medium");
    renderFindings(scan.findings || []);
    renderActions({ verdict: { level: scan.level === "safe" ? "low" : scan.level === "caution" ? "medium" : "high" } });

    // No technicals in passive
    setText("spfStatus", "—");
    setText("dkimStatus", "—");
    setText("dmarcStatus", "—");
    setText("spfExplain", "Technical verification requires raw headers.");
    setText("dkimExplain", "Technical verification requires raw headers.");
    setText("dmarcExplain", "Technical verification requires raw headers.");
    setText("rawHeader", "");

    lastExportPayload = buildPassiveExport(last);
    if (exportBtn) exportBtn.disabled = false;

    applyModeUI(currentMode);
  }

  /* ===============================
     HELPERS
  =============================== */
  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val ?? "";
  }

  function setStatus(id, status) {
    const el = document.getElementById(id);
    if (!el) return;
    const s = String(status || "none").toLowerCase();
    el.textContent = s.toUpperCase();
    el.className = "status " + (s === "pass" ? "ok" : s === "fail" ? "bad" : "warn");
  }

  function explainAuth(name, status) {
    const s = String(status || "none").toLowerCase();
    if (s === "pass") return `${name} passed authentication.`;
    if (s === "fail") return `${name} failed authentication.`;
    return `${name} not present or neutral.`;
  }

  function buildUserSummary(report) {
    const lvl = report.verdict?.level || "medium";
    if (lvl === "low") return "This email looks legitimate. Still remain cautious.";
    if (lvl === "medium") return "Some trust signals are missing or abnormal.";
    return "High risk indicators detected. Avoid interaction.";
  }

  function renderFindings(findings) {
    const box = document.getElementById("findingsList");
    if (!box) return;

    box.innerHTML = "";

    if (!findings.length) {
      box.innerHTML = `<div class="analysis-card success"><h4>No major red flags</h4></div>`;
      return;
    }

    findings.slice(0, 6).forEach(f => {
      const sev = (f.severity || "low").toLowerCase();
      const type = sev === "high" ? "error" : (sev === "medium" ? "warning" : "success");

      box.innerHTML += `
        <div class="analysis-card ${type}">
          <h4>${escapeHtml(f.title || "Finding")}</h4>
          <p>${escapeHtml(f.detail || "")}</p>
        </div>`;
    });
  }

  function renderActions(report) {
    if (!actionPanel) return;
    const lvl = report.verdict?.level || "medium";

    if (lvl === "low") {
      actionPanel.innerHTML =
        `<div class="analysis-card success"><h4>Safe to proceed</h4><p>Remain cautious with links.</p></div>`;
    } else if (lvl === "medium") {
      actionPanel.innerHTML =
        `<div class="analysis-card warning"><h4>Verify sender</h4><p>Confirm identity before acting.</p></div>`;
    } else {
      actionPanel.innerHTML =
        `<div class="analysis-card error"><h4>Do not interact</h4><p>High phishing risk detected.</p></div>`;
    }
  }

  function renderConfidence(level) {
    const pill = document.getElementById("confidencePill");
    if (!pill) return;
    pill.textContent =
      level === "high" ? "Confidence: High" :
      level === "medium" ? "Confidence: Medium" :
      "Confidence: Low";
  }

  function showError(msg, tip) {
    if (!errorBox) return;
    errorBox.style.display = "block";
    if (errorText) errorText.textContent = msg || "—";
    if (errorTip) errorTip.textContent = tip || "—";
  }

  function hideError() {
    if (!errorBox) return;
    errorBox.style.display = "none";
    if (errorText) errorText.textContent = "—";
    if (errorTip) errorTip.textContent = "—";
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  /* ===============================
     EXPORT
  =============================== */
  function exportPDF(text, filename) {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ orientation: "p", unit: "mm", format: "a4" });

    const margin = 15;
    const width = 210 - margin * 2;
    const lines = doc.splitTextToSize(text, width);

    let y = 15;
    for (const line of lines) {
      if (y > 280) {
        doc.addPage();
        y = 15;
      }
      doc.text(line, margin, y);
      y += 6;
    }

    doc.save(filename);
  }

  function buildFullExport(report, rawHeader) {
    return `
CERTIMAILER REPORT
==================
Score: ${report.score}
Verdict: ${report.verdict?.label}

SPF: ${report.auth?.spf}
DKIM: ${report.auth?.dkim}
DMARC: ${report.auth?.dmarc}

FINDINGS:
${(report.findings || []).map(f => "- " + (f.title || "")).join("\n")}

RAW HEADER:
${rawHeader}
`.trim();
  }

  function buildPassiveExport(last) {
    const scan = last.scan || {};
    const ctx = last.emailContext || {};
    return `
CERTIMAILER PASSIVE SCAN REPORT
==============================
Sender: ${ctx.senderEmail || "—"}
Subject: ${ctx.subject || "—"}
Score: ${scan.score}/100
Risk Level: ${scan.level}

Findings:
${(scan.findings || []).map(f => "- " + (f.title || "")).join("\n")}

Note: Passive scan does not include raw headers.
`.trim();
  }

  function buildGuidedExport(score, level) {
    return `
CERTIMAILER GUIDED CHECK REPORT
==============================
Score: ${score}
Risk Level: ${String(level).toUpperCase()}

User selected risk indicators.

Note: Behavioral risk modelling (not protocol authentication).
`.trim();
  }

  /* ===============================
     SAMPLE
  =============================== */
  const SAMPLE_HEADER = `From: example@paypal.com
Received: by mail.example.com
Authentication-Results: spf=pass dkim=pass dmarc=pass
Subject: Account verification required
Message-ID: <12345@example.com>
Return-Path: <example@paypal.com>`;
});
