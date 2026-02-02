/* js/analyzer-core.js
   Certimailer Header Analyzer Core (no DOM)
   Usage: const report = window.CertiHeaderAnalyzer.buildReport(rawHeaderText);
*/
(() => {
  const MAX_INPUT_CHARS = 400_000; // prevent freezing on huge .eml

  function normalizeRaw(raw) {
    if (!raw) return "";
    let s = String(raw);
    if (s.length > MAX_INPUT_CHARS) s = s.slice(0, MAX_INPUT_CHARS);
    return s.replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim();
  }

  // Unfold header lines: continuation lines start with space/tab
  function unfoldHeaders(text) {
    return text.replace(/\n[ \t]+/g, " ");
  }

  // Parse into { "header-name": [values...] }
  function parseToMap(raw) {
    const text = unfoldHeaders(normalizeRaw(raw));
    const lines = text.split("\n");

    const map = Object.create(null);
    for (const line of lines) {
      // stop if we hit empty line (header/body separator in .eml)
      if (!line.trim()) break;

      const idx = line.indexOf(":");
      if (idx <= 0) continue;

      const key = line.slice(0, idx).trim().toLowerCase();
      const val = line.slice(idx + 1).trim();

      if (!map[key]) map[key] = [];
      map[key].push(val);
    }
    return map;
  }

  function first(map, name) {
    const arr = map[name];
    return arr && arr.length ? arr[0] : null;
  }

  function all(map, name) {
    return map[name] ? [...map[name]] : [];
  }

  function extractAuthResult(authResultsRaw, type) {
    // looks for spf=pass/fail/none/neutral/softfail etc.
    const re = new RegExp(`${type}\\s*=\\s*([a-z]+)`, "i");
    const m = authResultsRaw.match(re);
    return m ? m[1].toLowerCase() : "none";
  }

  function pickAuthResults(map) {
    // some emails have multiple Authentication-Results headers
    const arr = all(map, "authentication-results");
    return arr.join(" | ");
  }

  function emailFromHeaderValue(v) {
    // extract email address from "Name <email@domain>" or plain
    const m = String(v || "").match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i);
    return m ? m[0].toLowerCase() : null;
  }

  function domainOfEmail(email) {
    const at = email ? email.lastIndexOf("@") : -1;
    return at > 0 ? email.slice(at + 1).toLowerCase() : null;
  }

  function calculateScore({ spf, dkim, dmarc, replyTo, from }) {
    // Your current logic starts from 50 and adjusts :contentReference[oaicite:2]{index=2}
    let score = 50;

    if (spf === "pass") score += 15;
    else if (spf === "fail") score -= 15;

    if (dkim === "pass") score += 15;
    else if (dkim === "fail") score -= 15;

    if (dmarc === "pass") score += 20;
    else if (dmarc === "fail") score -= 20;

    // Reply-To mismatch penalty (more correct domain-based check)
    const fromEmail = emailFromHeaderValue(from);
    const replyEmail = emailFromHeaderValue(replyTo);
    if (replyEmail && fromEmail) {
      if (domainOfEmail(replyEmail) !== domainOfEmail(fromEmail)) score -= 10;
    }

    return Math.max(0, Math.min(100, score));
  }

  function verdictFromScore(score) {
    if (score >= 80) return { label: "Likely Legitimate", level: "low" };
    if (score >= 50) return { label: "Suspicious", level: "medium" };
    return { label: "High Risk", level: "high" };
  }

  function buildFindings({ spf, dkim, dmarc, replyTo, from, messageId, returnPath }) {
    const findings = [];

    if (spf !== "pass") findings.push({
      id: "SPF_ISSUE", severity: spf === "fail" ? "high" : "medium",
      title: "SPF Issues", detail: "Sender IP not authorized or SPF missing."
    });

    if (dkim !== "pass") findings.push({
      id: "DKIM_ISSUE", severity: dkim === "fail" ? "high" : "medium",
      title: "DKIM Issues", detail: "Signature invalid or missing."
    });

    if (dmarc === "fail") findings.push({
      id: "DMARC_FAIL", severity: "high",
      title: "DMARC Fail", detail: "DMARC alignment/policy evaluation failed."
    });

    const fromEmail = emailFromHeaderValue(from);
    const replyEmail = emailFromHeaderValue(replyTo);
    if (replyEmail && fromEmail && domainOfEmail(replyEmail) !== domainOfEmail(fromEmail)) {
      findings.push({
        id: "REPLYTO_MISMATCH", severity: "medium",
        title: "Reply-To Mismatch", detail: "Reply address domain differs from sender domain."
      });
    }

    const rpEmail = emailFromHeaderValue(returnPath);
    if (rpEmail && fromEmail && domainOfEmail(rpEmail) !== domainOfEmail(fromEmail)) {
      findings.push({
        id: "RETURNPATH_MISMATCH", severity: "medium",
        title: "Return-Path Mismatch", detail: "Return-Path domain differs from From domain."
      });
    }

    if (!messageId) {
      findings.push({
        id: "MISSING_MESSAGE_ID", severity: "low",
        title: "Missing Message-ID", detail: "Some phishing emails omit Message-ID (not always malicious)."
      });
    }

    if (!findings.length) {
      findings.push({
        id: "NO_CRITICAL_ISSUES", severity: "low",
        title: "No Critical Issues", detail: "Authentication looks good."
      });
    }

    return findings;
  }

  function buildReport(rawHeaderText) {
    const map = parseToMap(rawHeaderText);

    const authResults = pickAuthResults(map);
    const from = first(map, "from") || "Unknown";
    const to = first(map, "to") || "Unknown";
    const subject = first(map, "subject") || "(No Subject)";
    const date = first(map, "date") || "Unknown";
    const returnPath = first(map, "return-path");
    const replyTo = first(map, "reply-to");
    const messageId = first(map, "message-id");
    const received = all(map, "received"); // keep all hops

    const spf = extractAuthResult(authResults, "spf");
    const dkim = extractAuthResult(authResults, "dkim");
    const dmarc = extractAuthResult(authResults, "dmarc");

    const score = calculateScore({ spf, dkim, dmarc, replyTo, from });
    const verdict = verdictFromScore(score);

    const findings = buildFindings({ spf, dkim, dmarc, replyTo, from, messageId, returnPath });

    return {
      ok: true,
      fields: { from, to, subject, date, returnPath, replyTo, messageId, received },
      auth: { spf, dkim, dmarc, authenticationResults: authResults || null },
      score,
      verdict,
      findings
    };
  }

  window.CertiHeaderAnalyzer = { buildReport };
})();
