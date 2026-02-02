(() => {
  /* ===============================
     CONFIG
  =============================== */

  const SUSPICIOUS_TLDS = [
    "top", "xyz", "tk", "work", "click", "country", "stream", "zip", "mov", "review", "support"
  ];

  const SHORTENERS = new Set([
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"
  ]);

  // Trusted Google services (reduce false positives for calendar/invites/meet)
  const TRUSTED_GOOGLE_HOSTS = new Set([
    "calendar.google.com",
    "meet.google.com",
    "accounts.google.com",
    "mail.google.com"
  ]);

  // Urgency / pressure (social engineering)
  const URGENCY_RE = /\b(urgent|immediately|action required|final notice|account (locked|suspended)|unusual activity|security alert|verify now|respond now|time[- ]limited)\b/i;

  // High-risk sensitive data (explicit credential/financial request)
  const SENSITIVE_HIGH_RE = /\b(otp|one[- ]time password|password|passcode|pin|credit card|cvv|bank account|debit card|security code)\b/i;

  // Medium-risk auth language (can be legit)
  const SENSITIVE_MED_RE = /\b(verify( your)? account|confirm( your)? identity|sign in|login to|authenticate)\b/i;

  /* ===============================
     HELPERS
  =============================== */

  function norm(s) {
    return String(s || "").trim();
  }

  function domainFromEmail(email) {
    const e = norm(email);
    const m = e.match(/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$/);
    return m ? m[1].toLowerCase() : "";
  }

  function hostFromUrl(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  function looksLikeIpHost(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  }

  function getTld(host) {
    const parts = host.split(".");
    return parts.length >= 2 ? parts[parts.length - 1] : "";
  }

  /* ===============================
     ENGINE
  =============================== */

  window.CertiScan = {
    analyze(input) {
      const senderEmail = norm(input.senderEmail);
      const senderName  = norm(input.senderName);
      const subject     = norm(input.subject);
      const bodyText    = norm(input.bodyText);
      const links       = Array.isArray(input.links) ? input.links : [];

      const combinedText = `${subject}\n${bodyText}`;

      const findings = [];
      let riskPoints = 0;

      const add = (severity, title, detail, points) => {
        findings.push({ severity, title, detail });
        riskPoints += points;
      };

      const senderDomain = domainFromEmail(senderEmail);

      /* ===============================
         1) Urgency / pressure
      =============================== */
      if (URGENCY_RE.test(combinedText)) {
        add(
          "medium",
          "Urgency / pressure language",
          "Email uses time pressure or threat language (common in phishing).",
          15
        );
      }

      /* ===============================
         2) Sensitive data requests
      =============================== */
      if (SENSITIVE_HIGH_RE.test(combinedText)) {
        add(
          "high",
          "Requests sensitive data",
          "Mentions OTP, passwords, PINs, or financial details (high-risk phishing signal).",
          30
        );
      } else if (SENSITIVE_MED_RE.test(combinedText)) {
        add(
          "medium",
          "Authentication / verification language",
          "Login/verification language detected. Legit services do this too — verify the domain.",
          10
        );
      }

      /* ===============================
         3) Brand impersonation
      =============================== */
      if (senderName && senderDomain) {
        const n = senderName.toLowerCase();
        const d = senderDomain.toLowerCase();

        const brandish = /(paypal|apple|google|microsoft|amazon|dhl|fedex|dbs|ocbc|uob|singpass|gov|bank)/i;

        // Simple check: brand-ish display name but domain doesn't look related
        if (brandish.test(n) && !n.includes(d.split(".")[0])) {
          add(
            "medium",
            "Possible brand impersonation",
            `Display name suggests a known brand, but sender domain is “${senderDomain}”.`,
            18
          );
        }
      }

      /* ===============================
         4) Link analysis
      =============================== */
      const uniqueHosts = new Set();

      for (const href of links) {
        const host = hostFromUrl(href);
        if (!host) continue;
        uniqueHosts.add(host);

        if (SHORTENERS.has(host)) {
          add(
            "medium",
            "Shortened link detected",
            `Uses URL shortener (${host}) which hides the real destination.`,
            15
          );
        }

        if (looksLikeIpHost(host)) {
          add(
            "high",
            "IP-address link detected",
            `Link points directly to an IP address (${host}).`,
            22
          );
        }

        const tld = getTld(host);
        if (tld && SUSPICIOUS_TLDS.includes(tld)) {
          add(
            "medium",
            "Suspicious domain ending",
            `Link uses potentially risky TLD (.${tld}).`,
            12
          );
        }
      }

      /* ===============================
         5) External domains logic (realistic)
      =============================== */
      if (senderDomain && uniqueHosts.size) {
        const senderBase = senderDomain.split(".").slice(-2).join(".");
        const externalHosts = [...uniqueHosts].filter(h => !h.endsWith(senderBase));

        // Many legitimate emails use 1-2 external hosts (CDN/trackers).
        if (externalHosts.length >= 4) {
          add(
            "medium",
            "Many external domains in links",
            `Email links point to ${externalHosts.length} different external domains.`,
            10
          );
        } else if (externalHosts.length >= 2) {
          add(
            "low",
            "Some external domains in links",
            "Links point to multiple external domains (common in marketing emails).",
            3
          );
        }
      }

      /* ===============================
         6) Trusted Google services dampener
      =============================== */
      if (uniqueHosts.size > 0) {
        const hosts = [...uniqueHosts];

        const allTrustedGoogle = hosts.every(
          h => TRUSTED_GOOGLE_HOSTS.has(h) || h.endsWith(".google.com") || h.endsWith(".gstatic.com")
        );

        if (allTrustedGoogle) {
          // Reduce false positives for calendar/meet/invites
          riskPoints = Math.max(0, riskPoints - 12);
        }
      }

      /* ===============================
         SCORING
      =============================== */
      riskPoints = Math.min(100, Math.max(0, riskPoints));
      const score = Math.max(0, 100 - riskPoints);

      let level = "safe";
      if (score < 50) level = "risk";
      else if (score < 80) level = "caution";

      return {
        ok: true,
        level,      // safe | caution | risk
        score,      // 0..100 (higher = safer)
        findings: findings.slice(0, 6)
      };
    }
  };
})();
