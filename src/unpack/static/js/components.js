/**
 * UNPACK Studio — XSS-Safe UI Components & Micro-Visualizations
 */
(function (global) {
  "use strict";

  const ESC_MAP = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };

  function t(key, params) {
    return global.UnpackI18n ? global.UnpackI18n.t(key, params) : key;
  }

  function esc(val) {
    if (val === null || val === undefined) return "";
    return String(val).replace(/[&<>"']/g, (ch) => ESC_MAP[ch]);
  }

  function fmtBytes(bytes) {
    const n = Number(bytes || 0);
    if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  }

  function fmtNum(n) {
    return Number(n || 0).toLocaleString();
  }

  function badge(text, tone = "muted") {
    return `<span class="badge badge-${esc(tone)}">${esc(text)}</span>`;
  }

  function protectionBadge(level) {
    const tones = {
      vmp: "danger",
      dex2c: "violet",
      function_extraction: "warn",
      dex_encryption: "accent",
      none: "ok",
      unknown: "muted",
    };
    const key = String(level || "none").toLowerCase();
    const tone = tones[key] || "muted";
    const label = tones[key] ? t(`badge.${key}`) : String(level || "NONE").toUpperCase();
    return badge(label, tone);
  }

  function severityBadge(sev) {
    const s = String(sev || "info").toLowerCase();
    const tone =
      s === "critical" || s === "high"
        ? "danger"
        : s === "medium"
        ? "warn"
        : s === "ok" || s === "pass"
        ? "ok"
        : "accent";
    return badge(s.toUpperCase(), tone);
  }

  function healthBadge(health) {
    const h = String(health || "ok").toLowerCase();
    if (h === "vmp" || h === "vmp_stub") return badge("VMP", "danger");
    if (h === "nop") return badge("NOP", "warn");
    if (h === "empty") return badge("EMPTY", "muted");
    return badge("OK", "ok");
  }

  function kindBadge(kind) {
    const tones = { apk: "accent", dex: "violet", dex_dir: "ok" };
    const k = String(kind || "").toLowerCase();
    const tone = tones[k] || "muted";
    const label = tones[k] ? t(`badge.${k}`) : String(kind || "").toUpperCase();
    return badge(label, tone);
  }

  function ringGauge(pct, label, tone = "accent") {
    const clamped = Math.max(0, Math.min(100, Math.round(Number(pct) || 0)));
    const r = 24;
    const c = 2 * Math.PI * r;
    const offset = c * (1 - clamped / 100);
    const colorVar =
      tone === "danger"
        ? "var(--danger)"
        : tone === "warn"
        ? "var(--warn)"
        : tone === "ok"
        ? "var(--ok)"
        : tone === "violet"
        ? "var(--violet)"
        : "var(--accent)";
    return `
      <div class="gauge-box">
        <svg width="62" height="62" viewBox="0 0 62 62" aria-label="${esc(label)} ${clamped}%">
          <circle cx="31" cy="31" r="${r}" fill="none" stroke="var(--border)" stroke-width="5"/>
          <circle cx="31" cy="31" r="${r}" fill="none" stroke="${colorVar}" stroke-width="5"
            stroke-linecap="round" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${offset.toFixed(1)}"
            transform="rotate(-90 31 31)"/>
          <text x="31" y="35" text-anchor="middle" fill="var(--text-primary)"
            font-family="var(--font-mono)" font-size="13" font-weight="700">${clamped}%</text>
        </svg>
        <div class="gauge-lbl">${esc(label)}</div>
      </div>
    `;
  }

  function kpi(label, value, sub = "", tone = "") {
    const style = tone ? ` style="color:var(--${esc(tone)})"` : "";
    return `
      <div class="kpi-card">
        <div class="kpi-label">${esc(label)}</div>
        <div class="kpi-value"${style}>${esc(value)}</div>
        ${sub ? `<div class="kpi-sub">${esc(sub)}</div>` : ""}
      </div>
    `;
  }

  function emptyState(title, desc, actionHtml = "") {
    return `
      <div class="empty-state">
        <h3>${esc(title)}</h3>
        <p>${esc(desc)}</p>
        ${actionHtml}
      </div>
    `;
  }

  function requireSamplePrompt(viewTitle) {
    return emptyState(
      t("common.require_sample.title", { view: viewTitle }),
      t("common.require_sample.desc"),
      `<button class="btn btn-primary" type="button" data-action="nav" data-view="samples">${esc(t("common.require_sample.btn"))}</button>`
    );
  }

  function toast(message, tone = "accent") {
    const stack = document.getElementById("toastStack");
    if (!stack) return;
    const el = document.createElement("div");
    el.className = `toast ${tone}`;
    el.textContent = message;
    stack.appendChild(el);
    setTimeout(() => {
      el.style.opacity = "0";
      el.style.transition = "opacity 0.2s";
      setTimeout(() => el.remove(), 220);
    }, 3600);
  }

  let modalPrevFocus = null;

  function openModal(title, bodyHtml) {
    const backdrop = document.getElementById("modalBackdrop");
    const tEl = document.getElementById("modalTitle");
    const bEl = document.getElementById("modalBody");
    if (!backdrop || !tEl || !bEl) return;
    if (backdrop.hidden) modalPrevFocus = document.activeElement;
    tEl.textContent = title;
    bEl.innerHTML = bodyHtml;
    backdrop.hidden = false;
    const closeBtn = document.getElementById("btnCloseModal");
    if (closeBtn) closeBtn.focus();
  }

  function closeModal() {
    const backdrop = document.getElementById("modalBackdrop");
    if (backdrop) backdrop.hidden = true;
    if (global.UnpackWorkspace) global.UnpackWorkspace.onModalClosed();
    if (global.UnpackAI) global.UnpackAI.onModalClosed();
    if (modalPrevFocus && typeof modalPrevFocus.focus === "function") {
      try {
        modalPrevFocus.focus();
      } catch (_) {}
      modalPrevFocus = null;
    }
  }

  let activeDialogResolve = null;
  let dialogPrevFocus = null;

  function closeDialog(result = null) {
    const backdrop = document.getElementById("dialogBackdrop");
    if (backdrop) backdrop.hidden = true;
    const resolver = activeDialogResolve;
    activeDialogResolve = null;
    if (dialogPrevFocus && typeof dialogPrevFocus.focus === "function") {
      try {
        dialogPrevFocus.focus();
      } catch (_) {}
      dialogPrevFocus = null;
    }
    if (resolver) resolver(result);
  }

  function confirmModal({ title, message, confirmText, cancelText, danger = true }) {
    const backdrop = document.getElementById("dialogBackdrop");
    const tEl = document.getElementById("dialogTitle");
    const bEl = document.getElementById("dialogBody");
    if (!backdrop || !tEl || !bEl) return Promise.resolve(false);
    if (activeDialogResolve) closeDialog(false);

    dialogPrevFocus = document.activeElement;
    tEl.textContent = title || t("dialog.confirm_delete_title");
    bEl.innerHTML = `
      <p class="dialog-msg">${esc(message || "")}</p>
      <div class="dialog-actions">
        <button class="btn btn-subtle btn-sm" type="button" id="dialogBtnCancel">${esc(cancelText || t("dialog.cancel_btn"))}</button>
        <button class="btn ${danger ? "btn-danger" : "btn-primary"} btn-sm" type="button" id="dialogBtnOk">${esc(confirmText || t("dialog.confirm_btn"))}</button>
      </div>
    `;
    backdrop.hidden = false;

    return new Promise((resolve) => {
      activeDialogResolve = resolve;
      const okBtn = document.getElementById("dialogBtnOk");
      const cancelBtn = document.getElementById("dialogBtnCancel");
      okBtn?.addEventListener("click", () => closeDialog(true), { once: true });
      cancelBtn?.addEventListener("click", () => closeDialog(false), { once: true });
      (cancelBtn || okBtn)?.focus();
    });
  }

  function promptModal({ title, value = "", placeholder = "", confirmText, cancelText }) {
    const backdrop = document.getElementById("dialogBackdrop");
    const tEl = document.getElementById("dialogTitle");
    const bEl = document.getElementById("dialogBody");
    if (!backdrop || !tEl || !bEl) return Promise.resolve(null);
    if (activeDialogResolve) closeDialog(null);

    dialogPrevFocus = document.activeElement;
    tEl.textContent = title || t("dialog.rename_ws_title");
    bEl.innerHTML = `
      <input type="text" class="input" id="dialogPromptInput" value="${esc(value)}" placeholder="${esc(placeholder)}" style="width:100%">
      <div class="dialog-actions">
        <button class="btn btn-subtle btn-sm" type="button" id="dialogBtnCancel">${esc(cancelText || t("dialog.cancel_btn"))}</button>
        <button class="btn btn-primary btn-sm" type="button" id="dialogBtnOk">${esc(confirmText || t("dialog.save_btn"))}</button>
      </div>
    `;
    backdrop.hidden = false;

    return new Promise((resolve) => {
      activeDialogResolve = resolve;
      const inp = document.getElementById("dialogPromptInput");
      const okBtn = document.getElementById("dialogBtnOk");
      const cancelBtn = document.getElementById("dialogBtnCancel");
      const submit = () => closeDialog((inp?.value || "").trim());
      okBtn?.addEventListener("click", submit, { once: true });
      cancelBtn?.addEventListener("click", () => closeDialog(null), { once: true });
      inp?.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          submit();
        }
      });
      if (inp) {
        inp.focus();
        inp.select();
      }
    });
  }

  global.UnpackUI = {
    esc,
    fmtBytes,
    fmtNum,
    badge,
    protectionBadge,
    severityBadge,
    healthBadge,
    kindBadge,
    ringGauge,
    kpi,
    emptyState,
    requireSamplePrompt,
    toast,
    openModal,
    closeModal,
    closeDialog,
    confirmModal,
    promptModal,
  };
})(window);
