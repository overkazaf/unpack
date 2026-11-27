/**
 * UNPACK Studio — AI Model Provider Settings & Embedded Reverse-Engineering AI Analysis
 * Safe XSS-proof Markdown renderer (zero raw HTML injection).
 */
(function (global) {
  "use strict";

  function t(key, params) {
    return global.UnpackI18n ? global.UnpackI18n.t(key, params) : key;
  }

  function esc(v) {
    return global.UnpackUI ? global.UnpackUI.esc(v) : String(v || "");
  }

  let settingsOpen = false;
  let draftConfig = null;

  // =========================================================================
  // XSS-Safe Lightweight Markdown Renderer
  // =========================================================================

  function renderInlineMd(escapedLine) {
    return escapedLine
      .replace(/`([^`]+)`/g, '<code class="md-inline-code">$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/\*([^*]+)\*/g, "<em>$1</em>");
  }

  function renderSafeMarkdown(rawMd) {
    if (!rawMd) return "";
    const lines = String(rawMd).replace(/\r\n/g, "\n").split("\n");
    const out = [];
    let inCode = false;
    let codeLang = "";
    let codeBuf = [];
    let inList = false;

    function flushList() {
      if (inList) {
        out.push("</ul>");
        inList = false;
      }
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim().startsWith("```")) {
        flushList();
        if (!inCode) {
          inCode = true;
          codeLang = line.trim().slice(3).trim();
          codeBuf = [];
        } else {
          out.push(
            `<pre class="md-code"><code class="mono" data-lang="${esc(codeLang)}">${esc(codeBuf.join("\n"))}</code></pre>`
          );
          inCode = false;
          codeLang = "";
          codeBuf = [];
        }
        continue;
      }
      if (inCode) {
        codeBuf.push(line);
        continue;
      }

      const trimmed = line.trim();
      if (!trimmed) {
        flushList();
        continue;
      }

      const h3 = trimmed.match(/^###\s+(.+)$/);
      const h2 = trimmed.match(/^##\s+(.+)$/);
      const h1 = trimmed.match(/^#\s+(.+)$/);
      if (h3) {
        flushList();
        out.push(`<h4>${renderInlineMd(esc(h3[1]))}</h4>`);
        continue;
      }
      if (h2) {
        flushList();
        out.push(`<h3>${renderInlineMd(esc(h2[1]))}</h3>`);
        continue;
      }
      if (h1) {
        flushList();
        out.push(`<h2>${renderInlineMd(esc(h1[1]))}</h2>`);
        continue;
      }

      const li = trimmed.match(/^([-*•]|\d+\.)\s+(.+)$/);
      if (li) {
        if (!inList) {
          out.push('<ul class="md-list">');
          inList = true;
        }
        out.push(`<li>${renderInlineMd(esc(li[2]))}</li>`);
        continue;
      }

      flushList();
      out.push(`<p>${renderInlineMd(esc(trimmed))}</p>`);
    }

    if (inCode && codeBuf.length) {
      out.push(`<pre class="md-code"><code class="mono">${esc(codeBuf.join("\n"))}</code></pre>`);
    }
    flushList();
    return `<div class="md-content">${out.join("")}</div>`;
  }

  // =========================================================================
  // AI Config Management
  // =========================================================================

  function updateStatusIndicators() {
    const cfg = global.UnpackStore.aiConfig;
    const configured = Boolean(cfg && cfg.configured);
    document.querySelectorAll("[data-ai-dot]").forEach((dot) => {
      dot.className = `status-dot ${configured ? "ok" : "warn"}`;
    });
    document.querySelectorAll("[data-ai-status-text]").forEach((el) => {
      el.textContent = configured ? `${cfg.provider}` : t("ai.status.unconfigured");
    });
  }

  async function loadConfig() {
    const Store = global.UnpackStore;
    try {
      const res = await global.UnpackAPI.getAiConfig();
      Store.aiConfig = res.config || null;
      Store.aiPresets = res.presets || [];
      Store.degraded.ai = false;
      updateStatusIndicators();
      if (settingsOpen) renderSettingsModal();
      return res;
    } catch (err) {
      Store.degraded.ai = true;
      document.querySelectorAll("[data-ai-dot]").forEach((dot) => {
        dot.className = "status-dot fail";
      });
      document.querySelectorAll("[data-ai-status-text]").forEach((el) => {
        el.textContent = t("status.degraded");
      });
      return null;
    }
  }

  function readModalForm() {
    const cur = draftConfig || global.UnpackStore.aiConfig || {};
    return {
      provider: cur.provider || "openai",
      enabled: Boolean(document.getElementById("aiCfgEnabled")?.checked ?? true),
      base_url: (document.getElementById("aiCfgBaseUrl")?.value || "").trim(),
      model: (document.getElementById("aiCfgModel")?.value || "").trim(),
      api_key: (document.getElementById("aiCfgApiKey")?.value || "").trim(),
      temperature: Number(document.getElementById("aiCfgTemp")?.value ?? 0.2),
      max_tokens: Number(document.getElementById("aiCfgMaxTokens")?.value ?? 2048),
      timeout_seconds: Number(document.getElementById("aiCfgTimeout")?.value ?? 60),
    };
  }

  function selectPreset(providerId) {
    const Store = global.UnpackStore;
    const preset = (Store.aiPresets || []).find((p) => p.id === providerId);
    const base = readModalForm();
    draftConfig = {
      ...(Store.aiConfig || {}),
      ...base,
      provider: providerId,
      base_url: preset ? preset.base_url : base.base_url,
      model: preset ? preset.default_model : base.model,
      requires_api_key: preset ? preset.requires_api_key : true,
    };
    Store.aiTestResult = null;
    renderSettingsModal();
  }

  function pickPresetModel(modelName) {
    const inp = document.getElementById("aiCfgModel");
    if (inp) inp.value = modelName;
    if (draftConfig) draftConfig.model = modelName;
  }

  async function saveSettings(clearApiKey = false) {
    const Store = global.UnpackStore;
    const UI = global.UnpackUI;
    const payload = readModalForm();
    if (clearApiKey) {
      payload.clear_api_key = true;
      payload.api_key = "";
    }
    try {
      const res = await global.UnpackAPI.saveAiConfig(payload);
      Store.aiConfig = res.config;
      Store.aiPresets = res.presets || Store.aiPresets;
      draftConfig = { ...res.config, api_key: "" };
      updateStatusIndicators();
      UI.toast(t("ai.modal.saved"), "ok");
      renderSettingsModal();
      if (global.UnpackApp) global.UnpackApp.render();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function runConnectionTest() {
    const Store = global.UnpackStore;
    const payload = readModalForm();
    Store.aiTesting = true;
    Store.aiTestResult = null;
    draftConfig = { ...(Store.aiConfig || {}), ...payload };
    renderSettingsModal();
    try {
      Store.aiTestResult = await global.UnpackAPI.testAiConnection(payload);
    } catch (err) {
      Store.aiTestResult = { ok: false, error: err.message, hint: "" };
    } finally {
      Store.aiTesting = false;
      renderSettingsModal();
    }
  }

  function openSettingsModal() {
    const Store = global.UnpackStore;
    settingsOpen = true;
    Store.aiTestResult = null;
    draftConfig = Store.aiConfig ? { ...Store.aiConfig, api_key: "" } : null;
    renderSettingsModal();
    if (!Store.aiPresets || !Store.aiPresets.length) {
      loadConfig();
    }
  }

  function renderSettingsModal() {
    const Store = global.UnpackStore;
    const UI = global.UnpackUI;
    const isZh = global.UnpackI18n && global.UnpackI18n.getLang() === "zh";
    const cfg = draftConfig || Store.aiConfig || {
      enabled: true,
      provider: "openai",
      base_url: "https://api.openai.com/v1",
      model: "gpt-4o-mini",
      has_api_key: false,
      api_key_masked: "",
      requires_api_key: true,
      temperature: 0.2,
      max_tokens: 2048,
      timeout_seconds: 60,
    };
    const presets = Store.aiPresets || [];
    const activePreset = presets.find((p) => p.id === cfg.provider);

    const presetBtns = presets
      .map((p) => {
        const active = p.id === cfg.provider;
        const label = isZh && p.label_zh ? p.label_zh : p.label;
        return `
          <button class="ai-preset-btn ${active ? "active" : ""}" type="button" data-action="ai-preset" data-provider="${esc(p.id)}">
            <strong>${esc(label)}</strong>
            <span class="mono">${esc(p.default_model || "custom")}</span>
          </button>
        `;
      })
      .join("");

    const modelChips = (activePreset && activePreset.models && activePreset.models.length)
      ? `<div class="toolbar" style="margin-top:5px">${activePreset.models
          .map(
            (m) =>
              `<button class="btn btn-ghost btn-xs mono" type="button" data-action="ai-pick-model" data-model="${esc(m)}">${esc(m)}</button>`
          )
          .join("")}</div>`
      : "";

    const testRes = Store.aiTestResult;
    const testBanner = testRes
      ? `<div class="ai-test-banner ${testRes.ok ? "ok" : "danger"}">
          <div><strong>${
            testRes.ok
              ? esc(t("ai.modal.test_ok", { ms: testRes.latency_ms || 0, reply: testRes.reply_preview || "OK" }))
              : esc(t("ai.modal.test_fail", { error: testRes.error || "error" }))
          }</strong></div>
          ${testRes.hint ? `<div style="margin-top:4px;font-size:11.5px;opacity:.9">${esc(testRes.hint)}</div>` : ""}
        </div>`
      : "";

    const keyPh = cfg.has_api_key
      ? t("ai.modal.api_key_saved", { masked: cfg.api_key_masked || "***" })
      : cfg.requires_api_key === false
      ? t("ai.modal.api_key_optional")
      : t("ai.modal.api_key_ph");

    const bodyHtml = `
      <p style="font-size:12.5px;color:var(--text-secondary);margin-bottom:12px">${esc(t("ai.modal.subtitle"))}</p>

      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin-bottom:7px">${esc(t("ai.modal.presets"))}</div>
      <div class="ai-preset-grid">${presetBtns}</div>

      <label class="checkbox-row" style="margin:10px 0 8px">
        <input type="checkbox" id="aiCfgEnabled" ${cfg.enabled !== false ? "checked" : ""}>
        <strong>${esc(t("ai.modal.enable"))}</strong>
      </label>

      <div class="grid-2" style="margin-bottom:10px">
        <div class="field">
          <label for="aiCfgBaseUrl">${esc(t("ai.modal.base_url"))}</label>
          <input type="text" class="input mono" id="aiCfgBaseUrl" value="${esc(cfg.base_url || "")}" placeholder="https://api.openai.com/v1">
        </div>
        <div class="field">
          <label for="aiCfgModel">${esc(t("ai.modal.model"))}</label>
          <input type="text" class="input mono" id="aiCfgModel" value="${esc(cfg.model || "")}" placeholder="gpt-4o-mini">
          ${modelChips}
        </div>
      </div>

      <div class="field" style="margin-bottom:12px">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <label for="aiCfgApiKey">${esc(t("ai.modal.api_key"))}</label>
          ${cfg.has_api_key ? `<button class="btn btn-ghost btn-xs" type="button" data-action="ai-clear-key">${esc(t("ai.modal.clear_key"))}</button>` : ""}
        </div>
        <input type="password" class="input mono" id="aiCfgApiKey" value="${esc(cfg.api_key || "")}" placeholder="${esc(keyPh)}" autocomplete="off">
      </div>

      <div class="grid-3" style="margin-bottom:14px">
        <div class="field">
          <label for="aiCfgTemp">${esc(t("ai.modal.temp"))}</label>
          <input type="number" step="0.1" min="0" max="2" class="input mono" id="aiCfgTemp" value="${esc(cfg.temperature ?? 0.2)}">
        </div>
        <div class="field">
          <label for="aiCfgMaxTokens">${esc(t("ai.modal.max_tokens"))}</label>
          <input type="number" step="128" min="64" max="32768" class="input mono" id="aiCfgMaxTokens" value="${esc(cfg.max_tokens ?? 2048)}">
        </div>
        <div class="field">
          <label for="aiCfgTimeout">${esc(t("ai.modal.timeout"))}</label>
          <input type="number" min="3" max="300" class="input mono" id="aiCfgTimeout" value="${esc(cfg.timeout_seconds ?? 60)}">
        </div>
      </div>

      ${testBanner}

      <div class="toolbar" style="justify-content:flex-end;padding-top:10px;border-top:1px solid var(--border)">
        <button class="btn btn-subtle btn-sm" type="button" id="btnAiTestConn" data-action="ai-test" ${Store.aiTesting ? "disabled" : ""}>
          ${esc(Store.aiTesting ? t("ai.modal.testing") : t("ai.modal.test_btn"))}
        </button>
        <button class="btn btn-primary btn-sm" type="button" id="btnAiSaveCfg" data-action="ai-save">
          ${esc(t("ai.modal.save_btn"))}
        </button>
      </div>
    `;

    UI.openModal(t("ai.modal.title"), bodyHtml);
  }

  // =========================================================================
  // Embedded AI Analysis Cards & Execution
  // =========================================================================

  function getSampleAnalysesForModule(sample, module) {
    if (!sample) return [];
    return (sample.ai_analyses || []).filter((a) => a.module === module);
  }

  async function runModuleAnalysis(module, extraPayload = {}) {
    const Store = global.UnpackStore;
    const UI = global.UnpackUI;
    const sample = Store.activeSample;
    if (!sample) return;

    if (Store.aiConfig && !Store.aiConfig.configured) {
      UI.toast(t("ai.card.unconfigured_hint"), "warn");
      openSettingsModal();
      return;
    }

    Store.aiLoading[module] = true;
    if (global.UnpackApp) global.UnpackApp.render();

    try {
      const res = await global.UnpackAPI.runSampleAi(sample.id, module, extraPayload);
      const item = res.analysis;
      if (item) {
        const prev = (sample.ai_analyses || []).filter((x) => x.id !== item.id);
        sample.ai_analyses = [item, ...prev];
        Store.aiSelectedByModule[module] = item.id;
      }
      if (global.UnpackWorkspace) {
        global.UnpackWorkspace.refreshHistory(Store.activeWorkspaceId);
      }
    } catch (err) {
      if (err.code === "ENGINE_UNAVAILABLE") {
        UI.toast(err.message, "warn");
        openSettingsModal();
      } else {
        UI.toast(err.message, "danger");
      }
    } finally {
      Store.aiLoading[module] = false;
      if (global.UnpackApp) global.UnpackApp.render();
    }
  }

  function selectHistoryItem(module, analysisId) {
    global.UnpackStore.aiSelectedByModule[module] = analysisId;
    if (global.UnpackApp) global.UnpackApp.render();
  }

  function copyMarkdown(module) {
    const sample = global.UnpackStore.activeSample;
    const list = getSampleAnalysesForModule(sample, module);
    const selId = global.UnpackStore.aiSelectedByModule[module];
    const active = list.find((a) => a.id === selId) || list[0];
    if (!active || !active.markdown) return;
    navigator.clipboard?.writeText(active.markdown).catch(() => {});
    global.UnpackUI.toast(t("ai.card.copied"), "ok");
  }

  function renderEmbeddedCard(module, opts = {}) {
    const Store = global.UnpackStore;
    const UI = global.UnpackUI;
    const sample = Store.activeSample;
    if (!sample) return "";

    const cfg = Store.aiConfig;
    const configured = Boolean(cfg && cfg.configured);
    const busy = Boolean(Store.aiLoading[module]);
    const list = getSampleAnalysesForModule(sample, module);
    const selId = Store.aiSelectedByModule[module];
    const active = list.find((a) => a.id === selId) || list[0] || null;

    const title = opts.title || t(`ai.mod.${module}.title`);
    const btnText = opts.btnText || t(`ai.mod.${module}.btn`);
    const desc = opts.desc || t(`ai.mod.${module}.desc`);
    const compact = Boolean(opts.compact);

    const historySelect =
      list.length > 1
        ? `<select class="select select-sm mono" data-ai-history-module="${esc(module)}" style="max-width:210px">
            ${list
              .map(
                (a) =>
                  `<option value="${esc(a.id)}" ${active && active.id === a.id ? "selected" : ""}>${esc((a.created_at || "").slice(5, 16).replace("T", " "))} · ${esc(a.model || a.provider)}</option>`
              )
              .join("")}
          </select>`
        : "";

    return `
      <div class="ai-card ${compact ? "compact" : ""}" id="aiCard_${esc(module)}">
        <div class="ai-card-head">
          <div class="toolbar">
            <span class="badge badge-violet">✦ ${esc(t("ai.card.badge"))}</span>
            <strong class="ai-card-title">${esc(title)}</strong>
            ${configured ? UI.badge(`${cfg.provider}/${cfg.model}`, "muted") : UI.badge(t("ai.status.unconfigured"), "warn")}
          </div>
          <div class="toolbar">
            ${historySelect}
            ${active ? `<button class="btn btn-subtle btn-xs" type="button" data-action="ai-copy" data-module="${esc(module)}">${esc(t("ai.card.copy"))}</button>` : ""}
            <button class="btn btn-subtle btn-xs" type="button" data-action="open-ai-settings">${esc(t("ai.nav_btn"))}</button>
            <button class="btn btn-primary btn-xs" type="button" data-action="ai-run" data-module="${esc(module)}" ${busy ? "disabled" : ""}>
              ✦ ${esc(busy ? t("ai.card.running") : btnText)}
            </button>
          </div>
        </div>
        <div class="ai-card-body">
          ${
            busy
              ? `<div class="ai-loading-row"><span class="ai-spinner"></span><span>${esc(t("ai.card.running"))}</span></div>`
              : active
              ? `
                <div class="ai-result-meta mono">
                  <span>${esc(active.title || title)}</span>
                  <span>${esc(active.provider)}/${esc(active.model)} &middot; ${active.latency_ms || 0} ms &middot; ${esc((active.created_at || "").slice(0, 19).replace("T", " "))}</span>
                </div>
                ${renderSafeMarkdown(active.markdown)}
              `
              : `<div class="ai-empty-row">
                  <span>${esc(configured ? desc : t("ai.card.unconfigured_hint"))}</span>
                  ${!configured ? `<button class="btn btn-subtle btn-xs" type="button" data-action="open-ai-settings">${esc(t("ai.card.configure_btn"))}</button>` : ""}
                </div>`
          }
        </div>
      </div>
    `;
  }

  global.UnpackAI = {
    renderSafeMarkdown,
    loadConfig,
    updateStatusIndicators,
    openSettingsModal,
    renderSettingsModal,
    selectPreset,
    pickPresetModel,
    saveSettings,
    runConnectionTest,
    runModuleAnalysis,
    selectHistoryItem,
    copyMarkdown,
    renderEmbeddedCard,
    isSettingsOpen: () => settingsOpen,
    onModalClosed: () => {
      settingsOpen = false;
    },
  };
})(window);
