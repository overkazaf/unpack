/**
 * UNPACK Studio — Deep, Self-Explanatory Pipeline Studio
 * Live Preflight Gate, Scenario Presets, Visual Stage Blueprint & Stage Inspector.
 */
(function (global) {
  "use strict";

  function t(key, params) {
    return global.UnpackI18n ? global.UnpackI18n.t(key, params) : key;
  }

  const PRESETS = [
    {
      id: "offline_audit",
      offline: true,
      titleKey: "pipe.preset.offline_audit.title",
      descKey: "pipe.preset.offline_audit.desc",
    },
    {
      id: "repair_repack",
      offline: true,
      titleKey: "pipe.preset.repair_repack.title",
      descKey: "pipe.preset.repair_repack.desc",
    },
    {
      id: "device_standard",
      offline: false,
      titleKey: "pipe.preset.device_standard.title",
      descKey: "pipe.preset.device_standard.desc",
    },
    {
      id: "device_deep",
      offline: false,
      titleKey: "pipe.preset.device_deep.title",
      descKey: "pipe.preset.device_deep.desc",
    },
  ];

  const STAGE_JUMP_MAP = {
    intake: { view: "samples", key: "nav.samples" },
    scan_inspect: { view: "overview", key: "pipe.inspector.jump_overview" },
    extract_dex: { view: "inspector", key: "pipe.inspector.jump_inspector" },
    dynamic_dump: { view: "inspector", key: "pipe.inspector.jump_inspector" },
    active_invoke: { view: "inspector", key: "pipe.inspector.jump_inspector" },
    repair_verify: { view: "repair", key: "pipe.inspector.jump_repair" },
    vmp_xref: { view: "vmp", key: "pipe.inspector.jump_vmp" },
    repack_report: { view: "reports", key: "pipe.inspector.jump_reports" },
  };

  let planReqSeq = 0;

  async function refreshPlan(explicitMode, refreshDoctor = false) {
    const Store = global.UnpackStore;
    const API = global.UnpackAPI;
    const sample = Store.activeSample;
    if (!sample) return null;

    const reqId = ++planReqSeq;
    const sampleId = sample.id;
    const lang = global.UnpackI18n ? global.UnpackI18n.getLang() : "en";
    const p = Store.pipeline;
    if (explicitMode) p.mode = explicitMode;
    p.planLoading = true;
    if (global.UnpackApp) global.UnpackApp.render();

    try {
      const plan = await API.planPipeline({
        sample_id: sampleId,
        mode: p.mode || "",
        engine: p.engine || "",
        deep: p.deep,
        timeout: p.timeout,
        anti_detect: p.antiDetect,
        repack: p.mode ? p.repack : undefined,
        generate_report: p.generateReport,
        lang,
        refresh_doctor: Boolean(refreshDoctor),
      });
      if (reqId !== planReqSeq || Store.activeSampleId !== sampleId) return null;
      p.plan = plan;
      if (!p.mode) {
        p.mode = plan.mode;
        p.repack = Boolean(plan.options && plan.options.repack);
        p.deep = Boolean(plan.options && plan.options.deep);
      }
      if (!p.selectedStageId && plan.stages && plan.stages.length) {
        p.selectedStageId = plan.stages[0].id;
      } else if (
        p.selectedStageId &&
        plan.stages &&
        !plan.stages.some((st) => st.id === p.selectedStageId)
      ) {
        p.selectedStageId = plan.stages[0]?.id || null;
      }
      return plan;
    } catch (err) {
      if (reqId === planReqSeq && global.UnpackUI) global.UnpackUI.toast(err.message, "danger");
      return null;
    } finally {
      if (reqId === planReqSeq) {
        p.planLoading = false;
        if (global.UnpackApp) global.UnpackApp.render();
        if (global.UnpackOnboarding) global.UnpackOnboarding.reposition();
      }
    }
  }

  async function setMode(mode) {
    const p = global.UnpackStore.pipeline;
    p.mode = mode;
    p.repack = mode === "repair_repack";
    p.deep = mode === "device_deep";
    p.userPinnedStage = false;
    p.liveStages = {};
    await refreshPlan(mode);
  }

  function selectStage(stageId) {
    const p = global.UnpackStore.pipeline;
    p.selectedStageId = stageId;
    p.userPinnedStage = true;
    if (global.UnpackApp) global.UnpackApp.render();
  }

  function updateParam(field, value) {
    const p = global.UnpackStore.pipeline;
    p[field] = value;
    refreshPlan(p.mode);
  }

  function syncJobStages(job) {
    const Store = global.UnpackStore;
    if (!job || !Array.isArray(job.stages)) return;
    if (Store.activeSample && job.sample_id && job.sample_id !== Store.activeSample.id) return;
    const p = Store.pipeline;
    job.stages.forEach((st) => {
      const sid = st.stage_id || st.id;
      if (sid) p.liveStages[sid] = st;
    });
  }

  function handleStageEvent(payload) {
    const Store = global.UnpackStore;
    const p = Store.pipeline;
    const sid = payload.stage_id || payload.id;
    if (!sid) return;
    p.liveStages[sid] = payload;
    if (payload.status === "running" && !p.userPinnedStage) {
      p.selectedStageId = sid;
    }
    if (Store.view === "pipeline" && global.UnpackApp) {
      global.UnpackApp.render();
    }
  }

  async function launch() {
    const Store = global.UnpackStore;
    const API = global.UnpackAPI;
    const UI = global.UnpackUI;
    const App = global.UnpackApp;
    const sample = Store.activeSample;
    if (!sample) return;

    const p = Store.pipeline;
    const mode = p.mode || (p.plan && p.plan.recommended_mode) || "offline_audit";

    p.liveStages = {};
    p.userPinnedStage = false;
    Store.busy.pipeline = true;
    if (App) App.render();

    try {
      const res = await API.launchPipelineJob({
        sample_id: sample.id,
        mode,
        engine: p.engine || "",
        timeout: Number(p.timeout || 15),
        deep: Boolean(p.deep || mode === "device_deep"),
        anti_detect: Boolean(p.antiDetect),
        repack: Boolean(p.repack),
        generate_report: Boolean(p.generateReport),
        lang: global.UnpackI18n ? global.UnpackI18n.getLang() : "en",
      });
      p.lastJobId = res.job_id;
      UI.toast(t("toast.job_started", { id: res.job_id }), "accent");
      if (App) {
        await App.refreshJobs();
        App.subscribeJob(res.job_id);
      }
    } catch (err) {
      UI.toast(err.message, "danger");
    } finally {
      Store.busy.pipeline = false;
      if (App) App.render();
    }
  }

  function stageStatusMeta(stPlan, stLive) {
    const status = stLive ? stLive.status : stPlan.will_run ? "pending" : "skipped";
    const iconMap = {
      pending: "○",
      running: "◉",
      done: "✓",
      skipped: "—",
      failed: "✕",
    };
    const toneMap = {
      pending: "muted",
      running: "accent",
      done: "ok",
      skipped: "muted",
      failed: "danger",
    };
    return {
      status,
      icon: iconMap[status] || "○",
      tone: toneMap[status] || "muted",
      label: t(`pipe.stage.${status}`),
    };
  }

  function renderStageMetricsChip(stLive) {
    if (!stLive || !stLive.metrics) return "";
    const m = stLive.metrics;
    const entries = Object.entries(m).slice(0, 2);
    if (!entries.length) return "";
    return entries
      .map(([k, v]) => {
        const val = Array.isArray(v) ? v.join(",") : String(v);
        return `<span class="stage-chip mono">${global.UnpackUI.esc(val.slice(0, 22))}</span>`;
      })
      .join("");
  }

  function renderWorkspace() {
    const Store = global.UnpackStore;
    const UI = global.UnpackUI;
    const esc = UI.esc;
    const sample = Store.activeSample;
    if (!sample) return UI.requireSamplePrompt(t("nav.pipeline"));

    const p = Store.pipeline;
    const plan = p.plan;
    const activeJob =
      Store.activeJob && Store.activeJob.sample_id === sample.id ? Store.activeJob : null;
    const isRunning = Boolean(activeJob && activeJob.status === "running");

    const selectedMode = p.mode || (plan && plan.mode) || "offline_audit";
    const isOfflineMode = selectedMode === "offline_audit" || selectedMode === "repair_repack";
    const recMode = plan ? plan.recommended_mode : "offline_audit";

    // 1. Scenario Preset Cards
    const presetCards = PRESETS.map((pr) => {
      const isSelected = selectedMode === pr.id;
      const isRec = recMode === pr.id;
      return `
        <button class="preset-card ${isSelected ? "selected" : ""}" type="button" data-action="pipe-mode" data-mode="${pr.id}">
          <div class="preset-card-top">
            <span class="badge ${pr.offline ? "badge-ok" : "badge-violet"}">${esc(t(pr.offline ? "pipe.tag.offline" : "pipe.tag.device"))}</span>
            ${isRec ? `<span class="badge badge-accent">${esc(t("pipe.recommended"))}</span>` : ""}
          </div>
          <div class="preset-card-title">${esc(t(pr.titleKey))}</div>
          <div class="preset-card-desc">${esc(t(pr.descKey))}</div>
        </button>
      `;
    }).join("");

    // 2. Preflight Gate Banner
    const checks = (plan && plan.preflight_checks) || [];
    const blocking = checks.filter((c) => c.status === "block");
    const warnings = checks.filter((c) => c.status === "warn");
    const gateTone = blocking.length ? "danger" : warnings.length ? "warn" : "ok";
    const gateBadge = blocking.length
      ? UI.badge(t("pipe.preflight.blocked", { count: blocking.length }), "danger")
      : warnings.length
      ? UI.badge(t("pipe.preflight.warnings", { count: warnings.length }), "warn")
      : UI.badge(t("pipe.preflight.ready"), "ok");

    const preflightHtml = plan
      ? `
        <div class="preflight-gate tone-${gateTone}">
          <div class="preflight-gate-head">
            <div class="panel-title">${esc(t("pipe.preflight.title"))} ${gateBadge}</div>
            <div class="toolbar">
              ${
                blocking.length && !isOfflineMode
                  ? `<button class="btn btn-primary btn-xs" type="button" data-action="pipe-switch-offline">${esc(t("pipe.preflight.switch_offline"))}</button>`
                  : ""
              }
              <button class="btn btn-subtle btn-xs" type="button" data-action="open-doctor">${esc(t("pipe.preflight.open_doctor"))}</button>
            </div>
          </div>
          <div class="preflight-list">
            ${checks
              .map((c) => {
                const stTone = c.status === "pass" ? "ok" : c.status === "block" ? "danger" : "warn";
                const icon = c.status === "pass" ? "✓" : c.status === "block" ? "✕" : "!";
                return `
                  <div class="preflight-item ${stTone}">
                    <span class="preflight-ico">${icon}</span>
                    <div class="preflight-body">
                      <div class="preflight-title">${esc(c.title)}</div>
                      <div class="preflight-detail">${esc(c.detail)}</div>
                      ${c.fix_hint ? `<div class="preflight-fix">${esc(c.fix_hint)}</div>` : ""}
                    </div>
                  </div>
                `;
              })
              .join("")}
          </div>
        </div>
      `
      : `<div class="panel"><div class="panel-body" style="color:var(--text-secondary)">${esc(t("common.loading"))}</div></div>`;

    // 3. Interactive Stage Blueprint + Stage Inspector
    const stages = (plan && plan.stages) || [];
    const selectedId = p.selectedStageId || (stages[0] && stages[0].id);
    const selPlan = stages.find((s) => s.id === selectedId) || stages[0] || null;
    const selLive = selPlan ? p.liveStages[selPlan.id] || null : null;

    const blueprintNodes = stages
      .map((st, idx) => {
        const live = p.liveStages[st.id] || null;
        const meta = stageStatusMeta(st, live);
        const isSel = selPlan && selPlan.id === st.id;
        const timeText = live && live.duration_ms > 0 ? `${live.duration_ms} ms` : st.estimated_hint;
        return `
          <button class="bp-node status-${meta.status} ${isSel ? "selected" : ""}" type="button" data-action="pipe-stage" data-stage="${esc(st.id)}">
            <div class="bp-node-head">
              <span class="bp-order mono">${idx + 1}</span>
              <span class="bp-status-icon ${meta.status}">${meta.icon}</span>
              <span class="bp-time mono">${esc(timeText)}</span>
            </div>
            <div class="bp-node-title">${esc(st.title)}</div>
            <div class="bp-node-chips">
              ${renderStageMetricsChip(live) || `<span class="stage-chip muted">${esc(meta.label)}</span>`}
            </div>
          </button>
        `;
      })
      .join("");

    let inspectorHtml = "";
    if (selPlan) {
      const meta = stageStatusMeta(selPlan, selLive);
      const jump = STAGE_JUMP_MAP[selPlan.id];
      const stageLogs = (selLive && selLive.logs) || [];
      const stageArts = (selLive && selLive.artifacts) || [];
      const stageMetrics = (selLive && selLive.metrics) || {};
      const metricEntries = Object.entries(stageMetrics);

      inspectorHtml = `
        <div class="stage-inspector" id="stageInspectorPanel">
          <div class="stage-inspector-head">
            <div class="toolbar">
              <span class="badge badge-accent mono">#${selPlan.order}</span>
              <h3 class="stage-inspector-title">${esc(selPlan.title)}</h3>
              ${UI.badge(meta.label, meta.tone)}
              ${selLive && selLive.duration_ms ? UI.badge(`${selLive.duration_ms} ms`, "muted") : ""}
            </div>
            <div class="toolbar">
              ${
                jump
                  ? `<button class="btn btn-subtle btn-xs" type="button" data-action="nav" data-view="${jump.view}">${esc(t(jump.key))} →</button>`
                  : ""
              }
            </div>
          </div>

          <div class="stage-inspector-grid">
            <div class="stage-col">
              <div class="stage-block">
                <div class="stage-block-label">${esc(t("pipe.inspector.purpose"))}</div>
                <p class="stage-block-text">${esc(selPlan.what_it_does)}</p>
              </div>
              <div class="stage-block">
                <div class="stage-block-label">${esc(t("pipe.inspector.why"))}</div>
                <p class="stage-block-text">${esc(selPlan.why_it_matters)}</p>
              </div>
              <div class="stage-block">
                <div class="stage-block-label">${esc(t("pipe.inspector.preflight"))}</div>
                <div class="stage-block-text">
                  ${
                    selPlan.will_run
                      ? UI.badge(`PREFLIGHT: ${String(selPlan.preflight_status || "pass").toUpperCase()}`, selPlan.preflight_status === "block" ? "danger" : selPlan.preflight_status === "warn" ? "warn" : "ok")
                      : UI.badge(t("pipe.stage.skipped"), "muted")
                  }
                  ${selPlan.skip_reason ? `<div style="margin-top:5px;color:var(--text-secondary)">${esc(selPlan.skip_reason)}</div>` : ""}
                </div>
              </div>
              <div class="stage-block">
                <div class="stage-block-label">${esc(t("pipe.inspector.io"))}</div>
                <div class="io-flow">
                  <div class="io-chips">${(selPlan.inputs || []).map((i) => UI.badge(i, "muted")).join(" ")}</div>
                  <span class="io-arrow">→</span>
                  <div class="io-chips">${(selPlan.outputs || []).map((o) => UI.badge(o, "accent")).join(" ")}</div>
                </div>
                ${
                  stageArts.length
                    ? `<div class="toolbar" style="margin-top:8px">${stageArts
                        .map(
                          (a) =>
                            `<a class="btn btn-primary btn-xs" href="${esc(a.download_url)}">⬇ ${esc(a.name)}</a>`
                        )
                        .join("")}</div>`
                    : ""
                }
              </div>
            </div>

            <div class="stage-col">
              <div class="stage-block">
                <div class="stage-block-label">${esc(t("pipe.inspector.metrics"))}</div>
                ${
                  selLive && selLive.summary
                    ? `<div class="stage-summary-box">${esc(selLive.summary)}</div>`
                    : ""
                }
                ${
                  metricEntries.length
                    ? `<div class="stage-metrics-grid">${metricEntries
                        .map(
                          ([k, v]) => `
                        <div class="stage-metric-tile">
                          <span class="stage-metric-k mono">${esc(k)}</span>
                          <span class="stage-metric-v mono">${esc(Array.isArray(v) ? v.join(", ") : String(v))}</span>
                        </div>
                      `
                        )
                        .join("")}</div>`
                    : `<p class="stage-block-text muted">${esc(t("pipe.inspector.no_metrics"))}</p>`
                }
                ${
                  selLive && selLive.next_hint
                    ? `<div class="stage-next-hint"><strong>${esc(t("pipe.inspector.next_hint"))}:</strong> ${esc(selLive.next_hint)}</div>`
                    : ""
                }
              </div>

              <div class="stage-block">
                <div class="stage-block-label">${esc(t("pipe.inspector.troubleshoot"))}</div>
                <ul class="stage-tips">
                  ${(selPlan.troubleshooting || []).map((tip) => `<li>${esc(tip)}</li>`).join("")}
                </ul>
              </div>

              <div class="stage-block">
                <div class="stage-block-label">${esc(t("pipe.inspector.logs"))} (${stageLogs.length})</div>
                <div class="log-console" style="max-height:145px">
                  ${
                    stageLogs.length
                      ? stageLogs
                          .map(
                            (l) =>
                              `<div class="log-line"><span class="log-ts">${esc((l.ts || "").slice(11, 19))}</span><span class="log-lvl-${esc(l.level || "info")}">${esc(l.message)}</span></div>`
                          )
                          .join("")
                      : `<div style="color:var(--text-muted)">${esc(t("pipe.inspector.no_logs"))}</div>`
                  }
                </div>
              </div>
            </div>
          </div>
        </div>
      `;
    }

    const dexSources = Store.samples
      .filter((s) => s.kind === "dex_dir" || s.kind === "dex")
      .map((s) => `<option value="${esc(s.id)}">${esc(s.name)} (${s.dex_count || 1} DEX)</option>`)
      .join("");

    return `
      <div class="view-header">
        <div>
          <h1 class="view-title">${esc(t("pipe.title"))}</h1>
          <p class="view-subtitle">${esc(t("pipe.subtitle"))}</p>
        </div>
        <div class="view-actions">
          <button class="btn btn-subtle btn-sm" type="button" data-action="pipe-refresh-plan">${esc(t("pipe.refresh_plan"))}</button>
          <button class="btn btn-subtle btn-sm" type="button" data-action="open-drawer">${esc(t("pipe.open_logs"))}</button>
        </div>
      </div>

      <div id="tourPipelineStudio">
        <!-- 1. Scenario Preset Cards -->
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">${esc(t("pipe.presets.title"))}</div>
            ${activeJob ? UI.badge(`${activeJob.status.toUpperCase()} (${activeJob.progress || 0}%)`, activeJob.status === "done" ? "ok" : activeJob.status === "failed" ? "danger" : "accent") : ""}
          </div>
          <div class="panel-body">
            <div class="preset-grid">${presetCards}</div>
            ${
              plan
                ? `
              <div class="plan-explain-grid">
                <div class="plan-explain-card">
                  <div class="plan-explain-kicker mono">${esc(t("pipe.why_rec"))}</div>
                  <p>${esc(plan.recommendation_reason)}</p>
                </div>
                <div class="plan-explain-card">
                  <div class="plan-explain-kicker mono">${esc(t("pipe.packer_intel"))}</div>
                  <p>${esc(plan.packer_explanation)}</p>
                </div>
              </div>
            `
                : ""
            }
          </div>
        </div>

        <!-- 2. Preflight Gate -->
        ${preflightHtml}

        <!-- 3. Interactive Stage Blueprint & Inspector -->
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">${esc(t("pipe.blueprint.title"))}</div>
            <span style="font-size:11.5px;color:var(--text-muted)">${esc(t("pipe.blueprint.hint"))}</span>
          </div>
          <div class="panel-body">
            <div class="bp-track">${blueprintNodes}</div>
            ${inspectorHtml}
          </div>
        </div>

        <!-- 4. Guided Parameters & Launch -->
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">${esc(t("pipe.params.title"))}</div>
            <button class="btn btn-primary btn-sm" type="button" id="btnLaunchDeepPipeline" data-action="run-deep-pipeline" ${isRunning || Store.busy.pipeline ? "disabled" : ""}>
              ▶ ${esc(isRunning || Store.busy.pipeline ? t("pipe.launching") : t("pipe.launch_btn"))}
            </button>
          </div>
          <div class="panel-body">
            <div class="guided-params-grid">
              <div class="param-card ${isOfflineMode ? "dimmed" : ""}">
                <label for="pipeEngine">${esc(t("pipe.param.engine"))}</label>
                <select class="select" id="pipeEngine" ${isOfflineMode ? "disabled" : ""}>
                  <option value="" ${!p.engine ? "selected" : ""}>${esc(t("pipe.param.engine.auto"))}</option>
                  <option value="memory" ${p.engine === "memory" ? "selected" : ""}>${esc(t("pipe.param.engine.memory"))}</option>
                  <option value="frida" ${p.engine === "frida" ? "selected" : ""}>${esc(t("pipe.param.engine.frida"))}</option>
                  <option value="ebpf" ${p.engine === "ebpf" ? "selected" : ""}>${esc(t("pipe.param.engine.ebpf"))}</option>
                </select>
                <div class="param-help">${esc(t("pipe.param.engine_help"))}</div>
              </div>

              <div class="param-card ${isOfflineMode ? "dimmed" : ""}">
                <label for="pipeTimeout">${esc(t("pipe.param.timeout"))}</label>
                <input type="number" class="input mono" id="pipeTimeout" value="${esc(p.timeout)}" min="5" max="300" ${isOfflineMode ? "disabled" : ""}>
                <div class="param-help">${esc(t("pipe.param.timeout_help"))}</div>
              </div>

              <div class="param-card ${isOfflineMode ? "dimmed" : ""}">
                <label class="checkbox-row" style="padding:0">
                  <input type="checkbox" id="pipeDeep" ${p.deep ? "checked" : ""} ${isOfflineMode ? "disabled" : ""}>
                  <strong>${esc(t("pipe.param.deep"))}</strong>
                </label>
                <div class="param-help">${esc(t("pipe.param.deep_help"))}</div>
              </div>

              <div class="param-card ${isOfflineMode ? "dimmed" : ""}">
                <label class="checkbox-row" style="padding:0">
                  <input type="checkbox" id="pipeAntiDetect" ${p.antiDetect ? "checked" : ""} ${isOfflineMode ? "disabled" : ""}>
                  <strong>${esc(t("pipe.param.antidetect"))}</strong>
                </label>
                <div class="param-help">${esc(t("pipe.param.antidetect_help"))}</div>
              </div>

              <div class="param-card">
                <label class="checkbox-row" style="padding:0">
                  <input type="checkbox" id="pipeRepack" ${p.repack ? "checked" : ""} ${sample.kind !== "apk" ? "disabled" : ""}>
                  <strong>${esc(t("pipe.param.repack"))}</strong>
                </label>
                <div class="param-help">${esc(t("pipe.param.repack_help"))}</div>
              </div>

              <div class="param-card">
                <label class="checkbox-row" style="padding:0">
                  <input type="checkbox" id="pipeGenReport" ${p.generateReport ? "checked" : ""}>
                  <strong>${esc(t("pipe.param.report"))}</strong>
                </label>
                <div class="param-help">${esc(t("pipe.param.report_help"))}</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Standalone Repack Center & FART Exporter -->
      <div class="grid-2">
        <div class="panel">
          <div class="panel-head"><div class="panel-title">${esc(t("pipe.repack.title"))}</div></div>
          <div class="panel-body">
            ${
              sample.kind === "apk"
                ? `
              <p style="color:var(--text-secondary);font-size:12.5px;margin-bottom:12px">
                ${esc(t("pipe.repack.desc", { name: sample.name }))}
              </p>
              <div class="field" style="margin-bottom:10px">
                <label for="repackDexSource">${esc(t("pipe.repack.dex_src"))}</label>
                <select class="select" id="repackDexSource">
                  <option value="">${esc(t("pipe.repack.dex_default"))}</option>
                  ${dexSources}
                </select>
              </div>
              <label class="checkbox-row" style="margin-bottom:12px">
                <input type="checkbox" id="repackStripSigs" checked> ${esc(t("pipe.repack.strip"))}
              </label>
              <div class="toolbar">
                <button class="btn btn-primary btn-sm" type="button" data-action="run-repack">${esc(Store.busy.repack ? t("pipe.repack.busy") : t("pipe.repack.btn"))}</button>
                ${
                  Store.repackResult && Store.repackResult.artifact
                    ? `<a class="btn btn-subtle btn-sm" href="${esc(Store.repackResult.artifact.download_url)}">${esc(t("common.download"))} ${esc(Store.repackResult.artifact.name)}</a>`
                    : ""
                }
              </div>
            `
                : `<p style="color:var(--text-secondary)">${esc(t("pipe.repack.need_apk"))}</p>`
            }
          </div>
        </div>

        <div class="panel">
          <div class="panel-head"><div class="panel-title">${esc(t("pipe.fart.title"))}</div></div>
          <div class="panel-body">
            <p style="color:var(--text-secondary);font-size:12.5px;margin-bottom:14px">
              ${esc(t("pipe.fart.desc"))}
            </p>
            <div class="toolbar">
              <button class="btn btn-primary btn-sm" type="button" data-action="run-fart">${esc(Store.busy.fart ? t("pipe.fart.busy") : t("pipe.fart.btn"))}</button>
              ${
                Store.fartResult && Store.fartResult.artifact
                  ? `<a class="btn btn-subtle btn-sm" href="${esc(Store.fartResult.artifact.download_url)}">${esc(t("common.download"))} FART ZIP (${UI.fmtNum(Store.fartResult.total_methods)})</a>`
                  : ""
              }
            </div>
          </div>
        </div>
      </div>
    `;
  }

  global.UnpackPipeline = {
    refreshPlan,
    setMode,
    selectStage,
    updateParam,
    syncJobStages,
    handleStageEvent,
    launch,
    renderWorkspace,
  };
})(window);
