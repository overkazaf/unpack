/**
 * UNPACK Studio — All 7 Workspace Views + Task Drawer & Doctor Modal (Fully Bilingual)
 */
(function (global) {
  "use strict";

  const UI = global.UnpackUI;
  const Store = global.UnpackStore;
  const esc = UI.esc;

  function t(key, params) {
    return global.UnpackI18n ? global.UnpackI18n.t(key, params) : key;
  }

  // =========================================================================
  // 1. Samples & Intake Workspace
  // =========================================================================

  function renderSamplesView() {
    const samples = Store.samples || [];
    const localItems = (Store.localLibrary && Store.localLibrary.items) || [];
    const filterQ = (Store.localFilter || "").trim().toLowerCase();
    const kindF = Store.localKindFilter || "all";

    const filteredLocal = localItems.filter((it) => {
      if (kindF !== "all" && it.kind !== kindF) return false;
      if (filterQ && !`${it.name} ${it.display_path}`.toLowerCase().includes(filterQ)) return false;
      return true;
    });

    const vaultRows = samples
      .map((s) => {
        const isActive = s.id === Store.activeSampleId;
        return `
          <tr class="${isActive ? "selected" : ""}">
            <td>
              <div class="mono" style="font-weight:600">${esc(s.name)}</div>
              <div style="font-size:11px;color:var(--text-muted)">${esc(s.display_path)} &middot; <span class="mono">${esc(s.id)}</span></div>
            </td>
            <td>${UI.kindBadge(s.kind)}</td>
            <td class="mono num">${esc(UI.fmtBytes(s.size_bytes))}</td>
            <td>${s.packer ? UI.badge(s.packer, "accent") : UI.badge("—", "muted")}</td>
            <td>${s.protection_level ? UI.protectionBadge(s.protection_level) : UI.badge(t("common.pending"), "muted")}</td>
            <td class="num">
              <div class="toolbar" style="justify-content:flex-end">
                <button class="btn btn-subtle btn-xs" type="button" data-action="select-sample" data-id="${esc(s.id)}">${esc(isActive ? t("common.open") : t("common.select"))}</button>
                <button class="btn btn-ghost btn-xs" type="button" data-action="delete-sample" data-id="${esc(s.id)}" title="${esc(t("samples.vault.remove_tip"))}">✕</button>
              </div>
            </td>
          </tr>
        `;
      })
      .join("");

    const localRows = filteredLocal
      .map(
        (it) => `
          <tr>
            <td>
              <div class="mono" style="font-weight:500">${esc(it.name)}</div>
              <div style="font-size:11px;color:var(--text-muted)">${esc(it.display_path)}</div>
            </td>
            <td>${UI.kindBadge(it.kind)}</td>
            <td class="mono num">${it.dex_count ? `${it.dex_count} DEX` : "—"}</td>
            <td class="mono num">${esc(UI.fmtBytes(it.size_bytes))}</td>
            <td class="num">
              <button class="btn btn-primary btn-xs" type="button" data-action="import-local" data-path="${esc(it.path)}">${esc(t("samples.local.import_btn"))}</button>
            </td>
          </tr>
        `
      )
      .join("");

    return `
      <div class="view-header">
        <div>
          <h1 class="view-title">${esc(t("samples.title"))}</h1>
          <p class="view-subtitle">${esc(t("samples.subtitle"))}</p>
        </div>
        <div class="view-actions">
          <button class="btn btn-subtle btn-sm" type="button" data-action="refresh-library">${esc(t("samples.refresh_lib"))}</button>
          <button class="btn btn-primary btn-sm" type="button" data-action="trigger-upload">${esc(t("samples.upload_btn"))}</button>
        </div>
      </div>

      <div class="kpi-strip">
        ${UI.kpi(t("samples.kpi.vault"), samples.length, t("samples.kpi.vault_sub"))}
        ${UI.kpi(t("samples.kpi.local"), localItems.length, (Store.localLibrary.roots || []).join(", ") || t("samples.kpi.local_none"))}
        ${UI.kpi(t("samples.kpi.active"), Store.activeSample ? Store.activeSample.name : t("common.none"), Store.activeSample ? Store.activeSample.kind.toUpperCase() : t("samples.kpi.active_none"))}
        ${UI.kpi(t("samples.kpi.jobs"), Store.jobs.filter((j) => j.status === "running").length, t("samples.kpi.jobs_sub", { count: Store.jobs.length }))}
      </div>

      <div class="tabs">
        <button class="tab-btn ${(Store.samplesTab || "intake") === "intake" ? "active" : ""}" type="button" data-action="samples-tab" data-tab="intake">${esc(t("ws.samples_tab.intake"))}</button>
        <button class="tab-btn ${Store.samplesTab === "history" ? "active" : ""}" type="button" data-action="samples-tab" data-tab="history">${esc(t("ws.samples_tab.history", { count: ((Store.workspaceHistory || {}).samples || []).length }))}</button>
      </div>

      ${
        Store.samplesTab === "history" && global.UnpackWorkspace
          ? global.UnpackWorkspace.renderHistoryPanel()
          : `
      <div id="tourSamplesLibrary">
        <div class="panel">
          <div class="panel-body">
            <div class="dropzone" id="uploadDropzone" data-action="trigger-upload">
              <h3>${esc(t("samples.dropzone.title"))}</h3>
              <p>${esc(t("samples.dropzone.desc"))}</p>
              <input type="file" id="studioFileInput" accept=".apk,.dex" multiple>
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">${esc(t("samples.vault.title"))} ${UI.badge(String(samples.length), "accent")}</div>
          </div>
          <div class="panel-body-flush">
            ${
              samples.length
                ? `<div class="table-wrap"><table class="data-table">
                    <thead><tr><th>${esc(t("samples.vault.col.sample"))}</th><th>${esc(t("common.type"))}</th><th class="num">${esc(t("common.size"))}</th><th>${esc(t("samples.vault.col.packer"))}</th><th>${esc(t("samples.vault.col.protection"))}</th><th class="num">${esc(t("common.actions"))}</th></tr></thead>
                    <tbody>${vaultRows}</tbody>
                  </table></div>`
                : `<div class="panel-body" style="color:var(--text-secondary)">${esc(t("samples.vault.empty"))}</div>`
            }
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">${esc(t("samples.local.title"))} ${UI.badge(String(filteredLocal.length), "muted")}</div>
            <div class="toolbar">
              <select class="select select-sm" id="localKindFilter">
                <option value="all" ${kindF === "all" ? "selected" : ""}>${esc(t("samples.local.all"))}</option>
                <option value="apk" ${kindF === "apk" ? "selected" : ""}>${esc(t("samples.local.apks"))}</option>
                <option value="dex_dir" ${kindF === "dex_dir" ? "selected" : ""}>${esc(t("samples.local.dex_dirs"))}</option>
                <option value="dex" ${kindF === "dex" ? "selected" : ""}>${esc(t("samples.local.dex"))}</option>
              </select>
              <input type="search" class="input input-sm" id="localSearchInput" placeholder="${esc(t("samples.local.search_ph"))}" value="${esc(Store.localFilter)}">
            </div>
          </div>
          <div class="panel-body-flush">
            ${
              filteredLocal.length
                ? `<div class="table-wrap"><table class="data-table">
                    <thead><tr><th>${esc(t("samples.local.col.target"))}</th><th>${esc(t("common.type"))}</th><th class="num">${esc(t("samples.local.col.dex"))}</th><th class="num">${esc(t("common.size"))}</th><th class="num">${esc(t("samples.local.col.action"))}</th></tr></thead>
                    <tbody>${localRows}</tbody>
                  </table></div>`
                : `<div class="panel-body" style="color:var(--text-secondary)">${esc(t("samples.local.empty"))}</div>`
            }
          </div>
        </div>
      </div>`
      }
    `;
  }

  // =========================================================================
  // 2. Scan & Packer Intelligence Workspace
  // =========================================================================

  function renderOverviewView() {
    const sample = Store.activeSample;
    if (!sample) return UI.requireSamplePrompt(t("nav.overview"));

    const scan = sample.scan_result;
    const insp = sample.inspect_result;
    const isApk = sample.kind === "apk";

    const confPct = scan ? Math.round((scan.confidence || 0) * 100) : 0;
    const riskScore = (insp && insp.risk_score) || (scan && scan.risk_score) || 0;
    const sevClass = riskScore >= 70 ? "sev-danger" : riskScore >= 40 ? "sev-warn" : "sev-ok";
    const confTone = confPct >= 60 ? "ok" : confPct >= 25 ? "warn" : "muted";
    const riskTone = riskScore >= 70 ? "danger" : riskScore >= 40 ? "warn" : "ok";

    const breakdownRows =
      scan && scan.score_breakdown
        ? scan.score_breakdown
            .map((b) => {
              const pct = b.max > 0 ? Math.min(100, Math.round((b.score / b.max) * 100)) : 0;
              return `
                <tr>
                  <td>${esc(b.dimension)}</td>
                  <td class="mono num">${Number(b.score || 0).toFixed(1)}</td>
                  <td class="mono num">${Number(b.max || 0).toFixed(1)}</td>
                  <td style="width:140px"><div class="bar-track"><div class="bar-seg ${b.matched ? "ok" : "accent"}" style="width:${pct}%"></div></div></td>
                  <td>${b.matched ? UI.badge(t("badge.hit"), "ok") : UI.badge(t("badge.miss"), "muted")}</td>
                </tr>
              `;
            })
            .join("")
        : "";

    const candidateRows =
      scan && scan.all_candidates && scan.all_candidates.length
        ? scan.all_candidates
            .map(
              (c) => `
                <tr>
                  <td style="font-weight:600">${esc(c.name)}</td>
                  <td class="mono num">${Number(c.score || 0).toFixed(1)}</td>
                  <td class="mono" style="font-size:11.5px;color:var(--text-secondary)">${esc((c.signatures || []).join(", "))}</td>
                </tr>
              `
            )
            .join("")
        : "";

    const manifest = (insp && insp.manifest) || {};
    const signing = (insp && insp.signing) || {};
    const perms = (insp && insp.permissions) || [];
    const dangerousPerms = perms.filter(
      (p) => p.protection_level === "dangerous" || p.level === "dangerous"
    );
    const findings = (insp && insp.findings) || [];
    const signingSchemes =
      signing.schemes && signing.schemes.length
        ? signing.schemes
        : [
            (signing.v1_signed || signing.v1) && "v1",
            (signing.v2_signed || signing.v2) && "v2",
            (signing.v3_signed || signing.v3) && "v3",
            signing.v31_signed && "v3.1",
          ].filter(Boolean);

    return `
      <div class="view-header">
        <div>
          <h1 class="view-title">${esc(t("overview.title"))}</h1>
          <p class="view-subtitle mono">${esc(sample.name)} &middot; SHA-256 ${esc(sample.sha256.slice(0, 16))}…</p>
        </div>
        <div class="view-actions">
          ${isApk ? `<button class="btn btn-primary btn-sm" type="button" data-action="run-scan">${esc(Store.busy.scan ? t("overview.scanning") : t("overview.run_scan"))}</button>` : ""}
          <button class="btn btn-subtle btn-sm" type="button" data-action="run-inspect">${esc(Store.busy.inspect ? t("overview.inspecting") : t("overview.refresh_intel"))}</button>
          <button class="btn btn-subtle btn-sm" type="button" data-action="nav" data-view="pipeline">${esc(t("overview.open_pipeline"))}</button>
          <button class="btn btn-subtle btn-sm" type="button" data-action="nav" data-view="inspector">${esc(t("overview.open_inspector"))}</button>
          <button class="btn btn-subtle btn-sm" type="button" data-action="nav" data-view="reports">${esc(t("overview.export_report"))}</button>
        </div>
      </div>

      <div id="tourVerdictBanner">
        <div class="verdict-banner ${sevClass}">
          <div>
            <div class="verdict-kicker">${esc(t("overview.verdict.kicker"))}</div>
            <div class="verdict-title">
              <span>${esc(scan ? scan.packer_name || t("overview.verdict.no_packer") : isApk ? t("overview.verdict.not_scanned") : t("overview.verdict.dex_ready"))}</span>
              ${scan && scan.packer_version ? UI.badge(scan.packer_version, "accent") : ""}
              ${scan ? UI.protectionBadge(scan.protection_level) : ""}
            </div>
            <div class="verdict-desc">${esc(
              (scan && (scan.strategy_reason || scan.details)) ||
                (isApk ? t("overview.verdict.desc_apk") : t("overview.verdict.desc_dex"))
            )}</div>
          </div>
          <div class="gauge-group">
            ${scan ? UI.ringGauge(confPct, t("overview.gauge.confidence"), confTone) : ""}
            ${UI.ringGauge(riskScore, t("overview.gauge.risk"), riskTone)}
          </div>
        </div>

        ${
          scan
            ? `
          <div class="grid-2">
            <div class="panel">
              <div class="panel-head">
                <div class="panel-title">${esc(t("overview.evidence.title"))}</div>
                ${UI.badge(t("overview.evidence.sigs", { count: (scan.matched_signatures || []).length }), "accent")}
              </div>
              <div class="panel-body-flush">
                <table class="data-table">
                  <thead><tr><th>${esc(t("overview.evidence.dim"))}</th><th class="num">${esc(t("overview.evidence.score"))}</th><th class="num">${esc(t("overview.evidence.max"))}</th><th>${esc(t("overview.evidence.weight"))}</th><th>${esc(t("common.status"))}</th></tr></thead>
                  <tbody>${breakdownRows || `<tr><td colspan="5" style="color:var(--text-muted)">${esc(t("overview.evidence.empty"))}</td></tr>`}</tbody>
                </table>
              </div>
              ${
                scan.matched_signatures && scan.matched_signatures.length
                  ? `<div class="panel-body" style="border-top:1px solid var(--border)">
                      <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px">${esc(t("overview.evidence.matched"))}</div>
                      <div class="toolbar">${scan.matched_signatures.map((s) => UI.badge(s, "accent")).join("")}</div>
                    </div>`
                  : ""
              }
            </div>

            <div class="panel">
              <div class="panel-head">
                <div class="panel-title">${esc(t("overview.strategy.title"))}</div>
                ${scan.recommended_engine ? UI.badge(`ENGINE: ${scan.recommended_engine.toUpperCase()}`, "ok") : ""}
              </div>
              <div class="panel-body">
                <div class="kv-list" style="margin-bottom:14px">
                  <div class="kv-row"><span class="kv-k">${esc(t("overview.strategy.app_class"))}</span><span class="kv-v">${esc(scan.app_class || manifest.application_class || "—")}</span></div>
                  <div class="kv-row"><span class="kv-k">${esc(t("overview.strategy.rec_engine"))}</span><span class="kv-v">${esc(scan.recommended_engine || "auto")}</span></div>
                  <div class="kv-row"><span class="kv-k">${esc(t("overview.strategy.flags"))}</span><span class="kv-v">${esc((scan.recommended_flags || []).join(" ") || t("common.none"))}</span></div>
                  <div class="kv-row"><span class="kv-k">${esc(t("overview.strategy.assets"))}</span><span class="kv-v">${(scan.suspicious_assets || []).length}</span></div>
                </div>
                ${
                  candidateRows
                    ? `<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px">${esc(t("overview.strategy.candidates"))}</div>
                       <table class="data-table"><thead><tr><th>${esc(t("overview.strategy.vendor"))}</th><th class="num">${esc(t("overview.evidence.score"))}</th><th>${esc(t("overview.strategy.signatures"))}</th></tr></thead><tbody>${candidateRows}</tbody></table>`
                    : `<div style="color:var(--text-muted);font-size:12px">${esc(t("overview.strategy.no_candidates"))}</div>`
                }
              </div>
            </div>
          </div>
        `
            : ""
        }
      </div>

      ${
        insp
          ? `
        <div class="grid-2">
          <div class="panel">
            <div class="panel-head">
              <div class="panel-title">${esc(t("overview.manifest.title"))}</div>
              ${UI.badge(t("overview.manifest.grade", { grade: insp.risk_grade || "A" }), riskTone)}
            </div>
            <div class="panel-body">
              <div class="kv-list">
                <div class="kv-row"><span class="kv-k">${esc(t("overview.manifest.package"))}</span><span class="kv-v">${esc(manifest.package || manifest.package_name || "—")}</span></div>
                <div class="kv-row"><span class="kv-k">${esc(t("overview.manifest.version"))}</span><span class="kv-v">${esc(manifest.version_name || "—")} (${esc(manifest.version_code || "—")})</span></div>
                <div class="kv-row"><span class="kv-k">${esc(t("overview.manifest.sdk"))}</span><span class="kv-v">${esc(manifest.min_sdk || "—")} / ${esc(manifest.target_sdk || "—")}</span></div>
                <div class="kv-row"><span class="kv-k">${esc(t("overview.manifest.debuggable"))}</span><span class="kv-v">${manifest.debuggable ? UI.badge("TRUE", "danger") : UI.badge("FALSE", "ok")}</span></div>
                <div class="kv-row"><span class="kv-k">${esc(t("overview.manifest.signing"))}</span><span class="kv-v">${
                  signingSchemes.length
                    ? `${esc(signingSchemes.join(" / "))}${signing.is_debug_cert ? " " + UI.badge("DEBUG CERT", "warn") : ""}`
                    : esc(t("overview.manifest.unsigned"))
                }</span></div>
                <div class="kv-row"><span class="kv-k">${esc(t("overview.manifest.permissions"))}</span><span class="kv-v">${esc(t("overview.manifest.perms_val", { total: perms.length, dangerous: dangerousPerms.length }))}</span></div>
                <div class="kv-row"><span class="kv-k">${esc(t("overview.manifest.dex_native"))}</span><span class="kv-v">${(insp.dex_files || []).length} DEX &middot; ${(insp.native_libs || []).length} SO</span></div>
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head">
              <div class="panel-title">${esc(t("overview.findings.title"))}</div>
              ${UI.badge(String(findings.length), findings.length ? "warn" : "ok")}
            </div>
            <div class="panel-body-flush">
              ${
                findings.length
                  ? `<table class="data-table"><thead><tr><th>${esc(t("overview.findings.severity"))}</th><th>${esc(t("overview.findings.finding"))}</th><th>${esc(t("common.detail"))}</th></tr></thead><tbody>
                      ${findings
                        .map(
                          (f) =>
                            `<tr><td>${UI.severityBadge(f.severity)}</td><td style="font-weight:600">${esc(f.title)}</td><td style="color:var(--text-secondary)">${esc(f.description || f.detail || "")}${f.evidence ? `<div class="mono" style="font-size:11px;color:var(--text-muted);margin-top:2px">${esc(f.evidence)}</div>` : ""}</td></tr>`
                        )
                        .join("")}
                    </tbody></table>`
                  : `<div class="panel-body" style="color:var(--text-secondary)">${esc(t("overview.findings.empty"))}</div>`
              }
            </div>
          </div>
        </div>
      `
          : ""
      }
      ${
        global.UnpackAI
          ? global.UnpackAI.renderEmbeddedCard("scan")
          : ""
      }

      ${
        global.UnpackWorkspace
          ? global.UnpackWorkspace.renderNotesBookmarksPanel(sample)
          : ""
      }
    `;
  }

  // =========================================================================
  // 3. APK & DEX Inspector Workspace (3-Pane Pro Browser)
  // =========================================================================

  function renderInspectorView() {
    const sample = Store.activeSample;
    if (!sample) return UI.requireSamplePrompt(t("nav.inspector"));

    const d = Store.dex;
    const dexOptions = (d.list || [])
      .map(
        (x) =>
          `<option value="${esc(x.name)}" ${x.name === d.selectedDex ? "selected" : ""}>${esc(x.name)} (${x.classes} cls &middot; ${x.size_kb} KB)</option>`
      )
      .join("");

    const page = d.classesPage;
    const classesList = (page && page.classes) || [];
    const classItems = classesList
      .map((c) => {
        const active = c.name === d.selectedClass;
        const shortName = c.name.replace(/^L|;$/g, "").split("/").pop();
        return `
          <button class="list-row-btn ${active ? "active" : ""}" type="button" data-action="select-class" data-class="${esc(c.name)}">
            <div class="list-row-main">
              <span class="mono">${esc(shortName)}</span>
              <span class="list-row-sub mono">${esc(c.package)} &middot; ${c.method_count}m</span>
            </div>
            ${UI.healthBadge(c.health)}
          </button>
        `;
      })
      .join("");

    const detail = d.classDetail;
    const methodItems = detail
      ? (detail.methods || [])
          .map((m) => {
            const key = `${m.name}#${m.method_idx}`;
            const active = key === d.selectedMethodKey;
            return `
              <button class="list-row-btn ${active ? "active" : ""}" type="button"
                data-action="select-method"
                data-class="${esc(detail.name)}"
                data-method="${esc(m.name)}"
                data-idx="${esc(m.method_idx)}">
                <div class="list-row-main">
                  <span class="mono">${esc(m.name)}</span>
                  <span class="list-row-sub mono">${esc(m.kind)} &middot; ${m.insns_size}u &middot; r${m.registers_size}</span>
                </div>
                ${UI.healthBadge(m.health)}
              </button>
            `;
          })
          .join("")
      : "";

    const dis = d.disasm;
    let disasmContent = `<div class="panel-body" style="color:var(--text-muted)">${esc(t("inspector.select_method_hint"))}</div>`;
    if (dis) {
      if (dis.instructions && dis.instructions.length) {
        const rows = dis.instructions
          .map((ins) => {
            const opCls = ins.mnemonic.startsWith("invoke")
              ? "op-invoke"
              : ins.mnemonic.startsWith("return")
              ? "op-ret"
              : ins.mnemonic === "nop"
              ? "op-nop"
              : "";
            const argCls = ins.ref_kind ? `ref-${esc(ins.ref_kind)}` : "";
            return `
              <tr>
                <td class="disasm-off">${esc(ins.offset)}</td>
                <td class="disasm-hex">${esc(ins.hex)}</td>
                <td class="disasm-op ${opCls}">${esc(ins.mnemonic)}</td>
                <td class="disasm-arg ${argCls}">${esc(ins.operand || "")}</td>
              </tr>
            `;
          })
          .join("");
        const bmKey = `${d.selectedDex}::${dis.class_name || d.selectedClass}->${dis.method_name}#${dis.method_idx}`;
        const isBookmarked = (sample.bookmarks || []).some((b) => b.key === bmKey);
        const methodAiBusy = Boolean((Store.aiLoading || {}).method);
        const methodAiList = (sample.ai_analyses || []).filter((a) => a.module === "method");
        const activeMethodAi =
          methodAiList.find((a) => a.id === (Store.aiSelectedByModule || {}).method) || methodAiList[0] || null;
        disasmContent = `
          <div style="padding:8px 12px;border-bottom:1px solid var(--border);background:var(--bg-inset);font-size:11.5px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between" class="mono">
            <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
              <span><strong>${esc(dis.method_name)}${dis.signature ? esc(dis.signature) : ""}</strong></span>
              <span style="color:var(--text-secondary)">code_off=0x${Number(dis.code_off || 0).toString(16)}</span>
              <span style="color:var(--text-secondary)">regs=${dis.registers_size}</span>
              <span style="color:var(--text-secondary)">units=${dis.insns_size}</span>
              ${dis.truncated ? UI.badge("TRUNCATED", "warn") : ""}
            </div>
            <div class="toolbar">
              <button class="btn ${isBookmarked ? "btn-primary" : "btn-subtle"} btn-xs" type="button"
                data-action="toggle-bookmark"
                data-dex="${esc(d.selectedDex || "")}"
                data-class="${esc(dis.class_name || d.selectedClass || "")}"
                data-method="${esc(dis.method_name || "")}"
                data-idx="${esc(dis.method_idx ?? 0)}">
                ${isBookmarked ? "★" : "☆"} ${esc(isBookmarked ? t("ws.bookmarks.remove") : t("ws.bookmarks.add"))}
              </button>
              <button class="btn btn-primary btn-xs" type="button" data-action="ai-run-method" ${methodAiBusy ? "disabled" : ""}>
                ✦ ${esc(methodAiBusy ? t("ai.card.running") : t("ai.mod.method.btn"))}
              </button>
            </div>
          </div>
          ${
            methodAiBusy || activeMethodAi
              ? `<div class="disasm-ai-drawer">
                  <div class="toolbar" style="justify-content:space-between;margin-bottom:6px">
                    <span class="badge badge-violet">✦ ${esc(t("ai.mod.method.title"))}</span>
                    ${activeMethodAi ? `<button class="btn btn-ghost btn-xs" type="button" data-action="ai-copy" data-module="method">${esc(t("ai.card.copy"))}</button>` : ""}
                  </div>
                  ${
                    methodAiBusy
                      ? `<div class="ai-loading-row"><span class="ai-spinner"></span><span>${esc(t("ai.card.running"))}</span></div>`
                      : global.UnpackAI
                      ? global.UnpackAI.renderSafeMarkdown(activeMethodAi.markdown)
                      : ""
                  }
                </div>`
              : ""
          }
          <div style="overflow:auto;flex:1">
            <table class="disasm-table"><tbody>${rows}</tbody></table>
          </div>
        `;
      } else {
        disasmContent = `<div class="panel-body" style="color:var(--text-secondary)">${esc(dis.note || t("inspector.no_insns"))}</div>`;
      }
    }

    const stringsView = `
      <div class="panel" id="tourDexLayout">
        <div class="panel-head">
          <div class="panel-title">${esc(t("inspector.strings.title"))}</div>
          <div class="toolbar">
            <input type="search" class="input input-sm" id="dexStringsInput" placeholder="${esc(t("inspector.strings.ph"))}" value="${esc(d.stringsQuery)}" style="width:280px">
            <button class="btn btn-primary btn-sm" type="button" data-action="search-strings">${esc(t("common.search"))}</button>
          </div>
        </div>
        <div class="panel-body-flush">
          <div class="table-wrap">
            <table class="data-table">
              <thead><tr><th style="width:90px">${esc(t("inspector.strings.col.index"))}</th><th style="width:110px">${esc(t("inspector.strings.col.cat"))}</th><th>${esc(t("inspector.strings.col.val"))}</th><th class="num" style="width:80px">${esc(t("inspector.strings.col.len"))}</th></tr></thead>
              <tbody>
                ${
                  d.stringsHits && d.stringsHits.length
                    ? d.stringsHits
                        .map((s) => {
                          const idx = s.index ?? s.string_idx ?? 0;
                          const cat = s.category || "plain";
                          const catTone = cat === "secret" || cat === "anti_analysis" ? "danger" : cat === "url" || cat === "ip" ? "warn" : "muted";
                          const val = s.value || "";
                          return `<tr><td class="mono" style="color:var(--text-muted)">#${idx}</td><td>${UI.badge(cat, catTone)}</td><td class="mono" style="word-break:break-all">${esc(val)}</td><td class="mono num">${s.length ?? val.length}</td></tr>`;
                        })
                        .join("")
                    : `<tr><td colspan="4" style="color:var(--text-muted)">${esc(t("inspector.strings.empty", { dex: d.selectedDex || "DEX" }))}</td></tr>`
                }
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    return `
      <div class="view-header">
        <div>
          <h1 class="view-title">${esc(t("inspector.title"))}</h1>
          <p class="view-subtitle">${esc(t("inspector.subtitle"))}</p>
        </div>
        <div class="view-actions">
          <select class="select select-sm mono" id="dexFileSelect" style="min-width:220px">
            ${dexOptions || `<option value="">${esc(t("inspector.no_dex"))}</option>`}
          </select>
          <button class="btn ${d.tab === "classes" ? "btn-primary" : "btn-subtle"} btn-sm" type="button" data-action="dex-tab" data-tab="classes">${esc(t("inspector.tab.classes"))}</button>
          <button class="btn ${d.tab === "strings" ? "btn-primary" : "btn-subtle"} btn-sm" type="button" data-action="dex-tab" data-tab="strings">${esc(t("inspector.tab.strings"))}</button>
        </div>
      </div>

      ${
        d.tab === "strings"
          ? stringsView
          : `
        <div class="dex-layout" id="tourDexLayout">
          <!-- Pane 1: Class Browser -->
          <div class="dex-pane">
            <div class="dex-pane-head">
              <div class="dex-pane-title">
                <span>${esc(t("inspector.pane.classes"))}</span>
                <span class="mono">${page ? `${classesList.length} / ${page.total}` : "0"}</span>
              </div>
              <input type="search" class="input input-sm" id="dexClassSearch" placeholder="${esc(t("inspector.filter_classes_ph"))}" value="${esc(d.query)}">
              <div class="toolbar">
                <select class="select select-sm" id="dexHealthFilter" style="flex:1">
                  <option value="" ${!d.health ? "selected" : ""}>${esc(t("inspector.health.all"))}</option>
                  <option value="ok" ${d.health === "ok" ? "selected" : ""}>${esc(t("inspector.health.ok"))}</option>
                  <option value="nop" ${d.health === "nop" ? "selected" : ""}>${esc(t("inspector.health.nop"))}</option>
                  <option value="vmp" ${d.health === "vmp" ? "selected" : ""}>${esc(t("inspector.health.vmp"))}</option>
                </select>
                <button class="btn btn-subtle btn-xs" type="button" data-action="filter-classes">${esc(t("common.apply"))}</button>
              </div>
            </div>
            <div class="dex-pane-list">
              ${classItems || `<div style="padding:14px;color:var(--text-muted);font-size:12px">${esc(t("inspector.no_classes"))}</div>`}
            </div>
          </div>

          <!-- Pane 2: Method Browser -->
          <div class="dex-pane">
            <div class="dex-pane-head">
              <div class="dex-pane-title">
                <span>${esc(t("inspector.pane.methods"))}</span>
                <span class="mono">${detail ? (detail.methods || []).length : 0}</span>
              </div>
              <div class="mono" style="font-size:11px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(detail ? detail.name : "")}">
                ${esc(detail ? detail.name : t("inspector.select_class"))}
              </div>
            </div>
            <div class="dex-pane-list">
              ${methodItems || `<div style="padding:14px;color:var(--text-muted);font-size:12px">${esc(t("inspector.select_class_hint"))}</div>`}
            </div>
          </div>

          <!-- Pane 3: Disassembly Preview -->
          <div class="dex-pane">
            <div class="dex-pane-head">
              <div class="dex-pane-title">
                <span>${esc(t("inspector.pane.disasm"))}</span>
                <span class="mono">${dis ? esc(t("inspector.insns_count", { count: (dis.instructions || []).length })) : "—"}</span>
              </div>
            </div>
            ${disasmContent}
          </div>
        </div>
      `
      }
    `;
  }

  // =========================================================================
  // 4. Repair & Verify Lab Workspace
  // =========================================================================

  function renderRepairView() {
    const sample = Store.activeSample;
    if (!sample) return UI.requireSamplePrompt(t("nav.repair"));

    const vSum = Store.verifySummary;
    const rep = Store.repairResult;

    const verifyRows =
      vSum && vSum.results
        ? vSum.results
            .map(
              (r) => `
                <tr>
                  <td class="mono" style="font-weight:600">${esc(r.file)}</td>
                  <td>${r.valid ? UI.badge(t("badge.valid"), "ok") : UI.badge(t("badge.issues"), "danger")}</td>
                  <td class="mono num">${Number(r.health_score || 0).toFixed(0)}/100</td>
                  <td class="mono num">${UI.fmtNum((r.stats || {}).class_count)}</td>
                  <td class="mono num">${UI.fmtNum((r.stats || {}).nop_only_methods)}</td>
                  <td class="mono num">${Math.round(((r.stats || {}).code_coverage || 0) * 100)}%</td>
                  <td style="font-size:12px;color:var(--text-secondary)">${esc((r.issues || []).join("; ") || t("repair.clean_header"))}</td>
                </tr>
              `
            )
            .join("")
        : "";

    const diffCards =
      rep && rep.diffs
        ? rep.diffs
            .map((d) => {
              const b = d.before || {};
              const a = d.after || {};
              const delta = Number(d.health_delta || 0);
              const deltaTone = delta > 0 ? "ok" : delta < 0 ? "danger" : "muted";
              const actions = ((d.repair || {}).actions || []).join(" · ");
              const beforeStatus = b.valid ? t("badge.valid") : `${(b.issues || []).length}`;
              return `
                <div class="diff-card">
                  <div class="diff-head">
                    <div class="toolbar">
                      <span class="mono" style="font-weight:700">${esc(d.file)}</span>
                      ${a.valid ? UI.badge(t("repair.diff.after_valid"), "ok") : UI.badge(t("repair.diff.after_warn"), "warn")}
                      ${UI.badge(`HEALTH ${delta >= 0 ? "+" : ""}${delta}`, deltaTone)}
                    </div>
                    <div class="mono" style="font-size:11.5px;color:var(--text-secondary)">${esc(actions)}</div>
                  </div>
                  <div class="diff-cols">
                    <div class="diff-box">
                      <h4>${esc(t("repair.diff.before", { status: beforeStatus }))}</h4>
                      <ul class="issue-list">
                        ${
                          (b.issues || []).length
                            ? b.issues.map((x) => `<li>${UI.badge("OLD", "danger")}<span>${esc(x)}</span></li>`).join("")
                            : `<li style="color:var(--ok)">${esc(t("repair.diff.before_clean"))}</li>`
                        }
                      </ul>
                    </div>
                    <div class="diff-box">
                      <h4>${esc(t("repair.diff.after", { resolved: (d.resolved_issues || []).length, remaining: (d.remaining_issues || []).length }))}</h4>
                      <ul class="issue-list">
                        ${(d.resolved_issues || []).map((x) => `<li>${UI.badge("FIXED", "ok")}<span>${esc(x)}</span></li>`).join("")}
                        ${(d.remaining_issues || []).map((x) => `<li>${UI.badge("OPEN", "warn")}<span>${esc(x)}</span></li>`).join("")}
                        ${
                          !(d.resolved_issues || []).length && !(d.remaining_issues || []).length
                            ? `<li style="color:var(--ok)">${esc(t("repair.diff.after_clean"))}</li>`
                            : ""
                        }
                      </ul>
                    </div>
                  </div>
                </div>
              `;
            })
            .join("")
        : "";

    return `
      <div class="view-header">
        <div>
          <h1 class="view-title">${esc(t("repair.title"))}</h1>
          <p class="view-subtitle">${esc(t("repair.subtitle"))}</p>
        </div>
        <div class="view-actions">
          <button class="btn btn-subtle btn-sm" type="button" data-action="run-verify">${esc(Store.busy.verify ? t("repair.btn_verifying") : t("repair.btn_verify"))}</button>
          <button class="btn btn-primary btn-sm" type="button" data-action="run-repair">${esc(Store.busy.repair ? t("repair.btn_repairing") : t("repair.btn_repair"))}</button>
          ${
            rep && rep.artifact
              ? `<a class="btn btn-subtle btn-sm" href="${esc(rep.artifact.download_url)}">${esc(t("repair.btn_download"))}</a>`
              : ""
          }
        </div>
      </div>

      ${
        vSum
          ? `
        <div class="kpi-strip">
          ${UI.kpi(t("repair.kpi.eval"), vSum.total)}
          ${UI.kpi(t("repair.kpi.valid"), vSum.valid_count, "", "ok")}
          ${UI.kpi(t("repair.kpi.issues"), vSum.invalid_count, "", vSum.invalid_count ? "danger" : "ok")}
          ${UI.kpi(t("repair.kpi.health"), `${vSum.avg_health}/100`)}
        </div>
        <div class="panel">
          <div class="panel-head"><div class="panel-title">${esc(t("repair.matrix.title"))}</div></div>
          <div class="panel-body-flush">
            <div class="table-wrap">
              <table class="data-table">
                <thead><tr><th>DEX</th><th>${esc(t("common.status"))}</th><th class="num">${esc(t("repair.matrix.health"))}</th><th class="num">${esc(t("repair.matrix.classes"))}</th><th class="num">NOP</th><th class="num">${esc(t("repair.matrix.coverage"))}</th><th>${esc(t("repair.matrix.diag"))}</th></tr></thead>
                <tbody>${verifyRows}</tbody>
              </table>
            </div>
          </div>
        </div>
      `
          : ""
      }

      ${
        diffCards
          ? `<div style="margin-bottom:10px;display:flex;align-items:center;justify-content:space-between">
              <h2 style="font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-secondary)">${esc(t("repair.diff.title"))}</h2>
              ${UI.badge(t("repair.diff.resolved_badge", { count: rep.resolved_issues_total || 0 }), "ok")}
            </div>${diffCards}`
          : !vSum
          ? UI.emptyState(
              t("repair.empty.title"),
              t("repair.empty.desc"),
              `<div class="toolbar" style="justify-content:center">
                <button class="btn btn-subtle" type="button" data-action="run-verify">${esc(t("repair.btn_verify"))}</button>
                <button class="btn btn-primary" type="button" data-action="run-repair">${esc(t("repair.btn_repair"))}</button>
              </div>`
            )
          : ""
      }
    `;
  }

  // =========================================================================
  // 5. VMP & Native Analysis Studio
  // =========================================================================

  function renderVmpView() {
    const sample = Store.activeSample;
    if (!sample) return UI.requireSamplePrompt(t("nav.vmp"));

    const vmp = sample.vmp_result;
    const insp = sample.inspect_result;
    const xref = sample.xref_result;
    const tab = Store.vmpTab || "stubs";

    const totalM = (vmp && vmp.total_methods) || 0;
    const normPct = totalM ? Math.round((vmp.normal_count / totalM) * 100) : 0;
    const nopPct = totalM ? Math.round((vmp.nop_count / totalM) * 100) : 0;
    const vmpPct = totalM ? Math.max(vmp.vmp_count ? 1 : 0, Math.round((vmp.vmp_count / totalM) * 100)) : 0;

    const searchQ = (Store.vmpSearch || "").trim().toLowerCase();
    const filteredStubs = ((vmp && vmp.vmp_methods) || []).filter((m) => {
      const cls = m.class_name || m.class || "";
      const meth = m.method_name || m.method || "";
      return !searchQ || `${cls} ${meth} ${m.dex || ""}`.toLowerCase().includes(searchQ);
    });

    const nativeLibs = (insp && insp.native_libs) || [];
    const getLibIndicators = (n) => {
      const merged = [
        ...(n.security_indicators || []),
        ...(n.vmp_indicators || []),
        ...(n.dex2c_indicators || []),
        ...(n.anti_debug_indicators || []),
        ...(n.crypto_indicators || []),
        ...(n.risk_flags || []),
      ];
      if (n.is_security_related && !merged.length) merged.push("security-lib");
      return Array.from(new Set(merged));
    };
    const secLibCount = nativeLibs.filter((n) => n.is_security_related || getLibIndicators(n).length > 0).length;

    const sensitiveCount = (x) => {
      const sa = x && x.sensitive_apis;
      if (!sa) return 0;
      if (Array.isArray(sa)) return sa.length;
      return Object.values(sa).reduce((acc, arr) => acc + (Array.isArray(arr) ? arr.length : 0), 0);
    };
    const formatIoc = (item) => {
      if (typeof item === "string") return { value: item, count: null };
      if (item && typeof item === "object") return { value: item.value || String(item), count: item.caller_count ?? null };
      return { value: String(item || ""), count: null };
    };

    return `
      <div class="view-header">
        <div>
          <h1 class="view-title">${esc(t("vmp.title"))}</h1>
          <p class="view-subtitle">${esc(t("vmp.subtitle"))}</p>
        </div>
        <div class="view-actions">
          <button class="btn btn-primary btn-sm" type="button" data-action="run-vmp">${esc(Store.busy.vmp ? t("vmp.btn_vmp_busy") : t("vmp.btn_vmp"))}</button>
          <button class="btn btn-subtle btn-sm" type="button" data-action="run-xref">${esc(Store.busy.xref ? t("vmp.btn_xref_busy") : t("vmp.btn_xref"))}</button>
        </div>
      </div>

      ${
        vmp
          ? `
        <div class="kpi-strip">
          ${UI.kpi(t("vmp.kpi.methods"), UI.fmtNum(vmp.total_methods), t("vmp.kpi.dex_sub", { count: vmp.dex_analyzed || 1 }))}
          ${UI.kpi(t("vmp.kpi.normal"), UI.fmtNum(vmp.normal_count), `${normPct}%`, "ok")}
          ${UI.kpi(t("vmp.kpi.nop"), UI.fmtNum(vmp.nop_count), `${nopPct}%`, vmp.nop_count ? "warn" : "ok")}
          ${UI.kpi(t("vmp.kpi.stubs"), UI.fmtNum(vmp.vmp_count), `${(vmp.vmp_ratio * 100).toFixed(2)}%`, vmp.vmp_count ? "danger" : "ok")}
          ${UI.kpi(t("vmp.kpi.risk"), `${vmp.risk_score || 0}/100`, (vmp.verdict || "clean").toUpperCase(), vmp.risk_score >= 50 ? "danger" : "ok")}
        </div>

        <div class="panel">
          <div class="panel-body">
            <div style="display:flex;justify-content:space-between;font-size:11.5px;margin-bottom:6px">
              <span>${esc(t("vmp.dist.title"))}</span>
              <span class="mono" style="color:var(--text-secondary)">Normal ${normPct}% &middot; NOP ${nopPct}% &middot; VMP ${vmpPct}%</span>
            </div>
            <div class="bar-track" style="height:10px">
              <div class="bar-seg ok" style="width:${normPct}%"></div>
              <div class="bar-seg warn" style="width:${nopPct}%"></div>
              <div class="bar-seg danger" style="width:${vmpPct}%"></div>
            </div>
          </div>
        </div>
      `
          : ""
      }

      <div class="tabs">
        <button class="tab-btn ${tab === "stubs" ? "active" : ""}" type="button" data-action="vmp-tab" data-tab="stubs">${esc(t("vmp.tab.stubs"))}</button>
        <button class="tab-btn ${tab === "native" ? "active" : ""}" type="button" data-action="vmp-tab" data-tab="native">${esc(t("vmp.tab.native", { count: nativeLibs.length }))}</button>
        <button class="tab-btn ${tab === "xref" ? "active" : ""}" type="button" data-action="vmp-tab" data-tab="xref">${esc(t("vmp.tab.xref"))}</button>
      </div>

      ${global.UnpackAI ? global.UnpackAI.renderEmbeddedCard("vmp_native", { compact: true }) : ""}

      ${
        tab === "stubs"
          ? vmp
            ? `
          <div class="grid-2">
            <div class="panel">
              <div class="panel-head"><div class="panel-title">${esc(t("vmp.dispatchers.title"))}</div></div>
              <div class="panel-body-flush">
                <table class="data-table">
                  <thead><tr><th>${esc(t("vmp.dispatchers.col_target"))}</th><th class="num">${esc(t("vmp.dispatchers.col_calls"))}</th></tr></thead>
                  <tbody>
                    ${
                      (vmp.dispatchers || []).length
                        ? vmp.dispatchers.map((d) => `<tr><td class="mono">${esc(d.dispatcher || d.target)}</td><td class="mono num">${d.stub_count ?? d.call_count ?? 0}</td></tr>`).join("")
                        : `<tr><td colspan="2" style="color:var(--text-muted)">${esc(t("vmp.dispatchers.empty"))}</td></tr>`
                    }
                  </tbody>
                </table>
              </div>
            </div>
            <div class="panel">
              <div class="panel-head"><div class="panel-title">${esc(t("vmp.density.title"))}</div></div>
              <div class="panel-body-flush">
                <table class="data-table">
                  <thead><tr><th>${esc(t("vmp.density.col_class"))}</th><th class="num">${esc(t("vmp.density.col_stubs"))}</th></tr></thead>
                  <tbody>
                    ${
                      (vmp.class_density || []).length
                        ? vmp.class_density.map((c) => `<tr><td class="mono">${esc(c.class_name || c.class)}</td><td class="mono num">${c.vmp_count ?? c.vmp_methods ?? 0}</td></tr>`).join("")
                        : `<tr><td colspan="2" style="color:var(--text-muted)">${esc(t("vmp.density.empty"))}</td></tr>`
                    }
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head">
              <div class="panel-title">${esc(t("vmp.stubs.title", { count: filteredStubs.length }))}</div>
              <input type="search" class="input input-sm" id="vmpSearchInput" style="width:220px" placeholder="${esc(t("vmp.stubs.ph"))}" value="${esc(Store.vmpSearch)}">
            </div>
            <div class="panel-body-flush">
              <div class="table-wrap">
                <table class="data-table">
                  <thead><tr><th>DEX</th><th>${esc(t("vmp.density.col_class"))}</th><th>${esc(t("vmp.stubs.col_method"))}</th><th class="num">${esc(t("vmp.stubs.col_units"))}</th></tr></thead>
                  <tbody>
                    ${
                      filteredStubs.length
                        ? filteredStubs
                            .slice(0, 150)
                            .map(
                              (m) =>
                                `<tr><td class="mono">${esc(m.dex || "classes.dex")}</td><td class="mono">${esc(m.class_name || m.class || "")}</td><td class="mono">${esc(m.method_name || m.method || "")}</td><td class="mono num">${m.insns_size || 0}</td></tr>`
                            )
                            .join("")
                        : `<tr><td colspan="4" style="color:var(--text-muted)">${esc(t("vmp.stubs.empty"))}</td></tr>`
                    }
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        `
            : UI.emptyState(
                t("vmp.empty.title"),
                t("vmp.empty.desc"),
                `<button class="btn btn-primary" type="button" data-action="run-vmp">${esc(t("vmp.btn_vmp"))}</button>`
              )
          : tab === "native"
          ? `
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">${esc(t("vmp.native.title"))}</div>
            ${UI.badge(t("vmp.native.sec_badge", { count: secLibCount }), secLibCount ? "warn" : "muted")}
          </div>
          <div class="panel-body-flush">
            ${
              nativeLibs.length
                ? `<div class="table-wrap"><table class="data-table">
                    <thead><tr><th>${esc(t("vmp.native.col_lib"))}</th><th>ABI</th><th>${esc(t("vmp.native.col_arch"))}</th><th>${esc(t("vmp.native.col_mit"))}</th><th class="num">${esc(t("common.size"))}</th><th>${esc(t("vmp.native.col_ind"))}</th></tr></thead>
                    <tbody>
                      ${nativeLibs
                        .map((n) => {
                          const isPie = n.is_pie ?? n.pie;
                          const inds = getLibIndicators(n);
                          const mits = [
                            isPie ? UI.badge("PIE", "ok") : "",
                            n.has_nx ? UI.badge("NX", "ok") : "",
                            n.relro && n.relro !== "none" ? UI.badge(`RELRO:${n.relro}`, n.relro === "full" ? "ok" : "warn") : "",
                            n.has_canary ? UI.badge("CANARY", "ok") : "",
                          ].filter(Boolean);
                          const archText = [n.elf_class, n.arch || (n.bits ? `${n.bits}b` : "")].filter(Boolean).join(" ") || "—";
                          return `<tr>
                            <td class="mono" style="font-weight:600">${esc(n.name)}</td>
                            <td class="mono">${esc(n.abi)}</td>
                            <td class="mono">${esc(archText)}</td>
                            <td>${mits.length ? mits.join(" ") : UI.badge("—", "muted")}</td>
                            <td class="mono num">${esc(UI.fmtBytes(n.size_bytes))}</td>
                            <td>${inds.length ? inds.slice(0, 6).map((k) => UI.badge(k, "warn")).join(" ") : UI.badge("standard", "muted")}</td>
                          </tr>`;
                        })
                        .join("")}
                    </tbody>
                  </table></div>`
                : `<div class="panel-body" style="color:var(--text-secondary)">${esc(t("vmp.native.empty"))}</div>`
            }
          </div>
        </div>
      `
          : xref
          ? `
        <div class="kpi-strip">
          ${UI.kpi(t("vmp.xref.kpi_strings"), UI.fmtNum((xref.counts || {}).strings))}
          ${UI.kpi(t("vmp.xref.kpi_methods"), UI.fmtNum((xref.counts || {}).method_calls ?? (xref.counts || {}).method_targets))}
          ${UI.kpi(t("vmp.xref.kpi_refl"), UI.fmtNum((xref.counts || {}).reflection_calls), "", (xref.counts || {}).reflection_calls ? "warn" : "ok")}
          ${UI.kpi(t("vmp.xref.kpi_apis"), UI.fmtNum(sensitiveCount(xref)))}
        </div>
        <div class="grid-2">
          <div class="panel">
            <div class="panel-head"><div class="panel-title">${esc(t("vmp.xref.refl_title"))}</div></div>
            <div class="panel-body-flush">
              <div class="table-wrap">
                <table class="data-table">
                  <thead><tr><th>${esc(t("vmp.xref.col_caller"))}</th><th>${esc(t("vmp.xref.col_sink"))}</th></tr></thead>
                  <tbody>
                    ${
                      (xref.reflection_calls || []).length
                        ? xref.reflection_calls
                            .slice(0, 80)
                            .map(
                              (r) =>
                                `<tr><td class="mono">${esc((r.caller || {}).class || "")}→${esc((r.caller || {}).method || "")}</td><td class="mono" style="color:var(--warn)">${esc(r.target)}</td></tr>`
                            )
                            .join("")
                        : `<tr><td colspan="2" style="color:var(--text-muted)">${esc(t("vmp.xref.refl_empty"))}</td></tr>`
                    }
                  </tbody>
                </table>
              </div>
            </div>
          </div>
          <div class="panel">
            <div class="panel-head"><div class="panel-title">${esc(t("vmp.xref.ioc_title"))}</div></div>
            <div class="panel-body">
              <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px">${esc(t("vmp.xref.urls", { count: ((xref.iocs || {}).urls || []).length }))}</div>
              <div class="mono" style="font-size:11.5px;max-height:170px;overflow:auto;background:var(--bg-inset);padding:8px;border-radius:4px;border:1px solid var(--border);margin-bottom:12px">
                ${
                  ((xref.iocs || {}).urls || []).length
                    ? (xref.iocs || {}).urls
                        .map((raw) => {
                          const it = formatIoc(raw);
                          return `<div style="margin-bottom:3px">${esc(it.value)}${it.count !== null ? ` <span style="color:var(--text-muted)">(${it.count})</span>` : ""}</div>`;
                        })
                        .join("")
                    : `<span style="color:var(--text-muted)">${esc(t("vmp.xref.none"))}</span>`
                }
              </div>
              <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px">${esc(t("vmp.xref.ips", { count: ((xref.iocs || {}).ips || []).length }))}</div>
              <div class="mono" style="font-size:11.5px;background:var(--bg-inset);padding:8px;border-radius:4px;border:1px solid var(--border)">
                ${
                  ((xref.iocs || {}).ips || []).length
                    ? (xref.iocs || {}).ips
                        .map((raw) => UI.badge(formatIoc(raw).value, "muted"))
                        .join(" ")
                    : `<span style="color:var(--text-muted)">${esc(t("vmp.xref.none"))}</span>`
                }
              </div>
            </div>
          </div>
        </div>
      `
          : UI.emptyState(
              t("vmp.xref.empty_title"),
              t("vmp.xref.empty_desc"),
              `<button class="btn btn-primary" type="button" data-action="run-xref">${esc(t("vmp.btn_xref"))}</button>`
            )
      }
    `;
  }

  // =========================================================================
  // 6. Deep Pipeline Studio (Delegated to pipeline.js)
  // =========================================================================

  function renderPipelineView() {
    if (global.UnpackPipeline) {
      return global.UnpackPipeline.renderWorkspace();
    }
    return UI.requireSamplePrompt(t("nav.pipeline"));
  }

  // =========================================================================
  // 7. Commercial Reports & Artifact Export Center
  // =========================================================================

  function renderReportsView() {
    const sample = Store.activeSample;
    if (!sample) return UI.requireSamplePrompt(t("nav.reports"));

    const fmt = Store.reportFormat || "html";
    const artifacts = sample.artifacts || [];
    const lang = global.UnpackI18n ? global.UnpackI18n.getLang() : "en";
    const langLabel = lang === "zh" ? "中文 (ZH)" : "English (EN)";

    return `
      <div class="view-header">
        <div>
          <h1 class="view-title">${esc(t("reports.title"))}</h1>
          <p class="view-subtitle">${esc(t("reports.subtitle"))}</p>
        </div>
        <div class="view-actions">
          <a class="btn btn-primary btn-sm" href="${esc(global.UnpackAPI.reportUrl(sample.id, "html", true, lang))}">${esc(t("reports.dl_html"))}</a>
          <a class="btn btn-subtle btn-sm" href="${esc(global.UnpackAPI.reportUrl(sample.id, "markdown", true, lang))}">${esc(t("reports.dl_md"))}</a>
          <a class="btn btn-subtle btn-sm" href="${esc(global.UnpackAPI.reportUrl(sample.id, "sarif", true, lang))}">${esc(t("reports.dl_sarif"))}</a>
          <a class="btn btn-subtle btn-sm" href="${esc(global.UnpackAPI.reportUrl(sample.id, "json", true, lang))}">${esc(t("reports.dl_json"))}</a>
        </div>
      </div>

      <div id="tourReportsPanel">
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">
              <span>${esc(t("reports.preview.title"))}</span>
              ${UI.badge(t("reports.preview.lang_badge", { lang: langLabel }), "accent")}
            </div>
            <div class="toolbar">
              ${["html", "markdown", "sarif", "json"]
                .map(
                  (f) =>
                    `<button class="btn ${fmt === f ? "btn-primary" : "btn-subtle"} btn-xs" type="button" data-action="preview-report" data-format="${f}">${f.toUpperCase()}</button>`
                )
                .join("")}
            </div>
          </div>
          <div class="panel-body">
            ${
              fmt === "html"
                ? Store.reportPreviewHtml
                  ? `<iframe class="report-frame" sandbox="allow-scripts" id="reportPreviewFrame" title="Audit Report Preview"></iframe>`
                  : `<div style="color:var(--text-secondary)">${esc(t("reports.preview.loading_html"))}</div>`
                : `<pre class="mono" style="background:var(--bg-inset);border:1px solid var(--border);border-radius:6px;padding:14px;max-height:540px;overflow:auto;font-size:12px;white-space:pre-wrap">${esc(Store.reportPreviewText || t("reports.preview.loading_text"))}</pre>`
            }
          </div>
        </div>

        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">${esc(t("reports.artifacts.title", { count: artifacts.length }))}</div>
          </div>
          <div class="panel-body-flush">
            ${
              artifacts.length
                ? `<table class="data-table">
                    <thead><tr><th>${esc(t("reports.artifacts.filename"))}</th><th>${esc(t("common.type"))}</th><th class="num">${esc(t("common.size"))}</th><th class="num">${esc(t("common.download"))}</th></tr></thead>
                    <tbody>
                      ${artifacts
                        .map(
                          (a) =>
                            `<tr><td class="mono">${esc(a.name)}</td><td>${UI.badge(a.kind, "accent")}</td><td class="mono num">${esc(UI.fmtBytes(a.size_bytes))}</td><td class="num"><a class="btn btn-subtle btn-xs" href="${esc(a.download_url)}">${esc(t("common.download"))}</a></td></tr>`
                        )
                        .join("")}
                    </tbody>
                  </table>`
                : `<div class="panel-body" style="color:var(--text-secondary)">${esc(t("reports.artifacts.empty"))}</div>`
            }
          </div>
        </div>
      </div>
    `;
  }

  // =========================================================================
  // Task Drawer & Doctor Modal Renderers
  // =========================================================================

  function renderTaskDrawer() {
    const body = document.getElementById("taskDrawerBody");
    const liveBadge = document.getElementById("drawerLiveBadge");
    if (!body) return;

    const job = Store.activeJob;
    const runningCount = Store.jobs.filter((j) => j.status === "running").length;
    if (liveBadge) {
      liveBadge.textContent = runningCount ? t("drawer.running", { count: runningCount }) : t("drawer.idle");
      liveBadge.className = `badge mono ${runningCount ? "badge-accent" : "badge-muted"}`;
    }

    const activeSection = job
      ? `
        <div class="panel" style="margin-bottom:0">
          <div class="panel-head">
            <div class="panel-title">${esc(t("drawer.active_job", { id: job.id }))}</div>
            <div class="toolbar">
              ${UI.badge(job.status.toUpperCase(), job.status === "done" ? "ok" : job.status === "failed" ? "danger" : "accent")}
              ${job.status === "running" ? `<button class="btn btn-danger btn-xs" type="button" data-action="cancel-job" data-id="${esc(job.id)}">${esc(t("common.cancel"))}</button>` : ""}
            </div>
          </div>
          <div class="panel-body">
            <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:6px">
              <span class="mono">${esc(job.apk)}</span>
              <span class="mono" style="color:var(--accent)">${esc(job.phase)} (${job.progress || 0}%)</span>
            </div>
            <div class="bar-track" style="margin-bottom:10px">
              <div class="bar-seg ${job.status === "failed" ? "danger" : job.status === "done" ? "ok" : "accent"}" style="width:${job.progress || 0}%"></div>
            </div>
            ${job.error ? `<div style="color:var(--danger);font-size:12px;margin-bottom:8px">${esc(job.error)}</div>` : ""}
            <div class="log-console" id="jobLogConsole">
              ${
                (job.logs || []).length
                  ? job.logs
                      .map(
                        (l) =>
                          `<div class="log-line"><span class="log-ts">${esc((l.ts || "").slice(11, 19))}</span><span class="log-lvl-${esc(l.level || "info")}">[${esc(l.phase || "")}] ${esc(l.message)}</span></div>`
                      )
                      .join("")
                  : `<div style="color:var(--text-muted)">${esc(t("drawer.waiting_sse"))}</div>`
              }
            </div>
            ${
              (job.artifacts || []).length
                ? `<div class="toolbar" style="margin-top:10px">${job.artifacts
                    .map((a) => `<a class="btn btn-subtle btn-xs" href="${esc(a.download_url)}">${esc(t("common.download"))} ${esc(a.name)}</a>`)
                    .join("")}</div>`
                : ""
            }
          </div>
        </div>
      `
      : "";

    const historyRows = (Store.jobs || [])
      .map(
        (j) => `
          <button class="list-row-btn ${job && job.id === j.id ? "active" : ""}" type="button" data-action="inspect-job" data-id="${esc(j.id)}">
            <div class="list-row-main">
              <span class="mono">${esc(j.apk)}</span>
              <span class="list-row-sub mono">#${esc(j.id)} &middot; ${esc(j.phase)} &middot; ${esc((j.created_at || "").slice(11, 19))}</span>
            </div>
            ${UI.badge(j.status.toUpperCase(), j.status === "done" ? "ok" : j.status === "failed" ? "danger" : "accent")}
          </button>
        `
      )
      .join("");

    body.innerHTML = `
      ${activeSection}
      <div class="panel" style="margin-bottom:0">
        <div class="panel-head"><div class="panel-title">${esc(t("drawer.history", { count: Store.jobs.length }))}</div></div>
        <div class="panel-body" style="padding:6px">
          ${historyRows || `<div style="padding:12px;color:var(--text-muted);font-size:12px">${esc(t("drawer.empty"))}</div>`}
        </div>
      </div>
    `;

    const consoleEl = document.getElementById("jobLogConsole");
    if (consoleEl) consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  function renderDoctorModalHtml(doc) {
    if (!doc) return `<div style="color:var(--text-secondary)">${esc(t("doctor.loading"))}</div>`;
    const checkRows = (doc.checks || [])
      .map(
        (c) => `
          <tr>
            <td style="font-weight:600">${esc(c.name)}</td>
            <td>${UI.badge(c.status.toUpperCase(), c.status === "pass" ? "ok" : c.status === "fail" ? "danger" : "warn")}</td>
            <td class="mono" style="font-size:11.5px">${esc(c.summary || c.detail || c.version || "—")}</td>
            <td class="mono" style="font-size:11px;color:var(--text-muted)">${esc(c.remediation || c.hint || "—")}</td>
          </tr>
        `
      )
      .join("");

    const engRows = (doc.engines || [])
      .map(
        (e) => `
          <tr>
            <td class="mono" style="font-weight:600">${esc(e.name)}</td>
            <td>${e.available ? UI.badge(t("badge.ready"), "ok") : UI.badge(t("badge.unavailable"), "muted")}</td>
            <td style="color:var(--text-secondary)">${esc(e.reason || t("doctor.ready_desc"))}</td>
          </tr>
        `
      )
      .join("");

    const overall = String(doc.overall_status || "ok").toLowerCase();
    const overallTone = overall === "healthy" || overall === "pass" ? "ok" : overall === "unhealthy" || overall === "fail" ? "danger" : "warn";

    return `
      <div class="kpi-strip" style="margin-bottom:14px">
        ${UI.kpi(t("doctor.overall"), overall.toUpperCase(), "", overallTone)}
        ${UI.kpi(t("doctor.python"), doc.python_version || "—")}
        ${UI.kpi(t("doctor.adb"), (doc.devices || []).length)}
        ${UI.kpi(t("doctor.engines_ready"), (doc.engines || []).filter((e) => e.available).length)}
      </div>
      <h4 style="font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin:12px 0 6px">${esc(t("doctor.sec_engines"))}</h4>
      <table class="data-table" style="margin-bottom:16px">
        <thead><tr><th>${esc(t("doctor.col_engine"))}</th><th>${esc(t("common.status"))}</th><th>${esc(t("common.detail"))}</th></tr></thead>
        <tbody>${engRows}</tbody>
      </table>
      <h4 style="font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin:12px 0 6px">${esc(t("doctor.sec_deps"))}</h4>
      <table class="data-table">
        <thead><tr><th>${esc(t("doctor.col_check"))}</th><th>${esc(t("common.status"))}</th><th>${esc(t("common.detail"))}</th><th>${esc(t("doctor.col_remediation"))}</th></tr></thead>
        <tbody>${checkRows}</tbody>
      </table>
    `;
  }

  global.UnpackViews = {
    samples: renderSamplesView,
    overview: renderOverviewView,
    inspector: renderInspectorView,
    repair: renderRepairView,
    vmp: renderVmpView,
    pipeline: renderPipelineView,
    reports: renderReportsView,
    renderTaskDrawer,
    renderDoctorModalHtml,
  };
})(window);
