/**
 * UNPACK Studio — All 7 Workspace Views + Task Drawer & Doctor Modal
 */
(function (global) {
  "use strict";

  const UI = global.UnpackUI;
  const Store = global.UnpackStore;
  const esc = UI.esc;

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
            <td>${s.protection_level ? UI.protectionBadge(s.protection_level) : UI.badge("PENDING", "muted")}</td>
            <td class="num">
              <div class="toolbar" style="justify-content:flex-end">
                <button class="btn btn-subtle btn-xs" type="button" data-action="select-sample" data-id="${esc(s.id)}">${isActive ? "Open" : "Select"}</button>
                <button class="btn btn-ghost btn-xs" type="button" data-action="delete-sample" data-id="${esc(s.id)}" title="Remove from vault">✕</button>
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
              <button class="btn btn-primary btn-xs" type="button" data-action="import-local" data-path="${esc(it.path)}">Import &amp; Analyze</button>
            </td>
          </tr>
        `
      )
      .join("");

    return `
      <div class="view-header">
        <div>
          <h1 class="view-title">Samples &amp; Intake</h1>
          <p class="view-subtitle">Upload APK/DEX artifacts or mount zero-copy targets from allowlisted local libraries.</p>
        </div>
        <div class="view-actions">
          <button class="btn btn-subtle btn-sm" type="button" data-action="refresh-library">Refresh Library</button>
          <button class="btn btn-primary btn-sm" type="button" data-action="trigger-upload">Upload Files</button>
        </div>
      </div>

      <div class="kpi-strip">
        ${UI.kpi("Vault Samples", samples.length, "Deduplicated by SHA-256")}
        ${UI.kpi("Local Library", localItems.length, (Store.localLibrary.roots || []).join(", ") || "No local roots")}
        ${UI.kpi("Active Target", Store.activeSample ? Store.activeSample.name : "None", Store.activeSample ? Store.activeSample.kind.toUpperCase() : "Select a target")}
        ${UI.kpi("Active Jobs", Store.jobs.filter((j) => j.status === "running").length, `${Store.jobs.length} total recorded`)}
      </div>

      <div class="panel">
        <div class="panel-body">
          <div class="dropzone" id="uploadDropzone" data-action="trigger-upload">
            <h3>Drop Android .apk or .dex files here, or click to browse</h3>
            <p>Supports multi-file upload up to 512 MB &middot; Automatic SHA-256 deduplication &amp; instant packer scan</p>
            <input type="file" id="studioFileInput" accept=".apk,.dex" multiple>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">Workspace Sample Vault ${UI.badge(String(samples.length), "accent")}</div>
        </div>
        <div class="panel-body-flush">
          ${
            samples.length
              ? `<div class="table-wrap"><table class="data-table">
                  <thead><tr><th>Sample</th><th>Type</th><th class="num">Size</th><th>Packer</th><th>Protection</th><th class="num">Actions</th></tr></thead>
                  <tbody>${vaultRows}</tbody>
                </table></div>`
              : `<div class="panel-body" style="color:var(--text-secondary)">No samples in vault yet. Upload a file above or import from the Local Library below.</div>`
          }
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">Sandboxed Local Library ${UI.badge(String(filteredLocal.length), "muted")}</div>
          <div class="toolbar">
            <select class="select select-sm" id="localKindFilter">
              <option value="all" ${kindF === "all" ? "selected" : ""}>All Types</option>
              <option value="apk" ${kindF === "apk" ? "selected" : ""}>APKs</option>
              <option value="dex_dir" ${kindF === "dex_dir" ? "selected" : ""}>DEX Dump Dirs</option>
              <option value="dex" ${kindF === "dex" ? "selected" : ""}>Single DEX</option>
            </select>
            <input type="search" class="input input-sm" id="localSearchInput" placeholder="Filter local samples..." value="${esc(Store.localFilter)}">
          </div>
        </div>
        <div class="panel-body-flush">
          ${
            filteredLocal.length
              ? `<div class="table-wrap"><table class="data-table">
                  <thead><tr><th>Target</th><th>Type</th><th class="num">DEX</th><th class="num">Size</th><th class="num">Action</th></tr></thead>
                  <tbody>${localRows}</tbody>
                </table></div>`
              : `<div class="panel-body" style="color:var(--text-secondary)">No local samples match the current filter. Configure <code>UNPACK_LOCAL_ROOTS</code> or place APKs in <code>test_apks/</code>.</div>`
          }
        </div>
      </div>
    `;
  }

  // =========================================================================
  // 2. Scan & Packer Intelligence Workspace
  // =========================================================================

  function renderOverviewView() {
    const sample = Store.activeSample;
    if (!sample) return UI.requireSamplePrompt("Scan & Intelligence");

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
                  <td>${b.matched ? UI.badge("HIT", "ok") : UI.badge("MISS", "muted")}</td>
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
    const dangerousPerms = perms.filter((p) => p.level === "dangerous");
    const findings = (insp && insp.findings) || [];

    return `
      <div class="view-header">
        <div>
          <h1 class="view-title">Scan &amp; Packer Intelligence</h1>
          <p class="view-subtitle mono">${esc(sample.name)} &middot; SHA-256 ${esc(sample.sha256.slice(0, 16))}…</p>
        </div>
        <div class="view-actions">
          ${isApk ? `<button class="btn btn-primary btn-sm" type="button" data-action="run-scan">${Store.busy.scan ? "Scanning..." : "Run Deep Scan"}</button>` : ""}
          <button class="btn btn-subtle btn-sm" type="button" data-action="run-inspect">${Store.busy.inspect ? "Inspecting..." : "Refresh APK Intel"}</button>
          <button class="btn btn-subtle btn-sm" type="button" data-action="nav" data-view="inspector">Open DEX Inspector</button>
          <button class="btn btn-subtle btn-sm" type="button" data-action="nav" data-view="reports">Export Report</button>
        </div>
      </div>

      <div class="verdict-banner ${sevClass}">
        <div>
          <div class="verdict-kicker">PACKER &amp; PROTECTION VERDICT</div>
          <div class="verdict-title">
            <span>${esc(scan ? scan.packer_name || "No Commercial Packer Detected" : isApk ? "Scan Not Yet Executed" : "DEX Artifact Ready")}</span>
            ${scan && scan.packer_version ? UI.badge(scan.packer_version, "accent") : ""}
            ${scan ? UI.protectionBadge(scan.protection_level) : ""}
          </div>
          <div class="verdict-desc">${esc(
            (scan && (scan.strategy_reason || scan.details)) ||
              (isApk ? "Click Run Deep Scan to evaluate 24 commercial packer signature families and protection tiers." : "Use DEX Inspector, Repair Lab, or VMP Studio to inspect this DEX sample.")
          )}</div>
        </div>
        <div class="gauge-group">
          ${scan ? UI.ringGauge(confPct, "Confidence", confTone) : ""}
          ${UI.ringGauge(riskScore, "Risk Score", riskTone)}
        </div>
      </div>

      ${
        scan
          ? `
        <div class="grid-2">
          <div class="panel">
            <div class="panel-head">
              <div class="panel-title">Evidence Matrix &amp; Scoring</div>
              ${UI.badge(`${(scan.matched_signatures || []).length} Signatures`, "accent")}
            </div>
            <div class="panel-body-flush">
              <table class="data-table">
                <thead><tr><th>Dimension</th><th class="num">Score</th><th class="num">Max</th><th>Weight</th><th>Status</th></tr></thead>
                <tbody>${breakdownRows || `<tr><td colspan="5" style="color:var(--text-muted)">No breakdown available</td></tr>`}</tbody>
              </table>
            </div>
            ${
              scan.matched_signatures && scan.matched_signatures.length
                ? `<div class="panel-body" style="border-top:1px solid var(--border)">
                    <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px">Matched Indicators</div>
                    <div class="toolbar">${scan.matched_signatures.map((s) => UI.badge(s, "accent")).join("")}</div>
                  </div>`
                : ""
            }
          </div>

          <div class="panel">
            <div class="panel-head">
              <div class="panel-title">Recommended Strategy &amp; Candidates</div>
              ${scan.recommended_engine ? UI.badge(`ENGINE: ${scan.recommended_engine.toUpperCase()}`, "ok") : ""}
            </div>
            <div class="panel-body">
              <div class="kv-list" style="margin-bottom:14px">
                <div class="kv-row"><span class="kv-k">Application Class</span><span class="kv-v">${esc(scan.app_class || manifest.application_class || "—")}</span></div>
                <div class="kv-row"><span class="kv-k">Recommended Engine</span><span class="kv-v">${esc(scan.recommended_engine || "auto")}</span></div>
                <div class="kv-row"><span class="kv-k">Suggested Flags</span><span class="kv-v">${esc((scan.recommended_flags || []).join(" ") || "none")}</span></div>
                <div class="kv-row"><span class="kv-k">Suspicious Assets</span><span class="kv-v">${(scan.suspicious_assets || []).length}</span></div>
              </div>
              ${
                candidateRows
                  ? `<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px">All Scored Candidates</div>
                     <table class="data-table"><thead><tr><th>Vendor</th><th class="num">Score</th><th>Signatures</th></tr></thead><tbody>${candidateRows}</tbody></table>`
                  : `<div style="color:var(--text-muted);font-size:12px">No competing packer candidates matched.</div>`
              }
            </div>
          </div>
        </div>
      `
          : ""
      }

      ${
        insp
          ? `
        <div class="grid-2">
          <div class="panel">
            <div class="panel-head">
              <div class="panel-title">Manifest &amp; Signing Posture</div>
              ${UI.badge(`GRADE ${insp.risk_grade || "A"}`, riskTone)}
            </div>
            <div class="panel-body">
              <div class="kv-list">
                <div class="kv-row"><span class="kv-k">Package</span><span class="kv-v">${esc(manifest.package || "—")}</span></div>
                <div class="kv-row"><span class="kv-k">Version</span><span class="kv-v">${esc(manifest.version_name || "—")} (${esc(manifest.version_code || "—")})</span></div>
                <div class="kv-row"><span class="kv-k">SDK (Min / Target)</span><span class="kv-v">${esc(manifest.min_sdk || "—")} / ${esc(manifest.target_sdk || "—")}</span></div>
                <div class="kv-row"><span class="kv-k">Debuggable</span><span class="kv-v">${manifest.debuggable ? UI.badge("TRUE", "danger") : UI.badge("FALSE", "ok")}</span></div>
                <div class="kv-row"><span class="kv-k">Signing Schemes</span><span class="kv-v">${
                  signing.signed
                    ? [signing.v1 && "v1", signing.v2 && "v2", signing.v3 && "v3"].filter(Boolean).join(" / ")
                    : "Unsigned / Unknown"
                }</span></div>
                <div class="kv-row"><span class="kv-k">Permissions</span><span class="kv-v">${perms.length} total (${dangerousPerms.length} dangerous)</span></div>
                <div class="kv-row"><span class="kv-k">DEX / Native Libs</span><span class="kv-v">${(insp.dex_files || []).length} DEX &middot; ${(insp.native_libs || []).length} SO</span></div>
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head">
              <div class="panel-title">Security Findings</div>
              ${UI.badge(String(findings.length), findings.length ? "warn" : "ok")}
            </div>
            <div class="panel-body-flush">
              ${
                findings.length
                  ? `<table class="data-table"><thead><tr><th>Severity</th><th>Finding</th><th>Detail</th></tr></thead><tbody>
                      ${findings
                        .map(
                          (f) =>
                            `<tr><td>${UI.severityBadge(f.severity)}</td><td style="font-weight:600">${esc(f.title)}</td><td style="color:var(--text-secondary)">${esc(f.detail)}</td></tr>`
                        )
                        .join("")}
                    </tbody></table>`
                  : `<div class="panel-body" style="color:var(--text-secondary)">No manifest or structural security issues flagged.</div>`
              }
            </div>
          </div>
        </div>
      `
          : ""
      }
    `;
  }

  // =========================================================================
  // 3. APK & DEX Inspector Workspace (3-Pane Pro Browser)
  // =========================================================================

  function renderInspectorView() {
    const sample = Store.activeSample;
    if (!sample) return UI.requireSamplePrompt("APK & DEX Inspector");

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
    let disasmContent = `<div class="panel-body" style="color:var(--text-muted)">Select a class and method to inspect Dalvik bytecode disassembly.</div>`;
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
        disasmContent = `
          <div style="padding:8px 12px;border-bottom:1px solid var(--border);background:var(--bg-inset);font-size:11.5px;display:flex;gap:14px;flex-wrap:wrap" class="mono">
            <span><strong>${esc(dis.method_name)}</strong></span>
            <span style="color:var(--text-secondary)">code_off=0x${Number(dis.code_off || 0).toString(16)}</span>
            <span style="color:var(--text-secondary)">regs=${dis.registers_size}</span>
            <span style="color:var(--text-secondary)">units=${dis.insns_size}</span>
            ${dis.truncated ? UI.badge("TRUNCATED", "warn") : ""}
          </div>
          <div style="overflow:auto;flex:1">
            <table class="disasm-table"><tbody>${rows}</tbody></table>
          </div>
        `;
      } else {
        disasmContent = `<div class="panel-body" style="color:var(--text-secondary)">${esc(dis.note || "No instructions in this method body.")}</div>`;
      }
    }

    const stringsView = `
      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">DEX String Pool Explorer</div>
          <div class="toolbar">
            <input type="search" class="input input-sm" id="dexStringsInput" placeholder="Search string literals (URLs, keys, JNI)..." value="${esc(d.stringsQuery)}" style="width:280px">
            <button class="btn btn-primary btn-sm" type="button" data-action="search-strings">Search</button>
          </div>
        </div>
        <div class="panel-body-flush">
          <div class="table-wrap">
            <table class="data-table">
              <thead><tr><th style="width:90px">Index</th><th>Literal Value</th><th class="num" style="width:80px">Len</th></tr></thead>
              <tbody>
                ${
                  d.stringsHits && d.stringsHits.length
                    ? d.stringsHits
                        .map(
                          (s) =>
                            `<tr><td class="mono" style="color:var(--text-muted)">#${s.index}</td><td class="mono" style="word-break:break-all">${esc(s.value)}</td><td class="mono num">${s.length}</td></tr>`
                        )
                        .join("")
                    : `<tr><td colspan="3" style="color:var(--text-muted)">Enter a query or click Search to list strings from ${esc(d.selectedDex || "DEX")}.</td></tr>`
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
          <h1 class="view-title">APK &amp; DEX Inspector</h1>
          <p class="view-subtitle">Browse DEX class trees, method health states, Dalvik disassembly, and string pools.</p>
        </div>
        <div class="view-actions">
          <select class="select select-sm mono" id="dexFileSelect" style="min-width:220px">
            ${dexOptions || `<option value="">No DEX entries</option>`}
          </select>
          <button class="btn ${d.tab === "classes" ? "btn-primary" : "btn-subtle"} btn-sm" type="button" data-action="dex-tab" data-tab="classes">Class Browser</button>
          <button class="btn ${d.tab === "strings" ? "btn-primary" : "btn-subtle"} btn-sm" type="button" data-action="dex-tab" data-tab="strings">String Pool</button>
        </div>
      </div>

      ${
        d.tab === "strings"
          ? stringsView
          : `
        <div class="dex-layout">
          <!-- Pane 1: Class Browser -->
          <div class="dex-pane">
            <div class="dex-pane-head">
              <div class="dex-pane-title">
                <span>Classes</span>
                <span class="mono">${page ? `${classesList.length} / ${page.total}` : "0"}</span>
              </div>
              <input type="search" class="input input-sm" id="dexClassSearch" placeholder="Filter classes..." value="${esc(d.query)}">
              <div class="toolbar">
                <select class="select select-sm" id="dexHealthFilter" style="flex:1">
                  <option value="" ${!d.health ? "selected" : ""}>All Health</option>
                  <option value="ok" ${d.health === "ok" ? "selected" : ""}>Healthy (OK)</option>
                  <option value="nop" ${d.health === "nop" ? "selected" : ""}>NOP-Only</option>
                  <option value="vmp" ${d.health === "vmp" ? "selected" : ""}>VMP Stubs</option>
                </select>
                <button class="btn btn-subtle btn-xs" type="button" data-action="filter-classes">Apply</button>
              </div>
            </div>
            <div class="dex-pane-list">
              ${classItems || `<div style="padding:14px;color:var(--text-muted);font-size:12px">No classes matched.</div>`}
            </div>
          </div>

          <!-- Pane 2: Method Browser -->
          <div class="dex-pane">
            <div class="dex-pane-head">
              <div class="dex-pane-title">
                <span>Methods</span>
                <span class="mono">${detail ? (detail.methods || []).length : 0}</span>
              </div>
              <div class="mono" style="font-size:11px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(detail ? detail.name : "")}">
                ${esc(detail ? detail.name : "Select a class")}
              </div>
            </div>
            <div class="dex-pane-list">
              ${methodItems || `<div style="padding:14px;color:var(--text-muted);font-size:12px">Pick a class on the left to inspect its direct &amp; virtual methods.</div>`}
            </div>
          </div>

          <!-- Pane 3: Disassembly Preview -->
          <div class="dex-pane">
            <div class="dex-pane-head">
              <div class="dex-pane-title">
                <span>Dalvik Disassembly Preview</span>
                <span class="mono">${dis ? `${(dis.instructions || []).length} insns` : "—"}</span>
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
    if (!sample) return UI.requireSamplePrompt("Repair & Verify Lab");

    const vSum = Store.verifySummary;
    const rep = Store.repairResult;

    const verifyRows =
      vSum && vSum.results
        ? vSum.results
            .map(
              (r) => `
                <tr>
                  <td class="mono" style="font-weight:600">${esc(r.file)}</td>
                  <td>${r.valid ? UI.badge("VALID", "ok") : UI.badge("ISSUES", "danger")}</td>
                  <td class="mono num">${Number(r.health_score || 0).toFixed(0)}/100</td>
                  <td class="mono num">${UI.fmtNum((r.stats || {}).class_count)}</td>
                  <td class="mono num">${UI.fmtNum((r.stats || {}).nop_only_methods)}</td>
                  <td class="mono num">${Math.round(((r.stats || {}).code_coverage || 0) * 100)}%</td>
                  <td style="font-size:12px;color:var(--text-secondary)">${esc((r.issues || []).join("; ") || "Clean DEX header & checksums")}</td>
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
              return `
                <div class="diff-card">
                  <div class="diff-head">
                    <div class="toolbar">
                      <span class="mono" style="font-weight:700">${esc(d.file)}</span>
                      ${a.valid ? UI.badge("AFTER: VALID", "ok") : UI.badge("AFTER: WARNINGS", "warn")}
                      ${UI.badge(`HEALTH ${delta >= 0 ? "+" : ""}${delta}`, deltaTone)}
                    </div>
                    <div class="mono" style="font-size:11.5px;color:var(--text-secondary)">${esc(actions)}</div>
                  </div>
                  <div class="diff-cols">
                    <div class="diff-box">
                      <h4>Before Repair (${b.valid ? "Valid" : `${(b.issues || []).length} issue(s)`})</h4>
                      <ul class="issue-list">
                        ${
                          (b.issues || []).length
                            ? b.issues.map((x) => `<li>${UI.badge("OLD", "danger")}<span>${esc(x)}</span></li>`).join("")
                            : `<li style="color:var(--ok)">No structural issues detected before repair.</li>`
                        }
                      </ul>
                    </div>
                    <div class="diff-box">
                      <h4>After Repair (${(d.resolved_issues || []).length} resolved &middot; ${(d.remaining_issues || []).length} remaining)</h4>
                      <ul class="issue-list">
                        ${(d.resolved_issues || []).map((x) => `<li>${UI.badge("FIXED", "ok")}<span>${esc(x)}</span></li>`).join("")}
                        ${(d.remaining_issues || []).map((x) => `<li>${UI.badge("OPEN", "warn")}<span>${esc(x)}</span></li>`).join("")}
                        ${
                          !(d.resolved_issues || []).length && !(d.remaining_issues || []).length
                            ? `<li style="color:var(--ok)">Verified clean — header, SHA-1, Adler32 &amp; bounds valid.</li>`
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
          <h1 class="view-title">Repair &amp; Verify Lab</h1>
          <p class="view-subtitle">Validate DEX integrity, fix corrupted headers/checksums/CDEX in isolation, and inspect before/after diffs.</p>
        </div>
        <div class="view-actions">
          <button class="btn btn-subtle btn-sm" type="button" data-action="run-verify">${Store.busy.verify ? "Verifying..." : "Verify DEX Set"}</button>
          <button class="btn btn-primary btn-sm" type="button" data-action="run-repair">${Store.busy.repair ? "Repairing..." : "Repair &amp; Diff"}</button>
          ${
            rep && rep.artifact
              ? `<a class="btn btn-subtle btn-sm" href="${esc(rep.artifact.download_url)}">Download Repaired ZIP</a>`
              : ""
          }
        </div>
      </div>

      ${
        vSum
          ? `
        <div class="kpi-strip">
          ${UI.kpi("DEX Evaluated", vSum.total)}
          ${UI.kpi("Valid DEX", vSum.valid_count, "", "ok")}
          ${UI.kpi("With Issues", vSum.invalid_count, "", vSum.invalid_count ? "danger" : "ok")}
          ${UI.kpi("Avg Health Score", `${vSum.avg_health}/100`)}
        </div>
        <div class="panel">
          <div class="panel-head"><div class="panel-title">Verification Matrix</div></div>
          <div class="panel-body-flush">
            <div class="table-wrap">
              <table class="data-table">
                <thead><tr><th>DEX</th><th>Status</th><th class="num">Health</th><th class="num">Classes</th><th class="num">NOP</th><th class="num">Coverage</th><th>Diagnostics</th></tr></thead>
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
              <h2 style="font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-secondary)">Before / After Repair Health Diff</h2>
              ${UI.badge(`${rep.resolved_issues_total || 0} Issues Resolved`, "ok")}
            </div>${diffCards}`
          : !vSum
          ? UI.emptyState(
              "Ready to Verify & Repair",
              "Run non-destructive DEX verification or generate repaired DEX artifacts with full before/after diagnostics.",
              `<div class="toolbar" style="justify-content:center">
                <button class="btn btn-subtle" type="button" data-action="run-verify">Verify DEX Set</button>
                <button class="btn btn-primary" type="button" data-action="run-repair">Repair &amp; Diff</button>
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
    if (!sample) return UI.requireSamplePrompt("VMP & Native Studio");

    const vmp = sample.vmp_result;
    const insp = sample.inspect_result;
    const xref = sample.xref_result;
    const tab = Store.vmpTab || "stubs";

    const totalM = (vmp && vmp.total_methods) || 0;
    const normPct = totalM ? Math.round((vmp.normal_count / totalM) * 100) : 0;
    const nopPct = totalM ? Math.round((vmp.nop_count / totalM) * 100) : 0;
    const vmpPct = totalM ? Math.max(vmp.vmp_count ? 1 : 0, Math.round((vmp.vmp_count / totalM) * 100)) : 0;

    const searchQ = (Store.vmpSearch || "").trim().toLowerCase();
    const filteredStubs = ((vmp && vmp.vmp_methods) || []).filter(
      (m) => !searchQ || `${m.class} ${m.method} ${m.dex || ""}`.toLowerCase().includes(searchQ)
    );

    const nativeLibs = (insp && insp.native_libs) || [];

    return `
      <div class="view-header">
        <div>
          <h1 class="view-title">VMP &amp; Native Analysis Studio</h1>
          <p class="view-subtitle">Detect virtualized dispatcher stubs, native ELF hardening indicators, and reflection/IOC cross-references.</p>
        </div>
        <div class="view-actions">
          <button class="btn btn-primary btn-sm" type="button" data-action="run-vmp">${Store.busy.vmp ? "Analyzing VMP..." : "Run VMP Analysis"}</button>
          <button class="btn btn-subtle btn-sm" type="button" data-action="run-xref">${Store.busy.xref ? "Building Xref..." : "Run Xref &amp; IOCs"}</button>
        </div>
      </div>

      ${
        vmp
          ? `
        <div class="kpi-strip">
          ${UI.kpi("Methods Analyzed", UI.fmtNum(vmp.total_methods), `${vmp.dex_analyzed || 1} DEX analyzed`)}
          ${UI.kpi("Normal Bytecode", UI.fmtNum(vmp.normal_count), `${normPct}%`, "ok")}
          ${UI.kpi("NOP-Only (Extracted)", UI.fmtNum(vmp.nop_count), `${nopPct}%`, vmp.nop_count ? "warn" : "ok")}
          ${UI.kpi("VMP Stubs", UI.fmtNum(vmp.vmp_count), `${(vmp.vmp_ratio * 100).toFixed(2)}%`, vmp.vmp_count ? "danger" : "ok")}
          ${UI.kpi("VMP Risk", `${vmp.risk_score || 0}/100`, (vmp.verdict || "clean").toUpperCase(), vmp.risk_score >= 50 ? "danger" : "ok")}
        </div>

        <div class="panel">
          <div class="panel-body">
            <div style="display:flex;justify-content:space-between;font-size:11.5px;margin-bottom:6px">
              <span>Method Body Distribution</span>
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
        <button class="tab-btn ${tab === "stubs" ? "active" : ""}" type="button" data-action="vmp-tab" data-tab="stubs">VMP Stubs &amp; Dispatchers</button>
        <button class="tab-btn ${tab === "native" ? "active" : ""}" type="button" data-action="vmp-tab" data-tab="native">Native ELF Libraries (${nativeLibs.length})</button>
        <button class="tab-btn ${tab === "xref" ? "active" : ""}" type="button" data-action="vmp-tab" data-tab="xref">Xref, Reflection &amp; IOCs</button>
      </div>

      ${
        tab === "stubs"
          ? vmp
            ? `
          <div class="grid-2">
            <div class="panel">
              <div class="panel-head"><div class="panel-title">Dispatcher Clusters</div></div>
              <div class="panel-body-flush">
                <table class="data-table">
                  <thead><tr><th>Target Dispatcher</th><th class="num">Calls</th></tr></thead>
                  <tbody>
                    ${
                      (vmp.dispatchers || []).length
                        ? vmp.dispatchers.map((d) => `<tr><td class="mono">${esc(d.target)}</td><td class="mono num">${d.call_count}</td></tr>`).join("")
                        : `<tr><td colspan="2" style="color:var(--text-muted)">No VMP dispatchers clustered.</td></tr>`
                    }
                  </tbody>
                </table>
              </div>
            </div>
            <div class="panel">
              <div class="panel-head"><div class="panel-title">High-Density VMP Classes</div></div>
              <div class="panel-body-flush">
                <table class="data-table">
                  <thead><tr><th>Class</th><th class="num">Stubs</th></tr></thead>
                  <tbody>
                    ${
                      (vmp.class_density || []).length
                        ? vmp.class_density.map((c) => `<tr><td class="mono">${esc(c.class)}</td><td class="mono num">${c.vmp_methods}</td></tr>`).join("")
                        : `<tr><td colspan="2" style="color:var(--text-muted)">No VMP stub classes detected.</td></tr>`
                    }
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head">
              <div class="panel-title">Detected VMP Stub Methods (${filteredStubs.length})</div>
              <input type="search" class="input input-sm" id="vmpSearchInput" style="width:220px" placeholder="Filter class or method..." value="${esc(Store.vmpSearch)}">
            </div>
            <div class="panel-body-flush">
              <div class="table-wrap">
                <table class="data-table">
                  <thead><tr><th>DEX</th><th>Class</th><th>Method</th><th class="num">Units</th></tr></thead>
                  <tbody>
                    ${
                      filteredStubs.length
                        ? filteredStubs
                            .slice(0, 150)
                            .map(
                              (m) =>
                                `<tr><td class="mono">${esc(m.dex || "classes.dex")}</td><td class="mono">${esc(m.class)}</td><td class="mono">${esc(m.method)}</td><td class="mono num">${m.insns_size || 0}</td></tr>`
                            )
                            .join("")
                        : `<tr><td colspan="4" style="color:var(--text-muted)">No VMP stub methods found in analyzed DEX files.</td></tr>`
                    }
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        `
            : UI.emptyState(
                "No VMP Analysis Yet",
                "Run VMP analysis to classify every DEX method body and identify native VM dispatcher stubs.",
                `<button class="btn btn-primary" type="button" data-action="run-vmp">Run VMP Analysis</button>`
              )
          : tab === "native"
          ? `
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">Native SO / ELF Inventory</div>
            ${UI.badge(`${nativeLibs.filter((n) => (n.security_indicators || []).length).length} Security Indicators`, "warn")}
          </div>
          <div class="panel-body-flush">
            ${
              nativeLibs.length
                ? `<div class="table-wrap"><table class="data-table">
                    <thead><tr><th>Library</th><th>ABI</th><th>Arch</th><th>PIE</th><th class="num">Size</th><th>Indicators</th></tr></thead>
                    <tbody>
                      ${nativeLibs
                        .map(
                          (n) => `<tr>
                            <td class="mono" style="font-weight:600">${esc(n.name)}</td>
                            <td class="mono">${esc(n.abi)}</td>
                            <td class="mono">${esc(n.arch || "—")}${n.bits ? ` (${n.bits}b)` : ""}</td>
                            <td>${n.pie ? UI.badge("PIE", "ok") : UI.badge("—", "muted")}</td>
                            <td class="mono num">${esc(UI.fmtBytes(n.size_bytes))}</td>
                            <td>${(n.security_indicators || []).length ? n.security_indicators.map((k) => UI.badge(k, "warn")).join(" ") : UI.badge("standard", "muted")}</td>
                          </tr>`
                        )
                        .join("")}
                    </tbody>
                  </table></div>`
                : `<div class="panel-body" style="color:var(--text-secondary)">No native .so libraries found (or inspect an APK sample first).</div>`
            }
          </div>
        </div>
      `
          : xref
          ? `
        <div class="kpi-strip">
          ${UI.kpi("String Refs", UI.fmtNum((xref.counts || {}).strings))}
          ${UI.kpi("Method Targets", UI.fmtNum((xref.counts || {}).method_targets))}
          ${UI.kpi("Reflection Sinks", UI.fmtNum((xref.counts || {}).reflection_calls), "", (xref.counts || {}).reflection_calls ? "warn" : "ok")}
          ${UI.kpi("Sensitive APIs", (xref.sensitive_apis || []).length)}
        </div>
        <div class="grid-2">
          <div class="panel">
            <div class="panel-head"><div class="panel-title">Reflection &amp; Dynamic ClassLoading</div></div>
            <div class="panel-body-flush">
              <div class="table-wrap">
                <table class="data-table">
                  <thead><tr><th>Caller</th><th>Sink Target</th></tr></thead>
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
                        : `<tr><td colspan="2" style="color:var(--text-muted)">No reflection calls indexed.</td></tr>`
                    }
                  </tbody>
                </table>
              </div>
            </div>
          </div>
          <div class="panel">
            <div class="panel-head"><div class="panel-title">Extracted IOCs (URLs &amp; IPs)</div></div>
            <div class="panel-body">
              <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px">URLs (${((xref.iocs || {}).urls || []).length})</div>
              <div class="mono" style="font-size:11.5px;max-height:170px;overflow:auto;background:var(--bg-inset);padding:8px;border-radius:4px;border:1px solid var(--border);margin-bottom:12px">
                ${((xref.iocs || {}).urls || []).map((u) => `<div>${esc(u)}</div>`).join("") || `<span style="color:var(--text-muted)">None found</span>`}
              </div>
              <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;margin-bottom:6px">IP Addresses (${((xref.iocs || {}).ips || []).length})</div>
              <div class="mono" style="font-size:11.5px;background:var(--bg-inset);padding:8px;border-radius:4px;border:1px solid var(--border)">
                ${((xref.iocs || {}).ips || []).map((ip) => UI.badge(ip, "muted")).join(" ") || `<span style="color:var(--text-muted)">None found</span>`}
              </div>
            </div>
          </div>
        </div>
      `
          : UI.emptyState(
              "No Xref Index Yet",
              "Build a cross-reference index to surface Java reflection, DexClassLoader sinks, sensitive APIs, and URL/IP IOCs.",
              `<button class="btn btn-primary" type="button" data-action="run-xref">Run Xref &amp; IOCs</button>`
            )
      }
    `;
  }

  // =========================================================================
  // 6. Pipeline, Repack & FART Export Center
  // =========================================================================

  function renderPipelineView() {
    const sample = Store.activeSample;
    if (!sample) return UI.requireSamplePrompt("Pipeline & Repack");

    const job = Store.activeJob;
    const phases = ["scanning", "dumping", "active_invoke", "repairing", "verifying"];
    const curIdx = job ? phases.indexOf(job.phase) : -1;

    const dexSources = Store.samples
      .filter((s) => s.kind === "dex_dir" || s.kind === "dex")
      .map((s) => `<option value="${esc(s.id)}">${esc(s.name)} (${s.dex_count || 1} DEX)</option>`)
      .join("");

    return `
      <div class="view-header">
        <div>
          <h1 class="view-title">Pipeline, Repack &amp; FART Studio</h1>
          <p class="view-subtitle">Orchestrate end-to-end live unpacking with SSE streaming, rebuild unpacked APKs, or export FART binaries.</p>
        </div>
        <div class="view-actions">
          <button class="btn btn-subtle btn-sm" type="button" data-action="open-drawer">Open Live Task Logs</button>
        </div>
      </div>

      ${
        sample.kind === "apk"
          ? `
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">End-to-End Unpack Pipeline (Live SSE)</div>
            ${job ? UI.badge(job.status.toUpperCase(), job.status === "done" ? "ok" : job.status === "failed" ? "danger" : "accent") : ""}
          </div>
          <div class="panel-body">
            <div class="stepper">
              ${phases
                .map((p, idx) => {
                  let cls = "";
                  if (job) {
                    if (job.status === "done" || (curIdx > idx && job.status !== "failed")) cls = "done";
                    else if (curIdx === idx) cls = job.status === "failed" ? "fail" : "active";
                  }
                  return `<div class="step-item ${cls}"><div class="step-name">${esc(p.replace("_", " "))}</div><div class="step-bar"></div></div>`;
                })
                .join("")}
            </div>
            <div class="form-grid">
              <div class="field">
                <label for="pipeEngine">Dump Engine</label>
                <select class="select" id="pipeEngine">
                  <option value="">Auto (Recommended)</option>
                  <option value="memory">Memory (/proc/pid/mem)</option>
                  <option value="frida">Frida Instrumentation</option>
                  <option value="ebpf">eBPF Uprobe</option>
                </select>
              </div>
              <div class="field">
                <label for="pipeStartFrom">Pipeline Mode</label>
                <select class="select" id="pipeStartFrom">
                  <option value="scan_only">Static Scan Only (No Device Needed)</option>
                  <option value="repairing">Repair &amp; Verify Existing DEXs (Offline)</option>
                  <option value="scan">Full Pipeline (Scan → Dump → Repair → Verify)</option>
                  <option value="dumping">Re-Dump from Device</option>
                </select>
              </div>
              <div class="field">
                <label for="pipeTimeout">Timeout (sec)</label>
                <input type="number" class="input mono" id="pipeTimeout" value="15" min="5" max="300">
              </div>
              <div class="field">
                <label class="checkbox-row"><input type="checkbox" id="pipeDeep"> Deep Active Invoke</label>
                <label class="checkbox-row"><input type="checkbox" id="pipeAntiDetect" checked> Anti-Detection</label>
              </div>
              <div class="field">
                <button class="btn btn-primary" type="button" data-action="run-pipeline">Launch Pipeline Job</button>
              </div>
            </div>
          </div>
        </div>
      `
          : ""
      }

      <div class="grid-2">
        <div class="panel">
          <div class="panel-head"><div class="panel-title">APK Repack Center</div></div>
          <div class="panel-body">
            ${
              sample.kind === "apk"
                ? `
              <p style="color:var(--text-secondary);font-size:12.5px;margin-bottom:12px">
                Replace packed <code>classes*.dex</code> inside <strong>${esc(sample.name)}</strong> with repaired or dumped DEX files while preserving all resources.
              </p>
              <div class="field" style="margin-bottom:10px">
                <label for="repackDexSource">DEX Source</label>
                <select class="select" id="repackDexSource">
                  <option value="">Use repaired/extracted DEXs from this APK</option>
                  ${dexSources}
                </select>
              </div>
              <label class="checkbox-row" style="margin-bottom:12px">
                <input type="checkbox" id="repackStripSigs" checked> Strip stale META-INF signature entries
              </label>
              <div class="toolbar">
                <button class="btn btn-primary btn-sm" type="button" data-action="run-repack">${Store.busy.repack ? "Repacking..." : "Build Unpacked APK"}</button>
                ${
                  Store.repackResult && Store.repackResult.artifact
                    ? `<a class="btn btn-subtle btn-sm" href="${esc(Store.repackResult.artifact.download_url)}">Download ${esc(Store.repackResult.artifact.name)}</a>`
                    : ""
                }
              </div>
            `
                : `<p style="color:var(--text-secondary)">Select an APK sample as the active target to repack it with dumped DEXs.</p>`
            }
          </div>
        </div>

        <div class="panel">
          <div class="panel-head"><div class="panel-title">FART Bin / Method Exporter</div></div>
          <div class="panel-body">
            <p style="color:var(--text-secondary);font-size:12.5px;margin-bottom:14px">
              Export non-NOP Dalvik method bodies to FART-compatible <code>*_fart.bin</code> &amp; <code>*_fart.txt</code> files for downstream code-item recovery.
            </p>
            <div class="toolbar">
              <button class="btn btn-primary btn-sm" type="button" data-action="run-fart">${Store.busy.fart ? "Exporting..." : "Generate FART Bundle"}</button>
              ${
                Store.fartResult && Store.fartResult.artifact
                  ? `<a class="btn btn-subtle btn-sm" href="${esc(Store.fartResult.artifact.download_url)}">Download FART ZIP (${UI.fmtNum(Store.fartResult.total_methods)} methods)</a>`
                  : ""
              }
            </div>
          </div>
        </div>
      </div>
    `;
  }

  // =========================================================================
  // 7. Commercial Reports & Artifact Export Center
  // =========================================================================

  function renderReportsView() {
    const sample = Store.activeSample;
    if (!sample) return UI.requireSamplePrompt("Reports & Export");

    const fmt = Store.reportFormat || "html";
    const artifacts = sample.artifacts || [];

    return `
      <div class="view-header">
        <div>
          <h1 class="view-title">Commercial Report &amp; Export Center</h1>
          <p class="view-subtitle">Generate self-contained executive audit reports (HTML, Markdown, SARIF 2.1.0, JSON) and download workspace artifacts.</p>
        </div>
        <div class="view-actions">
          <a class="btn btn-primary btn-sm" href="${esc(global.UnpackAPI.reportUrl(sample.id, "html", true))}">Download HTML</a>
          <a class="btn btn-subtle btn-sm" href="${esc(global.UnpackAPI.reportUrl(sample.id, "markdown", true))}">Download Markdown</a>
          <a class="btn btn-subtle btn-sm" href="${esc(global.UnpackAPI.reportUrl(sample.id, "sarif", true))}">Download SARIF 2.1.0</a>
          <a class="btn btn-subtle btn-sm" href="${esc(global.UnpackAPI.reportUrl(sample.id, "json", true))}">Download JSON</a>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">Live Report Preview</div>
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
                ? `<iframe class="report-frame" sandbox="allow-same-origin" id="reportPreviewFrame" title="Audit Report Preview"></iframe>`
                : `<div style="color:var(--text-secondary)">Loading HTML audit report preview...</div>`
              : `<pre class="mono" style="background:var(--bg-inset);border:1px solid var(--border);border-radius:6px;padding:14px;max-height:540px;overflow:auto;font-size:12px;white-space:pre-wrap">${esc(Store.reportPreviewText || "Loading preview...")}</pre>`
          }
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">Generated Artifacts (${artifacts.length})</div>
        </div>
        <div class="panel-body-flush">
          ${
            artifacts.length
              ? `<table class="data-table">
                  <thead><tr><th>Filename</th><th>Type</th><th class="num">Size</th><th class="num">Download</th></tr></thead>
                  <tbody>
                    ${artifacts
                      .map(
                        (a) =>
                          `<tr><td class="mono">${esc(a.name)}</td><td>${UI.badge(a.kind, "accent")}</td><td class="mono num">${esc(UI.fmtBytes(a.size_bytes))}</td><td class="num"><a class="btn btn-subtle btn-xs" href="${esc(a.download_url)}">Download</a></td></tr>`
                      )
                      .join("")}
                  </tbody>
                </table>`
              : `<div class="panel-body" style="color:var(--text-secondary)">Repaired DEX ZIPs, repacked APKs, and FART bundles created for this sample appear here.</div>`
          }
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
      liveBadge.textContent = runningCount ? `${runningCount} RUNNING` : "IDLE";
      liveBadge.className = `badge mono ${runningCount ? "badge-accent" : "badge-muted"}`;
    }

    const activeSection = job
      ? `
        <div class="panel" style="margin-bottom:0">
          <div class="panel-head">
            <div class="panel-title">Active Job #${esc(job.id)}</div>
            <div class="toolbar">
              ${UI.badge(job.status.toUpperCase(), job.status === "done" ? "ok" : job.status === "failed" ? "danger" : "accent")}
              ${job.status === "running" ? `<button class="btn btn-danger btn-xs" type="button" data-action="cancel-job" data-id="${esc(job.id)}">Cancel</button>` : ""}
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
                  : `<div style="color:var(--text-muted)">Waiting for SSE events...</div>`
              }
            </div>
            ${
              (job.artifacts || []).length
                ? `<div class="toolbar" style="margin-top:10px">${job.artifacts
                    .map((a) => `<a class="btn btn-subtle btn-xs" href="${esc(a.download_url)}">Download ${esc(a.name)}</a>`)
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
        <div class="panel-head"><div class="panel-title">Job History (${Store.jobs.length})</div></div>
        <div class="panel-body" style="padding:6px">
          ${historyRows || `<div style="padding:12px;color:var(--text-muted);font-size:12px">No background jobs yet. Launch a pipeline from Pipeline &amp; Repack.</div>`}
        </div>
      </div>
    `;

    const consoleEl = document.getElementById("jobLogConsole");
    if (consoleEl) consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  function renderDoctorModalHtml(doc) {
    if (!doc) return `<div style="color:var(--text-secondary)">Loading diagnostics...</div>`;
    const checkRows = (doc.checks || [])
      .map(
        (c) => `
          <tr>
            <td style="font-weight:600">${esc(c.name)}</td>
            <td>${UI.badge(c.status.toUpperCase(), c.status === "pass" ? "ok" : c.status === "fail" ? "danger" : "warn")}</td>
            <td class="mono" style="font-size:11.5px">${esc(c.detail)}</td>
            <td class="mono" style="font-size:11px;color:var(--text-muted)">${esc(c.hint || "—")}</td>
          </tr>
        `
      )
      .join("");

    const engRows = (doc.engines || [])
      .map(
        (e) => `
          <tr>
            <td class="mono" style="font-weight:600">${esc(e.name)}</td>
            <td>${e.available ? UI.badge("READY", "ok") : UI.badge("UNAVAILABLE", "muted")}</td>
            <td style="color:var(--text-secondary)">${esc(e.reason || "Ready for dynamic dump")}</td>
          </tr>
        `
      )
      .join("");

    return `
      <div class="kpi-strip" style="margin-bottom:14px">
        ${UI.kpi("Overall", (doc.overall_status || "ok").toUpperCase(), "", doc.overall_status === "pass" ? "ok" : "warn")}
        ${UI.kpi("Python", doc.python_version || "—")}
        ${UI.kpi("ADB Devices", (doc.devices || []).length)}
        ${UI.kpi("Engines Ready", (doc.engines || []).filter((e) => e.available).length)}
      </div>
      <h4 style="font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin:12px 0 6px">Dynamic Dump Engines</h4>
      <table class="data-table" style="margin-bottom:16px">
        <thead><tr><th>Engine</th><th>Status</th><th>Detail</th></tr></thead>
        <tbody>${engRows}</tbody>
      </table>
      <h4 style="font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin:12px 0 6px">Dependencies &amp; RE Toolchain</h4>
      <table class="data-table">
        <thead><tr><th>Check</th><th>Status</th><th>Detail</th><th>Remediation</th></tr></thead>
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
