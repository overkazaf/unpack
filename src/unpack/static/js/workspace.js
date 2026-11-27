/**
 * UNPACK Studio — Persistent Workspace Switcher, Saved History & Analyst Notes/Bookmarks
 */
(function (global) {
  "use strict";

  function t(key, params) {
    return global.UnpackI18n ? global.UnpackI18n.t(key, params) : key;
  }

  function esc(v) {
    return global.UnpackUI ? global.UnpackUI.esc(v) : String(v || "");
  }

  let managerOpen = false;

  async function loadWorkspaces() {
    const Store = global.UnpackStore;
    const API = global.UnpackAPI;
    try {
      const res = await API.listWorkspaces();
      Store.workspaces = res.workspaces || [];
      Store.activeWorkspaceId = res.active_workspace_id || "default";
      Store.degraded.workspaces = false;
      await refreshHistory(Store.activeWorkspaceId);
      renderSidebarWidget();
      if (managerOpen) renderManagerModal();
    } catch (err) {
      Store.degraded.workspaces = true;
      renderSidebarWidget();
      if (global.UnpackUI) {
        global.UnpackUI.toast(t("toast.load_failed", { target: t("ws.label"), error: err.message || "error" }), "warn");
      }
    }
  }

  async function refreshHistory(wsId) {
    const Store = global.UnpackStore;
    const API = global.UnpackAPI;
    const id = wsId || Store.activeWorkspaceId || "default";
    try {
      const hist = await API.getWorkspaceHistory(id, 60);
      Store.workspaceHistory = {
        samples: hist.samples || [],
        pipeline_runs: hist.pipeline_runs || [],
        ai_analyses: hist.ai_analyses || [],
      };
    } catch (err) {
      Store.degraded.workspaceHistory = true;
    }
  }

  async function activateWorkspace(wsId) {
    const Store = global.UnpackStore;
    const API = global.UnpackAPI;
    const UI = global.UnpackUI;
    try {
      const res = await API.activateWorkspace(wsId);
      Store.activeWorkspaceId = res.active_workspace_id || wsId;
      Store.samples = res.samples || [];
      Store.activeSampleId = null;
      Store.activeSample = null;
      Store.resetSampleSubState();
      Store.workspaceHistory = {
        samples: (await API.getWorkspaceHistory(Store.activeWorkspaceId, 60)).samples || [],
        pipeline_runs: res.pipeline_runs || [],
        ai_analyses: res.ai_analyses || [],
      };
      await loadWorkspaces();
      UI.toast(t("ws.toast.switched", { name: (res.workspace || {}).name || wsId }), "ok");
      if (global.UnpackApp) global.UnpackApp.render();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function createWorkspaceFromModal() {
    const nameEl = document.getElementById("wsCreateName");
    const descEl = document.getElementById("wsCreateDesc");
    const name = (nameEl?.value || "").trim();
    if (!name) return;
    try {
      const res = await global.UnpackAPI.createWorkspace({
        name,
        description: (descEl?.value || "").trim(),
        activate: true,
      });
      global.UnpackUI.toast(t("ws.toast.created", { name: res.workspace.name }), "ok");
      await activateWorkspace(res.workspace.id);
      if (managerOpen) renderManagerModal();
    } catch (err) {
      global.UnpackUI.toast(err.message, "danger");
    }
  }

  async function togglePinWorkspace(wsId, pinned) {
    try {
      await global.UnpackAPI.updateWorkspace(wsId, { pinned: !pinned });
      await loadWorkspaces();
      if (managerOpen) renderManagerModal();
    } catch (err) {
      global.UnpackUI.toast(err.message, "danger");
    }
  }

  async function renameWorkspace(wsId, currentName) {
    const next = await global.UnpackUI.promptModal({
      title: t("dialog.rename_ws_title"),
      value: currentName || "",
      placeholder: t("dialog.rename_ws_ph"),
      confirmText: t("dialog.save_btn"),
    });
    if (!next || !next.trim() || next.trim() === currentName) return;
    try {
      await global.UnpackAPI.updateWorkspace(wsId, { name: next.trim() });
      await loadWorkspaces();
      if (managerOpen) renderManagerModal();
      if (global.UnpackApp) global.UnpackApp.render();
    } catch (err) {
      global.UnpackUI.toast(err.message, "danger");
    }
  }

  async function deleteWorkspace(wsId, wsName) {
    const label = wsName || (global.UnpackStore.workspaces || []).find((w) => w.id === wsId)?.name || wsId;
    const confirmed = await global.UnpackUI.confirmModal({
      title: t("dialog.confirm_delete_title"),
      message: t("dialog.confirm_delete_ws", { name: label }),
      confirmText: t("dialog.confirm_btn"),
      danger: true,
    });
    if (!confirmed) return;
    try {
      const res = await global.UnpackAPI.deleteWorkspace(wsId);
      global.UnpackUI.toast(t("ws.toast.deleted"), "muted");
      await activateWorkspace(res.active_workspace_id || "default");
      if (managerOpen) renderManagerModal();
    } catch (err) {
      global.UnpackUI.toast(err.message, "danger");
    }
  }

  async function importWorkspaceBackup(file) {
    if (!file) return;
    try {
      const res = await global.UnpackAPI.importWorkspaceFile(file);
      global.UnpackUI.toast(t("ws.toast.imported", { name: res.workspace.name }), "ok");
      await activateWorkspace(res.workspace.id);
      if (managerOpen) renderManagerModal();
    } catch (err) {
      global.UnpackUI.toast(err.message, "danger");
    }
  }

  async function saveSampleNotes() {
    const Store = global.UnpackStore;
    const sample = Store.activeSample;
    if (!sample) return;
    const ta = document.getElementById("sampleNotesTextarea");
    const notes = ta ? ta.value : sample.notes || "";
    try {
      const res = await global.UnpackAPI.updateSampleNotes(sample.id, { notes });
      Store.activeSample.notes = res.sample.notes;
      global.UnpackUI.toast(t("ws.notes.saved"), "ok");
      await refreshHistory(Store.activeWorkspaceId);
    } catch (err) {
      global.UnpackUI.toast(err.message, "danger");
    }
  }

  async function toggleMethodBookmark(dexName, className, methodName, methodIdx) {
    const Store = global.UnpackStore;
    const sample = Store.activeSample;
    if (!sample) return;
    const cur = Array.isArray(sample.bookmarks) ? [...sample.bookmarks] : [];
    const key = `${dexName}::${className}->${methodName}#${methodIdx}`;
    const idx = cur.findIndex((b) => b.key === key);
    let added = false;
    if (idx >= 0) {
      cur.splice(idx, 1);
    } else {
      cur.unshift({
        key,
        dex_name: dexName,
        class_name: className,
        method_name: methodName,
        method_idx: Number(methodIdx),
        label: `${className.replace(/^L|;$/g, "").split("/").pop()}.${methodName}`,
        created_at: new Date().toISOString(),
      });
      added = true;
    }
    try {
      const res = await global.UnpackAPI.updateSampleNotes(sample.id, { bookmarks: cur });
      Store.activeSample.bookmarks = res.sample.bookmarks || cur;
      global.UnpackUI.toast(
        added ? t("ws.toast.bookmarked", { label: cur[0].label }) : t("ws.toast.unbookmarked"),
        added ? "ok" : "muted"
      );
      if (global.UnpackApp) global.UnpackApp.render();
    } catch (err) {
      global.UnpackUI.toast(err.message, "danger");
    }
  }

  async function removeBookmark(key) {
    const Store = global.UnpackStore;
    const sample = Store.activeSample;
    if (!sample) return;
    const cur = (sample.bookmarks || []).filter((b) => b.key !== key);
    try {
      const res = await global.UnpackAPI.updateSampleNotes(sample.id, { bookmarks: cur });
      Store.activeSample.bookmarks = res.sample.bookmarks || cur;
      global.UnpackUI.toast(t("ws.toast.unbookmarked"), "muted");
      if (global.UnpackApp) global.UnpackApp.render();
    } catch (err) {
      global.UnpackUI.toast(err.message, "danger");
    }
  }

  function renderSidebarWidget() {
    const host = document.getElementById("workspaceSidebarHost");
    if (!host) return;
    const Store = global.UnpackStore;
    const list = Store.workspaces || [];
    const active = list.find((w) => w.id === Store.activeWorkspaceId) || list[0];

    host.innerHTML = `
      <div class="ws-rail-card">
        <div class="ws-rail-top">
          <span class="ws-rail-kicker mono">${esc(t("ws.label"))}</span>
          <button class="ws-rail-link" type="button" data-action="open-ws-manager">${esc(t("ws.manage"))}</button>
        </div>
        <select class="select select-sm ws-rail-select" id="workspaceSwitcherSelect" aria-label="${esc(t("ws.label"))}">
          ${
            list.length
              ? list
                  .map(
                    (w) =>
                      `<option value="${esc(w.id)}" ${w.id === Store.activeWorkspaceId ? "selected" : ""}>${w.pinned ? "★ " : ""}${esc(w.name)}</option>`
                  )
                  .join("")
              : `<option value="default">Default Workspace</option>`
          }
        </select>
        ${
          active
            ? `<div class="ws-rail-meta mono">${esc(t("ws.meta", { samples: active.sample_count || 0, runs: active.pipeline_run_count || 0 }))}</div>`
            : ""
        }
      </div>
    `;

    document.getElementById("workspaceSwitcherSelect")?.addEventListener("change", (e) => {
      if (e.target.value && e.target.value !== Store.activeWorkspaceId) {
        activateWorkspace(e.target.value);
      }
    });
  }

  function openManagerModal() {
    managerOpen = true;
    renderManagerModal();
    loadWorkspaces();
  }

  function closeManagerModal() {
    managerOpen = false;
    global.UnpackUI.closeModal();
  }

  function renderManagerModal() {
    const Store = global.UnpackStore;
    const UI = global.UnpackUI;
    const list = Store.workspaces || [];

    const rows = list
      .map((w) => {
        const isActive = w.id === Store.activeWorkspaceId;
        return `
          <div class="ws-mgr-row ${isActive ? "active" : ""}">
            <div class="ws-mgr-main">
              <div class="toolbar">
                <strong>${w.pinned ? "★ " : ""}${esc(w.name)}</strong>
                ${isActive ? UI.badge(t("ws.modal.active_badge"), "accent") : ""}
                ${w.is_default ? UI.badge(t("ws.modal.default_badge"), "muted") : ""}
              </div>
              <div class="ws-mgr-sub">${esc(w.description || "—")}</div>
              <div class="ws-mgr-meta mono">${esc(t("ws.meta", { samples: w.sample_count || 0, runs: w.pipeline_run_count || 0 }))} &middot; AI: ${w.ai_analysis_count || 0} &middot; ${esc((w.updated_at || "").slice(0, 19).replace("T", " "))}</div>
            </div>
            <div class="toolbar">
              ${!isActive ? `<button class="btn btn-primary btn-xs" type="button" data-action="ws-activate" data-id="${esc(w.id)}">${esc(t("ws.modal.switch"))}</button>` : ""}
              <button class="btn btn-subtle btn-xs" type="button" data-action="ws-pin" data-id="${esc(w.id)}" data-pinned="${w.pinned ? "1" : "0"}">${esc(w.pinned ? t("ws.modal.unpin") : t("ws.modal.pin"))}</button>
              <button class="btn btn-subtle btn-xs" type="button" data-action="ws-rename" data-id="${esc(w.id)}" data-name="${esc(w.name)}">${esc(t("ws.modal.rename"))}</button>
              <a class="btn btn-subtle btn-xs" href="${esc(global.UnpackAPI.workspaceExportUrl(w.id))}">${esc(t("ws.modal.export"))}</a>
              ${!w.is_default ? `<button class="btn btn-danger btn-xs" type="button" data-action="ws-delete" data-id="${esc(w.id)}">${esc(t("ws.modal.delete"))}</button>` : ""}
            </div>
          </div>
        `;
      })
      .join("");

    const html = `
      <p style="font-size:12.5px;color:var(--text-secondary);margin-bottom:14px">${esc(t("ws.modal.subtitle"))}</p>
      <div class="ws-create-box">
        <div class="ws-create-title">${esc(t("ws.modal.create_title"))}</div>
        <div class="toolbar" style="margin-top:8px">
          <input type="text" class="input input-sm" id="wsCreateName" placeholder="${esc(t("ws.modal.name_ph"))}" style="flex:1;min-width:180px">
          <input type="text" class="input input-sm" id="wsCreateDesc" placeholder="${esc(t("ws.modal.desc_ph"))}" style="flex:1;min-width:160px">
          <button class="btn btn-primary btn-sm" type="button" data-action="ws-create">${esc(t("ws.modal.create_btn"))}</button>
          <button class="btn btn-subtle btn-sm" type="button" data-action="ws-import-trigger">${esc(t("ws.modal.import_btn"))}</button>
          <input type="file" id="wsImportFileInput" accept=".json,application/json" style="display:none">
        </div>
      </div>
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin:14px 0 8px">${esc(t("ws.modal.list_title", { count: list.length }))}</div>
      <div class="ws-mgr-list">${rows}</div>
    `;

    UI.openModal(t("ws.modal.title"), html);
    document.getElementById("wsImportFileInput")?.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) importWorkspaceBackup(e.target.files[0]);
    });
  }

  function renderHistoryPanel() {
    const Store = global.UnpackStore;
    const UI = global.UnpackUI;
    const hist = Store.workspaceHistory || { samples: [], pipeline_runs: [], ai_analyses: [] };
    const savedSamples = hist.samples || [];
    const runs = hist.pipeline_runs || [];
    const analyses = hist.ai_analyses || [];

    const sampleRows = savedSamples
      .map((s) => {
        const sid = s.sample_id;
        const liveMatch = (Store.samples || []).find((x) => x.id === sid);
        const fileOk = liveMatch ? liveMatch.file_available : false;
        const packer = (s.scan_result || {}).packer_name;
        const prot = (s.scan_result || {}).protection_level;
        const aiCnt = (s.ai_analyses || []).length;
        const bmCnt = (s.bookmarks || []).length;
        return `
          <tr>
            <td>
              <div class="mono" style="font-weight:600">${esc(s.filename)}</div>
              <div style="font-size:11px;color:var(--text-muted)">
                ${esc((s.updated_at || "").slice(0, 19).replace("T", " "))} &middot; <span class="mono">${esc((s.sha256 || sid).slice(0, 12))}</span>
                ${s.notes ? ` &middot; 📝 ${esc(s.notes.slice(0, 48))}` : ""}
              </div>
            </td>
            <td>${fileOk ? UI.badge(t("ws.history.local_ready"), "ok") : UI.badge(t("ws.history.snapshot_only"), "violet")}</td>
            <td>${packer ? `${UI.badge(packer, "accent")} ${UI.protectionBadge(prot)}` : UI.badge("—", "muted")}</td>
            <td class="mono num">AI ${aiCnt} &middot; ★ ${bmCnt}</td>
            <td class="num">
              <button class="btn btn-primary btn-xs" type="button" data-action="select-sample" data-id="${esc(sid)}">${esc(t("ws.history.resume"))}</button>
            </td>
          </tr>
        `;
      })
      .join("");

    const runRows = runs
      .slice(0, 20)
      .map(
        (r) => `
          <tr>
            <td class="mono">${esc(r.name || r.id)}</td>
            <td>${UI.badge(String(r.status || "done").toUpperCase(), r.status === "done" || r.status === "completed" ? "ok" : r.status === "failed" ? "danger" : "accent")}</td>
            <td style="color:var(--text-secondary)">${esc(r.summary || r.stage || "—")}</td>
            <td class="mono num">${r.duration_ms ? `${r.duration_ms} ms` : "—"}</td>
            <td class="mono" style="font-size:11px;color:var(--text-muted)">${esc((r.created_at || "").slice(0, 19).replace("T", " "))}</td>
          </tr>
        `
      )
      .join("");

    const aiRows = analyses
      .slice(0, 20)
      .map(
        (a) => `
          <tr>
            <td>${UI.badge(a.module, "violet")}</td>
            <td style="font-weight:600">${esc(a.title || a.module)}</td>
            <td style="color:var(--text-secondary);font-size:12px">${esc((a.summary || "").slice(0, 110))}</td>
            <td class="mono" style="font-size:11px">${esc(a.provider)}/${esc(a.model)}</td>
            <td class="mono" style="font-size:11px;color:var(--text-muted)">${esc((a.created_at || "").slice(0, 19).replace("T", " "))}</td>
          </tr>
        `
      )
      .join("");

    return `
      <div class="panel" id="workspaceHistoryPanel">
        <div class="panel-head">
          <div class="panel-title">${esc(t("ws.history.title"))} ${UI.badge(String(savedSamples.length), "accent")}</div>
          <button class="btn btn-subtle btn-xs" type="button" data-action="open-ws-manager">${esc(t("ws.manage"))}</button>
        </div>
        <div class="panel-body" style="padding-bottom:8px">
          <p style="font-size:12px;color:var(--text-secondary)">${esc(t("ws.history.subtitle"))}</p>
        </div>
        <div class="panel-body-flush">
          ${
            savedSamples.length
              ? `<div class="table-wrap"><table class="data-table">
                  <thead><tr><th>${esc(t("samples.vault.col.sample"))}</th><th>${esc(t("common.status"))}</th><th>${esc(t("samples.vault.col.packer"))}</th><th class="num">AI / ★</th><th class="num">${esc(t("common.actions"))}</th></tr></thead>
                  <tbody>${sampleRows}</tbody>
                </table></div>`
              : `<div class="panel-body" style="color:var(--text-muted)">${esc(t("samples.vault.empty"))}</div>`
          }
        </div>
      </div>

      <div class="grid-2">
        <div class="panel">
          <div class="panel-head"><div class="panel-title">${esc(t("ws.history.runs_title", { count: runs.length }))}</div></div>
          <div class="panel-body-flush">
            ${
              runs.length
                ? `<div class="table-wrap"><table class="data-table">
                    <thead><tr><th>Run</th><th>${esc(t("common.status"))}</th><th>Summary</th><th class="num">Time</th><th>At</th></tr></thead>
                    <tbody>${runRows}</tbody>
                  </table></div>`
                : `<div class="panel-body" style="color:var(--text-muted)">${esc(t("ws.history.runs_empty"))}</div>`
            }
          </div>
        </div>

        <div class="panel">
          <div class="panel-head"><div class="panel-title">${esc(t("ws.history.ai_title", { count: analyses.length }))}</div></div>
          <div class="panel-body-flush">
            ${
              analyses.length
                ? `<div class="table-wrap"><table class="data-table">
                    <thead><tr><th>Module</th><th>Title</th><th>Summary</th><th>Model</th><th>At</th></tr></thead>
                    <tbody>${aiRows}</tbody>
                  </table></div>`
                : `<div class="panel-body" style="color:var(--text-muted)">${esc(t("ws.history.ai_empty"))}</div>`
            }
          </div>
        </div>
      </div>
    `;
  }

  function renderNotesBookmarksPanel(sample) {
    if (!sample) return "";
    const UI = global.UnpackUI;
    const bookmarks = sample.bookmarks || [];
    return `
      <div class="panel" id="sampleNotesPanel">
        <div class="panel-head">
          <div class="panel-title">${esc(t("ws.notes.title"))}</div>
          <button class="btn btn-primary btn-xs" type="button" data-action="save-sample-notes">${esc(t("ws.notes.save"))}</button>
        </div>
        <div class="panel-body">
          <div class="grid-2">
            <div class="field">
              <textarea class="input notes-textarea" id="sampleNotesTextarea" rows="4" placeholder="${esc(t("ws.notes.ph"))}">${esc(sample.notes || "")}</textarea>
            </div>
            <div>
              <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin-bottom:6px">${esc(t("ws.bookmarks.title", { count: bookmarks.length }))}</div>
              ${
                bookmarks.length
                  ? `<div class="bookmark-list">${bookmarks
                      .map(
                        (b) => `
                      <div class="bookmark-item">
                        <span class="mono" style="font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(b.class_name)}->${esc(b.method_name)}">★ ${esc(b.label || b.method_name)}</span>
                        <div class="toolbar" style="flex-shrink:0">
                          ${
                            sample.file_available
                              ? `<button class="btn btn-subtle btn-xs" type="button" data-action="jump-bookmark" data-dex="${esc(b.dex_name)}" data-class="${esc(b.class_name)}" data-method="${esc(b.method_name)}" data-idx="${esc(b.method_idx)}">${esc(t("ws.bookmarks.jump"))}</button>`
                              : ""
                          }
                          <button class="btn btn-ghost btn-xs" type="button" data-action="remove-bookmark" data-key="${esc(b.key)}">✕</button>
                        </div>
                      </div>
                    `
                      )
                      .join("")}</div>`
                  : `<div style="font-size:12px;color:var(--text-muted)">${esc(t("ws.bookmarks.empty"))}</div>`
              }
            </div>
          </div>
        </div>
      </div>
    `;
  }

  global.UnpackWorkspace = {
    loadWorkspaces,
    refreshHistory,
    activateWorkspace,
    createWorkspaceFromModal,
    togglePinWorkspace,
    renameWorkspace,
    deleteWorkspace,
    importWorkspaceBackup,
    saveSampleNotes,
    toggleMethodBookmark,
    removeBookmark,
    renderSidebarWidget,
    openManagerModal,
    closeManagerModal,
    renderManagerModal,
    renderHistoryPanel,
    renderNotesBookmarksPanel,
    isManagerOpen: () => managerOpen,
    onModalClosed: () => {
      managerOpen = false;
    },
  };
})(window);
