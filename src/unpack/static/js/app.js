/**
 * UNPACK Studio — Application Controller, Delegated Router, i18n & Command Palette
 */
(function (global) {
  "use strict";

  const I18n = global.UnpackI18n;
  const API = global.UnpackAPI;
  const Store = global.UnpackStore;
  const UI = global.UnpackUI;
  const Views = global.UnpackViews;
  const Pipeline = global.UnpackPipeline;
  const Onboarding = global.UnpackOnboarding;
  const Workspace = global.UnpackWorkspace;
  const AI = global.UnpackAI;

  function t(key, params) {
    return I18n ? I18n.t(key, params) : key;
  }

  function render() {
    // Sync static shell i18n labels, theme, workspace switcher & AI status
    if (I18n) I18n.applyStaticDom();
    Store.updateThemeLabel();
    if (Workspace) Workspace.renderSidebarWidget();
    if (AI) AI.updateStatusIndicators();

    // Update nav active states
    document.querySelectorAll(".nav-item[data-view]").forEach((el) => {
      el.classList.toggle("active", el.dataset.view === Store.view);
    });

    // Update top context bar
    const countEl = document.getElementById("navSampleCount");
    if (countEl) countEl.textContent = String(Store.samples.length);

    const switcher = document.getElementById("sampleSwitcher");
    if (switcher) {
      const opts = [
        `<option value="">${UI.esc(t("ctx.no_sample"))}</option>`,
        ...Store.samples.map(
          (s) =>
            `<option value="${UI.esc(s.id)}" ${s.id === Store.activeSampleId ? "selected" : ""}>${UI.esc(s.name)} [${UI.esc(s.kind.toUpperCase())}]</option>`
        ),
      ];
      switcher.innerHTML = opts.join("");
    }

    const badgesEl = document.getElementById("activeSampleBadges");
    const btnScan = document.getElementById("btnQuickScan");
    const btnRep = document.getElementById("btnQuickReport");
    const s = Store.activeSample;
    if (badgesEl) {
      if (s) {
        const parts = [UI.kindBadge(s.kind), UI.badge(UI.fmtBytes(s.size_bytes), "muted")];
        if (s.file_available === false) {
          parts.push(`<span class="badge badge-violet" title="${UI.esc(t("samples.badge.offline_tip"))}">${UI.esc(t("samples.badge.offline"))}</span>`);
        }
        if (s.scan_result && s.scan_result.packer_name) {
          parts.push(UI.badge(s.scan_result.packer_name, "accent"));
          parts.push(UI.protectionBadge(s.scan_result.protection_level));
        }
        badgesEl.innerHTML = parts.join("");
      } else {
        badgesEl.innerHTML = "";
      }
    }
    if (btnScan) btnScan.disabled = !s || s.kind !== "apk";
    if (btnRep) btnRep.disabled = !s;

    // Update Doctor engines meta
    const meta = document.getElementById("doctorEnginesMeta");
    if (meta && Store.doctor) {
      const engs = Store.doctor.engines || [];
      const ready = engs.filter((e) => e.available).length;
      meta.textContent = t("nav.engines_meta", { ready, total: engs.length });
    }

    // Update Jobs button
    const running = Store.jobs.filter((j) => j.status === "running").length;
    const jobBadge = document.getElementById("jobCountBadge");
    const jobPulse = document.getElementById("jobPulseDot");
    if (jobBadge) jobBadge.textContent = String(Store.jobs.length);
    if (jobPulse) jobPulse.classList.toggle("running", running > 0);

    // Render Workflow Journey Stepper Strip
    if (Onboarding) Onboarding.renderJourneyStrip();

    // Render active workspace
    const viewport = document.getElementById("workspaceViewport");
    if (viewport) {
      const fn = Views[Store.view] || Views.samples;
      viewport.innerHTML = fn();

      // Safely populate report preview iframe via srcdoc
      if (Store.view === "reports" && Store.reportFormat === "html" && Store.reportPreviewHtml) {
        const frame = document.getElementById("reportPreviewFrame");
        if (frame) frame.srcdoc = Store.reportPreviewHtml;
      }

      bindDynamicInputs();
    }

    if (Store.drawerOpen) Views.renderTaskDrawer();
  }

  function bindDynamicInputs() {
    const fileInput = document.getElementById("studioFileInput");
    if (fileInput) {
      fileInput.addEventListener("change", () => {
        if (fileInput.files && fileInput.files.length) handleUpload(fileInput.files);
      });
    }

    const dz = document.getElementById("uploadDropzone");
    if (dz) {
      dz.addEventListener("dragover", (e) => {
        e.preventDefault();
        dz.classList.add("drag");
      });
      dz.addEventListener("dragleave", () => dz.classList.remove("drag"));
      dz.addEventListener("drop", (e) => {
        e.preventDefault();
        dz.classList.remove("drag");
        if (e.dataTransfer && e.dataTransfer.files.length) handleUpload(e.dataTransfer.files);
      });
    }

    const localSearch = document.getElementById("localSearchInput");
    if (localSearch) {
      let localTimer = null;
      localSearch.addEventListener("input", (e) => {
        Store.localFilter = e.target.value;
        clearTimeout(localTimer);
        localTimer = setTimeout(() => {
          if (!Views.updateLocalLibraryTable()) render();
        }, 60);
      });
    }

    const localKind = document.getElementById("localKindFilter");
    if (localKind) {
      localKind.addEventListener("change", (e) => {
        Store.localKindFilter = e.target.value;
        if (!Views.updateLocalLibraryTable()) render();
      });
    }

    const dexSel = document.getElementById("dexFileSelect");
    if (dexSel) {
      dexSel.addEventListener("change", (e) => {
        Store.dex.selectedDex = e.target.value;
        Store.dex.selectedClass = null;
        Store.dex.classDetail = null;
        Store.dex.disasm = null;
        loadDexClasses();
      });
    }

    const clsSearch = document.getElementById("dexClassSearch");
    if (clsSearch) {
      clsSearch.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          Store.dex.query = clsSearch.value;
          loadDexClasses();
        }
      });
    }

    const strInput = document.getElementById("dexStringsInput");
    if (strInput) {
      strInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          Store.dex.stringsQuery = strInput.value;
          searchDexStrings();
        }
      });
    }

    const vmpSearch = document.getElementById("vmpSearchInput");
    if (vmpSearch) {
      let vmpTimer = null;
      vmpSearch.addEventListener("input", (e) => {
        Store.vmpSearch = e.target.value;
        clearTimeout(vmpTimer);
        vmpTimer = setTimeout(() => {
          if (!Views.updateVmpStubsTable()) render();
        }, 60);
      });
    }

    // Pipeline Studio live parameter bindings
    document.getElementById("pipeEngine")?.addEventListener("change", (e) => {
      Pipeline?.updateParam("engine", e.target.value);
    });
    document.getElementById("pipeTimeout")?.addEventListener("change", (e) => {
      Pipeline?.updateParam("timeout", Math.max(5, Math.min(300, Number(e.target.value) || 15)));
    });
    document.getElementById("pipeDeep")?.addEventListener("change", (e) => {
      Pipeline?.updateParam("deep", Boolean(e.target.checked));
    });
    document.getElementById("pipeAntiDetect")?.addEventListener("change", (e) => {
      Pipeline?.updateParam("antiDetect", Boolean(e.target.checked));
    });
    document.getElementById("pipeRepack")?.addEventListener("change", (e) => {
      Pipeline?.updateParam("repack", Boolean(e.target.checked));
    });
    document.getElementById("pipeGenReport")?.addEventListener("change", (e) => {
      Pipeline?.updateParam("generateReport", Boolean(e.target.checked));
    });

    // AI History switcher selects
    document.querySelectorAll("[data-ai-history-module]").forEach((sel) => {
      sel.addEventListener("change", (e) => {
        AI?.selectHistoryItem(sel.getAttribute("data-ai-history-module"), e.target.value);
      });
    });
  }

  // =========================================================================
  // Data Actions
  // =========================================================================

  async function switchView(view) {
    Store.view = view;
    document.getElementById("navRail")?.classList.remove("open");
    render();
    if (!Store.activeSample) return;

    if (view === "overview" && !Store.activeSample.inspect_result) {
      await runInspect();
    } else if (view === "inspector" && !Store.dex.list.length) {
      await loadDexList();
    } else if (view === "pipeline" && !Store.pipeline.plan) {
      await Pipeline?.refreshPlan();
    } else if (view === "reports" && !Store.reportPreviewHtml && !Store.reportPreviewText) {
      await loadReportPreview(Store.reportFormat || "html");
    }
  }

  async function refreshSamples() {
    try {
      const res = await API.listSamples();
      Store.samples = res.items || [];
      render();
      Workspace?.loadWorkspaces();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function refreshLocalLibrary() {
    try {
      Store.localLibrary = await API.localLibrary();
      render();
    } catch (err) {
      UI.toast(err.message, "warn");
    }
  }

  async function loadDoctor(checkDevices = false) {
    try {
      const doc = await API.doctor(checkDevices);
      Store.doctor = doc;
      Store.degraded.doctor = false;
      const dot = document.getElementById("doctorDot");
      const meta = document.getElementById("doctorEnginesMeta");
      if (dot) {
        const st = String(doc.overall_status || "").toLowerCase();
        dot.className = `status-dot ${st === "healthy" || st === "pass" ? "ok" : st === "unhealthy" || st === "fail" ? "fail" : "warn"}`;
      }
      if (meta) {
        const engs = doc.engines || [];
        const ready = engs.filter((e) => e.available).length;
        meta.textContent = t("nav.engines_meta", { ready, total: engs.length });
      }
      return doc;
    } catch (err) {
      Store.degraded.doctor = true;
      const dot = document.getElementById("doctorDot");
      const meta = document.getElementById("doctorEnginesMeta");
      if (dot) dot.className = "status-dot fail";
      if (meta) meta.textContent = t("status.degraded");
      return null;
    }
  }

  async function selectSample(id, targetView, preservePipeline = false) {
    if (!id) {
      Store.activeSampleId = null;
      Store.activeSample = null;
      Store.resetSampleSubState();
      render();
      return;
    }
    try {
      const res = await API.getSample(id);
      const sameSample = Store.activeSampleId === id;
      const prevPipeline = sameSample && preservePipeline ? Store.pipeline : null;

      Store.activeSampleId = id;
      Store.activeSample = res.sample;
      if (!sameSample || !preservePipeline) {
        Store.resetSampleSubState();
      } else if (prevPipeline) {
        Store.pipeline = prevPipeline;
      }

      if (res.sample.verify_results) {
        const rs = res.sample.verify_results;
        Store.verifySummary = {
          total: rs.length,
          valid_count: rs.filter((r) => r.valid).length,
          invalid_count: rs.filter((r) => !r.valid).length,
          avg_health: rs.length ? Math.round(rs.reduce((a, b) => a + (b.health_score || 0), 0) / rs.length) : 0,
          results: rs,
        };
      }
      if (res.sample.repair_diffs) {
        Store.repairResult = {
          diffs: res.sample.repair_diffs,
          resolved_issues_total: res.sample.repair_diffs.reduce((a, d) => a + (d.resolved_issues || []).length, 0),
          artifact: (res.sample.artifacts || []).find((a) => a.kind === "repaired_dex_bundle") || null,
        };
      }
      if (targetView) Store.view = targetView;
      render();
      if (Store.view === "overview" && !Store.activeSample.inspect_result) await runInspect();
      if (Store.view === "inspector" && !Store.dex.list.length) await loadDexList();
      if (Store.view === "pipeline" && !Store.pipeline.plan) await Pipeline?.refreshPlan();
      if (Store.view === "reports") await loadReportPreview(Store.reportFormat || "html");
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function handleUpload(files) {
    UI.toast(t("toast.uploading", { count: files.length }), "accent");
    try {
      const res = await API.uploadSamples(files, true);
      await refreshSamples();
      if (res.items && res.items.length) {
        const first = res.items[0];
        UI.toast(t("toast.loaded", { name: first.name }), "ok");
        await selectSample(first.id, first.kind === "apk" ? "overview" : "inspector");
      }
      if (res.errors && res.errors.length) {
        UI.toast(res.errors[0].error, "warn");
      }
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function importLocal(path) {
    UI.toast(t("toast.importing"), "accent");
    try {
      const res = await API.importLocal(path, true);
      await refreshSamples();
      UI.toast(t("toast.mounted", { name: res.sample.name }), "ok");
      await selectSample(res.sample.id, res.sample.kind === "apk" ? "overview" : "inspector");
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function importLocalSilent(path) {
    try {
      const res = await API.importLocal(path, true);
      await refreshSamples();
      await selectSample(res.sample.id);
      return res.sample;
    } catch (err) {
      UI.toast(err.message, "danger");
      return null;
    }
  }

  async function deleteSample(id, name) {
    const label = name || (Store.samples || []).find((s) => s.id === id)?.name || id;
    const confirmed = await UI.confirmModal({
      title: t("dialog.confirm_delete_title"),
      message: t("dialog.confirm_delete_sample", { name: label }),
      confirmText: t("dialog.confirm_btn"),
      danger: true,
    });
    if (!confirmed) return;
    try {
      await API.deleteSample(id);
      if (Store.activeSampleId === id) {
        Store.activeSampleId = null;
        Store.activeSample = null;
        Store.resetSampleSubState();
      }
      await refreshSamples();
      UI.toast(t("toast.removed"), "muted");
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function runScan() {
    if (!Store.activeSample) return;
    Store.busy.scan = true;
    render();
    try {
      const res = await API.scanSample(Store.activeSample.id);
      Store.activeSample.scan_result = res.scan;
      await refreshSamples();
      UI.toast(
        res.scan.packer_name ? t("toast.scan_hit", { packer: res.scan.packer_name }) : t("toast.scan_clean"),
        "ok"
      );
    } catch (err) {
      UI.toast(err.message, "danger");
    } finally {
      Store.busy.scan = false;
      render();
    }
  }

  async function runInspect(refresh = false) {
    if (!Store.activeSample) return;
    Store.busy.inspect = true;
    render();
    try {
      const res = await API.inspectSample(Store.activeSample.id, refresh);
      Store.activeSample.inspect_result = res.inspect;
    } catch (err) {
      UI.toast(err.message, "danger");
    } finally {
      Store.busy.inspect = false;
      render();
    }
  }

  async function loadDexList() {
    if (!Store.activeSample) return;
    try {
      const res = await API.listDex(Store.activeSample.id);
      Store.dex.list = res.dex_files || [];
      if (Store.dex.list.length && !Store.dex.selectedDex) {
        Store.dex.selectedDex = Store.dex.list[0].name;
      }
      render();
      if (Store.dex.selectedDex) await loadDexClasses();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function loadDexClasses() {
    if (!Store.activeSample || !Store.dex.selectedDex) return;
    try {
      const page = await API.listClasses(Store.activeSample.id, Store.dex.selectedDex, {
        q: Store.dex.query,
        health: Store.dex.health,
        package: Store.dex.pkg,
        limit: 120,
      });
      Store.dex.classesPage = page;
      render();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function selectClass(clsName) {
    if (!Store.activeSample || !Store.dex.selectedDex) return;
    Store.dex.selectedClass = clsName;
    Store.dex.selectedMethodKey = null;
    Store.dex.disasm = null;
    try {
      Store.dex.classDetail = await API.inspectClass(Store.activeSample.id, Store.dex.selectedDex, clsName);
      render();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function selectMethod(clsName, methodName, methodIdx) {
    if (!Store.activeSample || !Store.dex.selectedDex) return;
    Store.dex.selectedMethodKey = `${methodName}#${methodIdx}`;
    try {
      Store.dex.disasm = await API.disasmMethod(Store.activeSample.id, Store.dex.selectedDex, clsName, methodName, methodIdx);
      render();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function searchDexStrings() {
    if (!Store.activeSample || !Store.dex.selectedDex) return;
    try {
      const res = await API.searchStrings(Store.activeSample.id, Store.dex.selectedDex, Store.dex.stringsQuery, 150);
      Store.dex.stringsHits = res.strings || [];
      render();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function runVerify() {
    if (!Store.activeSample) return;
    Store.busy.verify = true;
    render();
    try {
      Store.verifySummary = await API.runVerify(Store.activeSample.id);
      Store.activeSample.verify_results = Store.verifySummary.results;
      UI.toast(t("toast.verified", { count: Store.verifySummary.total }), "ok");
    } catch (err) {
      UI.toast(err.message, "danger");
    } finally {
      Store.busy.verify = false;
      render();
    }
  }

  async function runRepair() {
    if (!Store.activeSample) return;
    Store.busy.repair = true;
    render();
    try {
      const res = await API.runRepair(Store.activeSample.id);
      Store.repairResult = res;
      Store.activeSample.repair_diffs = res.diffs;
      if (res.artifact) Store.activeSample.artifacts = [res.artifact, ...(Store.activeSample.artifacts || [])];
      UI.toast(t("toast.repaired", { count: res.total, resolved: res.resolved_issues_total }), "ok");
    } catch (err) {
      UI.toast(err.message, "danger");
    } finally {
      Store.busy.repair = false;
      render();
    }
  }

  async function runVmp() {
    if (!Store.activeSample) return;
    Store.busy.vmp = true;
    render();
    try {
      const res = await API.runVmp(Store.activeSample.id);
      Store.activeSample.vmp_result = res.vmp;
      UI.toast(t("toast.vmp_done", { stubs: res.vmp.vmp_count, total: res.vmp.total_methods }), "ok");
    } catch (err) {
      UI.toast(err.message, "danger");
    } finally {
      Store.busy.vmp = false;
      render();
    }
  }

  async function runXref() {
    if (!Store.activeSample) return;
    Store.busy.xref = true;
    render();
    try {
      const res = await API.runXref(Store.activeSample.id);
      Store.activeSample.xref_result = res.xref;
      Store.vmpTab = "xref";
      UI.toast(t("toast.xref_done", { count: (res.xref.counts || {}).strings || 0 }), "ok");
    } catch (err) {
      UI.toast(err.message, "danger");
    } finally {
      Store.busy.xref = false;
      render();
    }
  }

  async function runRepack() {
    if (!Store.activeSample) return;
    Store.busy.repack = true;
    render();
    try {
      const dexSrc = document.getElementById("repackDexSource")?.value || "";
      const strip = document.getElementById("repackStripSigs")?.checked ?? true;
      const res = await API.runRepack(Store.activeSample.id, dexSrc || null, strip);
      Store.repackResult = res;
      if (res.artifact) Store.activeSample.artifacts = [res.artifact, ...(Store.activeSample.artifacts || [])];
      UI.toast(t("toast.repack_done", { name: res.artifact.name }), "ok");
    } catch (err) {
      UI.toast(err.message, "danger");
    } finally {
      Store.busy.repack = false;
      render();
    }
  }

  async function runFart() {
    if (!Store.activeSample) return;
    Store.busy.fart = true;
    render();
    try {
      const res = await API.exportFart(Store.activeSample.id);
      Store.fartResult = res;
      if (res.artifact) Store.activeSample.artifacts = [res.artifact, ...(Store.activeSample.artifacts || [])];
      UI.toast(t("toast.fart_done", { count: res.total_methods }), "ok");
    } catch (err) {
      UI.toast(err.message, "danger");
    } finally {
      Store.busy.fart = false;
      render();
    }
  }

  let reportReqSeq = 0;

  async function loadReportPreview(format) {
    if (!Store.activeSample) return;
    const reqId = ++reportReqSeq;
    const sampleId = Store.activeSample.id;
    const lang = I18n ? I18n.getLang() : "en";
    Store.reportFormat = format;
    Store.reportPreviewHtml = "";
    Store.reportPreviewText = "";
    render();
    try {
      const txt = await API.fetchReportText(sampleId, format, lang);
      // Guard against stale async responses after sample/language/format switches
      if (
        reqId !== reportReqSeq ||
        Store.activeSampleId !== sampleId ||
        Store.reportFormat !== format ||
        (I18n && I18n.getLang() !== lang)
      ) {
        return;
      }
      if (format === "html") Store.reportPreviewHtml = txt;
      else Store.reportPreviewText = txt;
      render();
    } catch (err) {
      if (reqId === reportReqSeq) UI.toast(err.message, "danger");
    }
  }

  // =========================================================================
  // Async Pipeline & SSE Job Drawer
  // =========================================================================

  function setDrawerOpen(open) {
    Store.drawerOpen = open;
    const el = document.getElementById("taskDrawer");
    if (el) {
      el.classList.toggle("open", open);
      el.setAttribute("aria-hidden", String(!open));
    }
    if (open) Views.renderTaskDrawer();
  }

  async function refreshJobs() {
    try {
      const res = await API.listJobs();
      Store.jobs = res.jobs || [];
      Store.degraded.jobs = false;
      render();
    } catch (err) {
      Store.degraded.jobs = true;
      UI.toast(t("toast.load_failed", { target: t("ctx.tasks"), error: err.message || "error" }), "warn");
    }
  }

  function subscribeJob(jobId) {
    if (Store.sseSource) {
      Store.sseSource.close();
      Store.sseSource = null;
    }
    Store.activeJobId = jobId;
    Store.sseSource = API.subscribeJobEvents(jobId, {
      snapshot: (snap) => {
        Store.activeJob = snap;
        Pipeline?.syncJobStages(snap);
        render();
      },
      stage: (stPayload) => {
        Pipeline?.handleStageEvent(stPayload);
      },
      log: (entry) => {
        if (Store.activeJob) {
          Store.activeJob.logs = [...(Store.activeJob.logs || []), entry];
          if (Store.drawerOpen) Views.renderTaskDrawer();
        }
      },
      phase: (p) => {
        if (Store.activeJob) {
          Store.activeJob.phase = p.phase;
          Store.activeJob.progress = p.progress;
          render();
        }
      },
      phase_data: (pd) => {
        if (Store.activeJob) {
          Store.activeJob.phases = Store.activeJob.phases || {};
          Store.activeJob.phases[pd.key] = pd.data;
        }
      },
      artifact: (art) => {
        if (Store.activeJob) {
          Store.activeJob.artifacts = [...(Store.activeJob.artifacts || []), art];
          if (Store.drawerOpen) Views.renderTaskDrawer();
        }
      },
      done: () => {
        if (Store.activeJob) {
          Store.activeJob.status = "done";
          Store.activeJob.phase = "done";
          Store.activeJob.progress = 100;
        }
        Store.sseSource?.close();
        Store.sseSource = null;
        UI.toast(t("toast.job_done", { id: jobId }), "ok");
        refreshJobs();
        Workspace?.loadWorkspaces();
        if (Store.activeSampleId) selectSample(Store.activeSampleId, null, true);
      },
      failed: (p) => {
        if (Store.activeJob) {
          Store.activeJob.status = "failed";
          Store.activeJob.error = p.error || "Job failed";
        }
        Store.sseSource?.close();
        Store.sseSource = null;
        UI.toast(t("toast.job_failed", { id: jobId, error: p.error || "error" }), "danger");
        refreshJobs();
      },
      cancelled: () => {
        if (Store.activeJob) Store.activeJob.status = "cancelled";
        Store.sseSource?.close();
        Store.sseSource = null;
        refreshJobs();
      },
    });
  }

  async function inspectJob(jobId) {
    try {
      const job = await API.getJob(jobId);
      Store.activeJobId = jobId;
      Store.activeJob = job;
      Pipeline?.syncJobStages(job);
      if (job.status === "running") subscribeJob(jobId);
      Views.renderTaskDrawer();
      if (Store.view === "pipeline") render();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function cancelJob(jobId) {
    try {
      await API.cancelJob(jobId);
      UI.toast(t("toast.job_cancelled", { id: jobId }), "warn");
      await refreshJobs();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  // =========================================================================
  // Command Palette (Cmd+K / Ctrl+K)
  // =========================================================================

  let paletteItems = [];
  let paletteSelectedIdx = 0;

  function updatePaletteSelection(nextIdx) {
    const visibleCount = Math.min(14, paletteItems.length);
    if (!visibleCount) return;
    paletteSelectedIdx = ((nextIdx % visibleCount) + visibleCount) % visibleCount;
    const list = document.getElementById("paletteList");
    if (!list) return;
    list.querySelectorAll("[data-palette-idx]").forEach((el) => {
      const active = Number(el.dataset.paletteIdx) === paletteSelectedIdx;
      el.classList.toggle("selected", active);
      if (active && typeof el.scrollIntoView === "function") {
        el.scrollIntoView({ block: "nearest" });
      }
    });
  }

  function buildPaletteCommands() {
    const cmds = [
      { label: t("palette.cmd.ai"), cat: "AI", run: () => AI?.openSettingsModal() },
      { label: t("palette.cmd.workspace"), cat: "WS", run: () => Workspace?.openManagerModal() },
      { label: t("palette.cmd.guide"), cat: "GUIDE", run: () => Onboarding?.openWelcomeModal() },
      { label: t("palette.cmd.lang"), cat: "I18N", run: () => I18n?.toggleLang() },
      { label: t("nav.samples"), cat: "NAV", run: () => switchView("samples") },
      { label: t("nav.overview"), cat: "NAV", run: () => switchView("overview") },
      { label: t("nav.inspector"), cat: "NAV", run: () => switchView("inspector") },
      { label: t("nav.repair"), cat: "NAV", run: () => switchView("repair") },
      { label: t("nav.vmp"), cat: "NAV", run: () => switchView("vmp") },
      { label: t("nav.pipeline"), cat: "NAV", run: () => switchView("pipeline") },
      { label: t("nav.reports"), cat: "NAV", run: () => switchView("reports") },
      { label: t("palette.cmd.theme"), cat: "UI", run: () => Store.setTheme(Store.theme === "dark" ? "light" : "dark") },
      { label: t("palette.cmd.doctor"), cat: "SYS", run: () => openDoctorModal() },
      { label: t("palette.cmd.drawer"), cat: "SYS", run: () => setDrawerOpen(!Store.drawerOpen) },
    ];
    if (Store.activeSample) {
      if (Store.activeSample.kind === "apk") {
        cmds.push({ label: `${t("overview.run_scan")}: ${Store.activeSample.name}`, cat: "ACTION", run: () => runScan() });
      }
      cmds.push({ label: `${t("repair.btn_verify")}: ${Store.activeSample.name}`, cat: "ACTION", run: () => { switchView("repair"); runVerify(); } });
      cmds.push({ label: `${t("vmp.btn_vmp")}: ${Store.activeSample.name}`, cat: "ACTION", run: () => { switchView("vmp"); runVmp(); } });
    }
    Store.samples.forEach((s) => {
      cmds.push({ label: `${s.name} [${s.kind.toUpperCase()}]`, cat: "VAULT", run: () => selectSample(s.id, "overview") });
    });
    (Store.localLibrary.items || []).slice(0, 20).forEach((it) => {
      cmds.push({ label: `${t("samples.local.import_btn")}: ${it.display_path}`, cat: "LOCAL", run: () => importLocal(it.path) });
    });
    return cmds;
  }

  function renderPalette(query) {
    const list = document.getElementById("paletteList");
    if (!list) return;
    const q = (query || "").trim().toLowerCase();
    paletteItems = buildPaletteCommands().filter((c) => !q || `${c.label} ${c.cat}`.toLowerCase().includes(q));
    paletteSelectedIdx = 0;
    list.innerHTML = paletteItems
      .slice(0, 14)
      .map(
        (c, i) =>
          `<button class="palette-item ${i === 0 ? "selected" : ""}" type="button" data-palette-idx="${i}"><span>${UI.esc(c.label)}</span><span class="palette-cat">${UI.esc(c.cat)}</span></button>`
      )
      .join("") || `<div style="padding:14px;color:var(--text-muted);text-align:center">${UI.esc(t("palette.empty"))}</div>`;
  }

  function openPalette() {
    const bg = document.getElementById("paletteBackdrop");
    const inp = document.getElementById("paletteInput");
    if (!bg || !inp) return;
    bg.hidden = false;
    inp.value = "";
    renderPalette("");
    inp.focus();
  }

  function closePalette() {
    const bg = document.getElementById("paletteBackdrop");
    if (bg) bg.hidden = true;
  }

  async function openDoctorModal() {
    UI.openModal(t("doctor.title"), Views.renderDoctorModalHtml(Store.doctor));
    const fresh = await loadDoctor(true);
    if (fresh) UI.openModal(t("doctor.title"), Views.renderDoctorModalHtml(fresh));
  }

  // =========================================================================
  // Global Delegated Event Wiring
  // =========================================================================

  function initEvents() {
    document.addEventListener("click", (e) => {
      const navBtn = e.target.closest(".nav-item[data-view]");
      if (navBtn) {
        switchView(navBtn.dataset.view);
        return;
      }

      const palBtn = e.target.closest("[data-palette-idx]");
      if (palBtn) {
        const idx = Number(palBtn.dataset.paletteIdx);
        closePalette();
        if (paletteItems[idx]) paletteItems[idx].run();
        return;
      }

      const act = e.target.closest("[data-action]");
      if (!act) return;
      const action = act.dataset.action;

      if (action === "set-lang") {
        I18n?.setLang(act.dataset.lang);
      } else if (action === "open-welcome") {
        Onboarding?.openWelcomeModal();
      } else if (action === "close-welcome") {
        Onboarding?.closeWelcomeModal();
      } else if (action === "start-demo-tour") {
        Onboarding?.startDemoTour();
      } else if (action === "onboard-goal") {
        Onboarding?.handleGoalClick(act.dataset.goal);
      } else if (action === "tour-next") {
        Onboarding?.nextStep();
      } else if (action === "tour-prev") {
        Onboarding?.prevStep();
      } else if (action === "tour-end") {
        Onboarding?.endTour();
      } else if (action === "toggle-journey") {
        Store.setJourneyVisible(!Store.journeyVisible);
        Onboarding?.renderJourneyStrip();
      } else if (action === "journey-next") {
        const target = act.dataset.target || "samples";
        switchView(target).then(() => {
          if (target === "overview" && Store.activeSample && !Store.activeSample.scan_result && Store.activeSample.kind === "apk") {
            runScan();
          }
        });
      } else if (action === "open-doctor") {
        openDoctorModal();
      } else if (action === "open-ws-manager") {
        Workspace?.openManagerModal();
      } else if (action === "ws-activate") {
        Workspace?.activateWorkspace(act.dataset.id);
      } else if (action === "ws-create") {
        Workspace?.createWorkspaceFromModal();
      } else if (action === "ws-pin") {
        Workspace?.togglePinWorkspace(act.dataset.id, act.dataset.pinned === "1");
      } else if (action === "ws-rename") {
        Workspace?.renameWorkspace(act.dataset.id, act.dataset.name);
      } else if (action === "ws-delete") {
        Workspace?.deleteWorkspace(act.dataset.id);
      } else if (action === "ws-import-trigger") {
        document.getElementById("wsImportFileInput")?.click();
      } else if (action === "samples-tab") {
        Store.samplesTab = act.dataset.tab || "intake";
        if (Store.samplesTab === "history") {
          Workspace?.refreshHistory(Store.activeWorkspaceId).then(() => render());
        } else {
          render();
        }
      } else if (action === "save-sample-notes") {
        Workspace?.saveSampleNotes();
      } else if (action === "toggle-bookmark") {
        Workspace?.toggleMethodBookmark(act.dataset.dex, act.dataset.class, act.dataset.method, act.dataset.idx);
      } else if (action === "remove-bookmark") {
        Workspace?.removeBookmark(act.dataset.key);
      } else if (action === "jump-bookmark") {
        const dexName = act.dataset.dex;
        const clsName = act.dataset.class;
        const methName = act.dataset.method;
        const methIdx = act.dataset.idx;
        switchView("inspector").then(async () => {
          if (dexName) Store.dex.selectedDex = dexName;
          await loadDexClasses();
          await selectClass(clsName);
          await selectMethod(clsName, methName, methIdx);
        });
      } else if (action === "open-ai-settings") {
        AI?.openSettingsModal();
      } else if (action === "ai-preset") {
        AI?.selectPreset(act.dataset.provider);
      } else if (action === "ai-pick-model") {
        AI?.pickPresetModel(act.dataset.model);
      } else if (action === "ai-save") {
        AI?.saveSettings(false);
      } else if (action === "ai-clear-key") {
        AI?.saveSettings(true);
      } else if (action === "ai-test") {
        AI?.runConnectionTest();
      } else if (action === "ai-copy") {
        AI?.copyMarkdown(act.dataset.module);
      } else if (action === "ai-run") {
        AI?.runModuleAnalysis(act.dataset.module);
      } else if (action === "ai-run-method") {
        const dis = Store.dex.disasm;
        if (dis) {
          AI?.runModuleAnalysis("method", {
            dex_name: Store.dex.selectedDex,
            class_name: dis.class_name || Store.dex.selectedClass || "",
            method_name: dis.method_name || "",
            method_idx: dis.method_idx,
            disasm: dis,
          });
        }
      } else if (action === "ai-run-pipeline-stage") {
        const stageId = act.dataset.stage || Store.pipeline.selectedStageId || "";
        const planStage = ((Store.pipeline.plan || {}).stages || []).find((s) => s.id === stageId) || {};
        const liveStage = (Store.pipeline.liveStages || {})[stageId] || {};
        const blockers = ((Store.pipeline.plan || {}).preflight_checks || [])
          .filter((c) => c.status !== "pass")
          .map((c) => `${c.title}: ${c.detail} (${c.fix_hint || ""})`)
          .join("\n");
        const errLogs = (liveStage.logs || []).map((l) => `[${l.level}] ${l.message}`).join("\n");
        AI?.runModuleAnalysis("pipeline_issue", {
          stage: { ...planStage, ...liveStage, name: planStage.title || stageId },
          error_text: [Store.activeJob?.error || "", blockers, errLogs].filter(Boolean).join("\n"),
        });
      } else if (action === "pipe-mode") {
        Pipeline?.setMode(act.dataset.mode);
      } else if (action === "pipe-switch-offline") {
        Pipeline?.setMode("offline_audit");
        UI.toast(t("toast.switched_offline"), "ok");
      } else if (action === "pipe-refresh-plan") {
        Pipeline?.refreshPlan(Store.pipeline.mode, true);
      } else if (action === "pipe-stage") {
        Pipeline?.selectStage(act.dataset.stage);
      } else if (action === "run-deep-pipeline") {
        Pipeline?.launch();
      } else if (action === "nav") {
        switchView(act.dataset.view);
      } else if (action === "trigger-upload") {
        document.getElementById("studioFileInput")?.click();
      } else if (action === "refresh-library") {
        refreshLocalLibrary();
      } else if (action === "select-sample") {
        selectSample(act.dataset.id, "overview");
      } else if (action === "delete-sample") {
        deleteSample(act.dataset.id, act.dataset.name);
      } else if (action === "import-local") {
        importLocal(act.dataset.path);
      } else if (action === "run-scan") {
        runScan();
      } else if (action === "run-inspect") {
        runInspect(true);
      } else if (action === "dex-tab") {
        Store.dex.tab = act.dataset.tab;
        render();
        if (Store.dex.tab === "strings" && !Store.dex.stringsHits.length) searchDexStrings();
      } else if (action === "filter-classes") {
        Store.dex.query = document.getElementById("dexClassSearch")?.value || "";
        Store.dex.health = document.getElementById("dexHealthFilter")?.value || "";
        loadDexClasses();
      } else if (action === "select-class") {
        selectClass(act.dataset.class);
      } else if (action === "select-method") {
        selectMethod(act.dataset.class, act.dataset.method, act.dataset.idx);
      } else if (action === "search-strings") {
        Store.dex.stringsQuery = document.getElementById("dexStringsInput")?.value || "";
        searchDexStrings();
      } else if (action === "run-verify") {
        runVerify();
      } else if (action === "run-repair") {
        runRepair();
      } else if (action === "run-vmp") {
        runVmp();
      } else if (action === "run-xref") {
        runXref();
      } else if (action === "vmp-tab") {
        Store.vmpTab = act.dataset.tab;
        render();
      } else if (action === "run-repack") {
        runRepack();
      } else if (action === "run-fart") {
        runFart();
      } else if (action === "preview-report") {
        loadReportPreview(act.dataset.format);
      } else if (action === "open-drawer") {
        setDrawerOpen(true);
      } else if (action === "inspect-job") {
        inspectJob(act.dataset.id);
      } else if (action === "cancel-job") {
        cancelJob(act.dataset.id);
      }
    });

    document.getElementById("sampleSwitcher")?.addEventListener("change", (e) => {
      selectSample(e.target.value);
    });
    document.getElementById("btnQuickScan")?.addEventListener("click", () => {
      switchView("overview").then(() => runScan());
    });
    document.getElementById("btnQuickReport")?.addEventListener("click", () => switchView("reports"));
    document.getElementById("btnToggleJobs")?.addEventListener("click", () => {
      setDrawerOpen(!Store.drawerOpen);
      if (Store.drawerOpen) refreshJobs();
    });
    document.getElementById("btnCloseDrawer")?.addEventListener("click", () => setDrawerOpen(false));
    document.getElementById("btnRefreshJobs")?.addEventListener("click", () => refreshJobs());
    document.getElementById("btnOpenDoctor")?.addEventListener("click", () => openDoctorModal());
    document.getElementById("btnCloseModal")?.addEventListener("click", () => UI.closeModal());
    document.getElementById("modalBackdrop")?.addEventListener("click", (e) => {
      if (e.target.id === "modalBackdrop") UI.closeModal();
    });
    document.getElementById("btnCloseDialog")?.addEventListener("click", () => UI.closeDialog(null));
    document.getElementById("dialogBackdrop")?.addEventListener("click", (e) => {
      if (e.target.id === "dialogBackdrop") UI.closeDialog(null);
    });
    document.getElementById("onboardBackdrop")?.addEventListener("click", (e) => {
      if (e.target.id === "onboardBackdrop") Onboarding?.closeWelcomeModal();
    });
    document.getElementById("btnThemeToggle")?.addEventListener("click", () => {
      Store.setTheme(Store.theme === "dark" ? "light" : "dark");
    });
    document.getElementById("btnCmdPalette")?.addEventListener("click", () => openPalette());
    document.getElementById("btnToggleNav")?.addEventListener("click", () => {
      document.getElementById("navRail")?.classList.toggle("open");
    });

    document.getElementById("paletteBackdrop")?.addEventListener("click", (e) => {
      if (e.target.id === "paletteBackdrop") closePalette();
    });
    document.getElementById("paletteInput")?.addEventListener("input", (e) => renderPalette(e.target.value));
    document.getElementById("paletteInput")?.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        updatePaletteSelection(paletteSelectedIdx + 1);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        updatePaletteSelection(paletteSelectedIdx - 1);
      } else if (e.key === "Enter" && paletteItems.length) {
        e.preventDefault();
        const chosen = paletteItems[paletteSelectedIdx] || paletteItems[0];
        closePalette();
        if (chosen) chosen.run();
      }
    });

    document.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        const bg = document.getElementById("paletteBackdrop");
        if (bg && !bg.hidden) closePalette();
        else openPalette();
        return;
      }
      if (e.key === "Escape") {
        const dlg = document.getElementById("dialogBackdrop");
        if (dlg && !dlg.hidden) {
          UI.closeDialog(null);
          return;
        }
        closePalette();
        UI.closeModal();
        if (Onboarding?.isWelcomeOpen()) Onboarding.closeWelcomeModal();
        if (Onboarding?.isTourActive()) Onboarding.endTour();
        setDrawerOpen(false);
      }
    });

    // React cleanly to language switches without losing state
    if (I18n) {
      I18n.onChange(() => {
        render();
        Onboarding?.onLangChange();
        if (Workspace?.isManagerOpen()) Workspace.renderManagerModal();
        if (AI?.isSettingsOpen()) AI.renderSettingsModal();
        if (Store.activeSample && Store.view === "pipeline") {
          Pipeline?.refreshPlan(Store.pipeline.mode);
        }
        if (Store.activeSample && Store.view === "reports") {
          loadReportPreview(Store.reportFormat || "html");
        }
      });
    }
  }

  async function boot() {
    if (I18n) I18n.applyStaticDom();
    Store.setTheme(Store.theme);
    initEvents();
    render();
    await Promise.all([
      refreshSamples(),
      refreshLocalLibrary(),
      refreshJobs(),
      loadDoctor(false),
      Workspace ? Workspace.loadWorkspaces() : Promise.resolve(),
      AI ? AI.loadConfig() : Promise.resolve(),
    ]);
    render();
    Onboarding?.maybeAutoOpenWelcome();
  }

  global.UnpackApp = {
    render,
    switchView,
    selectSample,
    importLocal,
    importLocalSilent,
    refreshSamples,
    refreshJobs,
    subscribeJob,
    openDoctorModal,
  };

  document.addEventListener("DOMContentLoaded", boot);
})(window);
