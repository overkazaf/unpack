/**
 * UNPACK Studio — Application Controller, Delegated Router & Command Palette
 */
(function (global) {
  "use strict";

  const API = global.UnpackAPI;
  const Store = global.UnpackStore;
  const UI = global.UnpackUI;
  const Views = global.UnpackViews;

  function render() {
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
        `<option value="">No sample selected</option>`,
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

    // Update Jobs button
    const running = Store.jobs.filter((j) => j.status === "running").length;
    const jobBadge = document.getElementById("jobCountBadge");
    const jobPulse = document.getElementById("jobPulseDot");
    if (jobBadge) jobBadge.textContent = String(Store.jobs.length);
    if (jobPulse) jobPulse.classList.toggle("running", running > 0);

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
      localSearch.addEventListener("input", (e) => {
        Store.localFilter = e.target.value;
        render();
        const again = document.getElementById("localSearchInput");
        if (again) {
          again.focus();
          again.setSelectionRange(again.value.length, again.value.length);
        }
      });
    }

    const localKind = document.getElementById("localKindFilter");
    if (localKind) {
      localKind.addEventListener("change", (e) => {
        Store.localKindFilter = e.target.value;
        render();
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
      vmpSearch.addEventListener("input", (e) => {
        Store.vmpSearch = e.target.value;
        render();
        const again = document.getElementById("vmpSearchInput");
        if (again) {
          again.focus();
          again.setSelectionRange(again.value.length, again.value.length);
        }
      });
    }
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
    } else if (view === "reports" && !Store.reportPreviewHtml && !Store.reportPreviewText) {
      await loadReportPreview(Store.reportFormat || "html");
    }
  }

  async function refreshSamples() {
    try {
      const res = await API.listSamples();
      Store.samples = res.items || [];
      render();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function refreshLocalLibrary() {
    try {
      Store.localLibrary = await API.localLibrary();
      render();
    } catch (err) {
      UI.toast(`Local library: ${err.message}`, "warn");
    }
  }

  async function loadDoctor(checkDevices = false) {
    try {
      const doc = await API.doctor(checkDevices);
      Store.doctor = doc;
      const dot = document.getElementById("doctorDot");
      const meta = document.getElementById("doctorEnginesMeta");
      if (dot) {
        dot.className = `status-dot ${doc.overall_status === "pass" ? "ok" : doc.overall_status === "fail" ? "fail" : "warn"}`;
      }
      if (meta) {
        const ready = (doc.engines || []).filter((e) => e.available).length;
        meta.textContent = `${ready}/${(doc.engines || []).length} eng`;
      }
      return doc;
    } catch (_) {
      return null;
    }
  }

  async function selectSample(id, targetView) {
    if (!id) {
      Store.activeSampleId = null;
      Store.activeSample = null;
      Store.resetSampleSubState();
      render();
      return;
    }
    try {
      const res = await API.getSample(id);
      Store.activeSampleId = id;
      Store.activeSample = res.sample;
      Store.resetSampleSubState();
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
      if (Store.view === "overview") await runInspect();
      if (Store.view === "inspector") await loadDexList();
      if (Store.view === "reports") await loadReportPreview(Store.reportFormat || "html");
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function handleUpload(files) {
    UI.toast(`Uploading ${files.length} file(s)...`, "accent");
    try {
      const res = await API.uploadSamples(files, true);
      await refreshSamples();
      if (res.items && res.items.length) {
        const first = res.items[0];
        UI.toast(`Loaded ${first.name}`, "ok");
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
    UI.toast("Importing local sample...", "accent");
    try {
      const res = await API.importLocal(path, true);
      await refreshSamples();
      UI.toast(`Mounted ${res.sample.name}`, "ok");
      await selectSample(res.sample.id, res.sample.kind === "apk" ? "overview" : "inspector");
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function deleteSample(id) {
    try {
      await API.deleteSample(id);
      if (Store.activeSampleId === id) {
        Store.activeSampleId = null;
        Store.activeSample = null;
        Store.resetSampleSubState();
      }
      await refreshSamples();
      UI.toast("Sample removed from vault", "muted");
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
      UI.toast(res.scan.packer_name ? `Detected ${res.scan.packer_name}` : "Scan complete — no commercial packer detected", "ok");
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
      UI.toast(`Verified ${Store.verifySummary.total} DEX file(s)`, "ok");
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
      UI.toast(`Repaired ${res.total} DEX (${res.resolved_issues_total} issues resolved)`, "ok");
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
      UI.toast(`VMP scan complete: ${res.vmp.vmp_count} stub(s) in ${res.vmp.total_methods} methods`, "ok");
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
      UI.toast(`Xref indexed ${(res.xref.counts || {}).strings || 0} strings`, "ok");
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
      UI.toast(`Built ${res.artifact.name}`, "ok");
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
      UI.toast(`Exported ${res.total_methods} FART method bodies`, "ok");
    } catch (err) {
      UI.toast(err.message, "danger");
    } finally {
      Store.busy.fart = false;
      render();
    }
  }

  async function loadReportPreview(format) {
    if (!Store.activeSample) return;
    Store.reportFormat = format;
    Store.reportPreviewHtml = "";
    Store.reportPreviewText = "";
    render();
    try {
      const txt = await API.fetchReportText(Store.activeSample.id, format);
      if (format === "html") Store.reportPreviewHtml = txt;
      else Store.reportPreviewText = txt;
      render();
    } catch (err) {
      UI.toast(err.message, "danger");
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
      render();
    } catch (_) {}
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
        render();
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
        UI.toast(`Job #${jobId} completed`, "ok");
        refreshJobs();
        if (Store.activeSampleId) selectSample(Store.activeSampleId);
      },
      failed: (p) => {
        if (Store.activeJob) {
          Store.activeJob.status = "failed";
          Store.activeJob.error = p.error || "Job failed";
        }
        Store.sseSource?.close();
        Store.sseSource = null;
        UI.toast(`Job #${jobId} failed: ${p.error || "error"}`, "danger");
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

  async function launchPipeline() {
    if (!Store.activeSample) return;
    const opts = {
      engine: document.getElementById("pipeEngine")?.value || "",
      start_from: document.getElementById("pipeStartFrom")?.value || "scan_only",
      timeout: Number(document.getElementById("pipeTimeout")?.value || 15),
      deep: Boolean(document.getElementById("pipeDeep")?.checked),
      anti_detect: Boolean(document.getElementById("pipeAntiDetect")?.checked),
    };
    try {
      const res = await API.runPipeline(Store.activeSample.id, opts);
      UI.toast(`Started job #${res.job_id}`, "accent");
      await refreshJobs();
      setDrawerOpen(true);
      subscribeJob(res.job_id);
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function inspectJob(jobId) {
    try {
      const job = await API.getJob(jobId);
      Store.activeJobId = jobId;
      Store.activeJob = job;
      if (job.status === "running") subscribeJob(jobId);
      Views.renderTaskDrawer();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  async function cancelJob(jobId) {
    try {
      await API.cancelJob(jobId);
      UI.toast(`Cancelled job #${jobId}`, "warn");
      await refreshJobs();
    } catch (err) {
      UI.toast(err.message, "danger");
    }
  }

  // =========================================================================
  // Command Palette (Cmd+K / Ctrl+K)
  // =========================================================================

  let paletteItems = [];

  function buildPaletteCommands() {
    const cmds = [
      { label: "Workspace: Samples & Intake", cat: "NAV", run: () => switchView("samples") },
      { label: "Workspace: Scan & Packer Intelligence", cat: "NAV", run: () => switchView("overview") },
      { label: "Workspace: APK & DEX Inspector", cat: "NAV", run: () => switchView("inspector") },
      { label: "Workspace: Repair & Verify Lab", cat: "NAV", run: () => switchView("repair") },
      { label: "Workspace: VMP & Native Studio", cat: "NAV", run: () => switchView("vmp") },
      { label: "Workspace: Pipeline & Repack Center", cat: "NAV", run: () => switchView("pipeline") },
      { label: "Workspace: Reports & Export", cat: "NAV", run: () => switchView("reports") },
      { label: "Toggle Dark / Light Theme", cat: "UI", run: () => Store.setTheme(Store.theme === "dark" ? "light" : "dark") },
      { label: "Open Environment Doctor", cat: "SYS", run: () => openDoctorModal() },
      { label: "Toggle Task Manager Drawer", cat: "SYS", run: () => setDrawerOpen(!Store.drawerOpen) },
    ];
    if (Store.activeSample) {
      if (Store.activeSample.kind === "apk") {
        cmds.push({ label: `Scan ${Store.activeSample.name}`, cat: "ACTION", run: () => runScan() });
      }
      cmds.push({ label: `Verify DEXs (${Store.activeSample.name})`, cat: "ACTION", run: () => { switchView("repair"); runVerify(); } });
      cmds.push({ label: `Run VMP Analysis (${Store.activeSample.name})`, cat: "ACTION", run: () => { switchView("vmp"); runVmp(); } });
    }
    Store.samples.forEach((s) => {
      cmds.push({ label: `Switch Sample: ${s.name}`, cat: "VAULT", run: () => selectSample(s.id, "overview") });
    });
    (Store.localLibrary.items || []).slice(0, 20).forEach((it) => {
      cmds.push({ label: `Import Local: ${it.display_path}`, cat: "LOCAL", run: () => importLocal(it.path) });
    });
    return cmds;
  }

  function renderPalette(query) {
    const list = document.getElementById("paletteList");
    if (!list) return;
    const q = (query || "").trim().toLowerCase();
    paletteItems = buildPaletteCommands().filter((c) => !q || `${c.label} ${c.cat}`.toLowerCase().includes(q));
    list.innerHTML = paletteItems
      .slice(0, 14)
      .map(
        (c, i) =>
          `<button class="palette-item ${i === 0 ? "selected" : ""}" type="button" data-palette-idx="${i}"><span>${UI.esc(c.label)}</span><span class="palette-cat">${UI.esc(c.cat)}</span></button>`
      )
      .join("") || `<div style="padding:14px;color:var(--text-muted);text-align:center">No matching commands</div>`;
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
    UI.openModal("Environment Diagnostics", Views.renderDoctorModalHtml(Store.doctor));
    const fresh = await loadDoctor(true);
    if (fresh) UI.openModal("Environment Diagnostics", Views.renderDoctorModalHtml(fresh));
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

      if (action === "nav") switchView(act.dataset.view);
      else if (action === "trigger-upload") document.getElementById("studioFileInput")?.click();
      else if (action === "refresh-library") refreshLocalLibrary();
      else if (action === "select-sample") selectSample(act.dataset.id, "overview");
      else if (action === "delete-sample") deleteSample(act.dataset.id);
      else if (action === "import-local") importLocal(act.dataset.path);
      else if (action === "run-scan") runScan();
      else if (action === "run-inspect") runInspect(true);
      else if (action === "dex-tab") {
        Store.dex.tab = act.dataset.tab;
        render();
        if (Store.dex.tab === "strings" && !Store.dex.stringsHits.length) searchDexStrings();
      } else if (action === "filter-classes") {
        Store.dex.query = document.getElementById("dexClassSearch")?.value || "";
        Store.dex.health = document.getElementById("dexHealthFilter")?.value || "";
        loadDexClasses();
      } else if (action === "select-class") selectClass(act.dataset.class);
      else if (action === "select-method") selectMethod(act.dataset.class, act.dataset.method, act.dataset.idx);
      else if (action === "search-strings") {
        Store.dex.stringsQuery = document.getElementById("dexStringsInput")?.value || "";
        searchDexStrings();
      } else if (action === "run-verify") runVerify();
      else if (action === "run-repair") runRepair();
      else if (action === "run-vmp") runVmp();
      else if (action === "run-xref") runXref();
      else if (action === "vmp-tab") {
        Store.vmpTab = act.dataset.tab;
        render();
      } else if (action === "run-pipeline") launchPipeline();
      else if (action === "run-repack") runRepack();
      else if (action === "run-fart") runFart();
      else if (action === "preview-report") loadReportPreview(act.dataset.format);
      else if (action === "open-drawer") setDrawerOpen(true);
      else if (action === "inspect-job") inspectJob(act.dataset.id);
      else if (action === "cancel-job") cancelJob(act.dataset.id);
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
      if (e.key === "Enter" && paletteItems.length) {
        e.preventDefault();
        closePalette();
        paletteItems[0].run();
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
        closePalette();
        UI.closeModal();
        setDrawerOpen(false);
      }
    });
  }

  async function boot() {
    Store.setTheme(Store.theme);
    initEvents();
    render();
    await Promise.all([refreshSamples(), refreshLocalLibrary(), refreshJobs(), loadDoctor(false)]);
  }

  document.addEventListener("DOMContentLoaded", boot);
})(window);
