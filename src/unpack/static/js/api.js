/**
 * UNPACK Studio — REST & SSE API Client
 */
(function (global) {
  "use strict";

  async function requestJSON(url, options) {
    const resp = await fetch(url, options);
    const ct = resp.headers.get("content-type") || "";
    const data = ct.includes("application/json")
      ? await resp.json()
      : { error: await resp.text() };
    if (!resp.ok) {
      const err = new Error(data.error || `HTTP ${resp.status}`);
      err.status = resp.status;
      err.code = data.code || "HTTP_ERROR";
      throw err;
    }
    return data;
  }

  function qs(params) {
    const sp = new URLSearchParams();
    Object.entries(params || {}).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") sp.set(k, String(v));
    });
    const s = sp.toString();
    return s ? `?${s}` : "";
  }

  function currentLang() {
    return global.UnpackI18n ? global.UnpackI18n.getLang() : "en";
  }

  const API = {
    health: () => requestJSON("/api/v1/health"),
    doctor: (checkDevices = true) =>
      requestJSON(`/api/v1/doctor${qs({ check_devices: checkDevices })}`),
    localLibrary: () => requestJSON("/api/v1/local-library"),

    listSamples: () => requestJSON("/api/v1/samples"),
    getSample: (id) => requestJSON(`/api/v1/samples/${encodeURIComponent(id)}`),
    deleteSample: (id) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(id)}`, { method: "DELETE" }),

    uploadSamples: (files, autoScan = true) => {
      const form = new FormData();
      Array.from(files).forEach((f) => form.append("files", f));
      form.append("auto_scan", String(autoScan));
      return requestJSON("/api/v1/samples/upload", { method: "POST", body: form });
    },

    importLocal: (path, autoScan = true) =>
      requestJSON("/api/v1/samples/import-local", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path, auto_scan: autoScan }),
      }),

    scanSample: (id) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(id)}/scan`, { method: "POST" }),

    inspectSample: (id, refresh = false) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(id)}/inspect${qs({ refresh })}`),

    listDex: (id) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(id)}/dex`),

    listClasses: (id, dexName, params) =>
      requestJSON(
        `/api/v1/samples/${encodeURIComponent(id)}/dex/${encodeURIComponent(dexName)}/classes${qs(params)}`
      ),

    inspectClass: (id, dexName, className) =>
      requestJSON(
        `/api/v1/samples/${encodeURIComponent(id)}/dex/${encodeURIComponent(dexName)}/class${qs({ name: className })}`
      ),

    disasmMethod: (id, dexName, className, methodName, methodIdx) =>
      requestJSON(
        `/api/v1/samples/${encodeURIComponent(id)}/dex/${encodeURIComponent(dexName)}/disasm${qs({
          class: className,
          method: methodName,
          method_idx: methodIdx,
        })}`
      ),

    searchStrings: (id, dexName, q, limit = 100) =>
      requestJSON(
        `/api/v1/samples/${encodeURIComponent(id)}/dex/${encodeURIComponent(dexName)}/strings${qs({ q, limit })}`
      ),

    runVmp: (id, dexName) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(id)}/vmp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(dexName ? { dex_name: dexName } : {}),
      }),

    runXref: (id, dexName, limit = 100) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(id)}/xref`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dex_name: dexName || undefined, limit }),
      }),

    runVerify: (id, dexNames) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(id)}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(dexNames ? { dex_names: dexNames } : {}),
      }),

    runRepair: (id, dexNames) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(id)}/repair`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(dexNames ? { dex_names: dexNames } : {}),
      }),

    runRepack: (id, dexSampleId, stripSignatures = true) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(id)}/repack`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          dex_sample_id: dexSampleId || undefined,
          strip_signatures: stripSignatures,
        }),
      }),

    exportFart: (id, dexNames) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(id)}/export/fart`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(dexNames ? { dex_names: dexNames } : {}),
      }),

    planPipeline: (opts) =>
      requestJSON("/api/v1/pipeline/plan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lang: currentLang(), ...(opts || {}) }),
      }),

    launchPipelineJob: (opts) =>
      requestJSON("/api/v1/jobs/pipeline", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lang: currentLang(), ...(opts || {}) }),
      }),

    runPipeline: (id, opts) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(id)}/pipeline`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lang: currentLang(), ...(opts || {}) }),
      }),

    reportUrl: (id, format = "html", download = false, lang) =>
      `/api/v1/samples/${encodeURIComponent(id)}/reports${qs({
        format,
        download: download ? 1 : 0,
        lang: lang || currentLang(),
      })}`,

    fetchReportText: async (id, format = "html", lang) => {
      const resp = await fetch(API.reportUrl(id, format, false, lang));
      if (!resp.ok) {
        const j = await resp.json().catch(() => ({}));
        throw new Error(j.error || `Report failed (${resp.status})`);
      }
      return resp.text();
    },

    listJobs: () => requestJSON("/api/v1/jobs"),
    getJob: (jobId) => requestJSON(`/api/v1/jobs/${encodeURIComponent(jobId)}`),
    cancelJob: (jobId) =>
      requestJSON(`/api/v1/jobs/${encodeURIComponent(jobId)}/cancel`, { method: "POST" }),

    // Persistent Workspaces & Notes
    listWorkspaces: () => requestJSON("/api/v1/workspaces"),
    createWorkspace: (payload) =>
      requestJSON("/api/v1/workspaces", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload || {}),
      }),
    activateWorkspace: (wsId) =>
      requestJSON(`/api/v1/workspaces/${encodeURIComponent(wsId)}/activate`, { method: "POST" }),
    updateWorkspace: (wsId, payload) =>
      requestJSON(`/api/v1/workspaces/${encodeURIComponent(wsId)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload || {}),
      }),
    deleteWorkspace: (wsId) =>
      requestJSON(`/api/v1/workspaces/${encodeURIComponent(wsId)}`, { method: "DELETE" }),
    getWorkspaceHistory: (wsId, limit = 50) =>
      requestJSON(`/api/v1/workspaces/${encodeURIComponent(wsId)}/history${qs({ limit })}`),
    workspaceExportUrl: (wsId) => `/api/v1/workspaces/${encodeURIComponent(wsId)}/export`,
    importWorkspaceFile: (file) => {
      const form = new FormData();
      form.append("file", file);
      return requestJSON("/api/v1/workspaces/import", { method: "POST", body: form });
    },
    updateSampleNotes: (sampleId, payload) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(sampleId)}/notes`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload || {}),
      }),

    // AI Config & Embedded Analysis
    getAiConfig: () => requestJSON("/api/v1/ai/config"),
    saveAiConfig: (payload) =>
      requestJSON("/api/v1/ai/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload || {}),
      }),
    testAiConnection: (configOverride) =>
      requestJSON("/api/v1/ai/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lang: currentLang(), config: configOverride || undefined }),
      }),
    listSampleAi: (sampleId, module) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(sampleId)}/ai${qs({ module })}`),
    runSampleAi: (sampleId, module, payload) =>
      requestJSON(`/api/v1/samples/${encodeURIComponent(sampleId)}/ai/${encodeURIComponent(module)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ lang: currentLang(), ...(payload || {}) }),
      }),

    subscribeJobEvents: (jobId, handlers) => {
      const es = new EventSource(`/api/v1/jobs/${encodeURIComponent(jobId)}/events`);
      ["snapshot", "log", "phase", "phase_data", "stage", "artifact", "done", "failed", "cancelled"].forEach(
        (evt) => {
          es.addEventListener(evt, (e) => {
            try {
              const payload = JSON.parse(e.data);
              if (handlers[evt]) handlers[evt](payload);
            } catch (_) {
              /* ignore malformed event */
            }
          });
        }
      );
      es.onerror = () => {
        if (handlers.error) handlers.error();
      };
      return es;
    },
  };

  global.UnpackAPI = API;
})(window);
