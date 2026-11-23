/**
 * UNPACK Studio — Centralized Client State
 */
(function (global) {
  "use strict";

  const savedTheme = localStorage.getItem("unpack_studio_theme") || "dark";
  const savedJourney = localStorage.getItem("unpack_studio_journey");

  function defaultPipelineState() {
    return {
      mode: null, // "offline_audit" | "repair_repack" | "device_standard" | "device_deep"
      engine: "",
      timeout: 15,
      deep: false,
      antiDetect: true,
      repack: false,
      generateReport: true,
      plan: null,
      planLoading: false,
      selectedStageId: null,
      userPinnedStage: false,
      liveStages: {},
      lastJobId: null,
    };
  }

  const Store = {
    view: "samples",
    theme: savedTheme,
    journeyVisible: savedJourney === null ? true : savedJourney !== "0",
    samples: [],
    activeSampleId: null,
    activeSample: null,

    localLibrary: { roots: [], items: [] },
    localFilter: "",
    localKindFilter: "all",
    samplesTab: "intake", // "intake" | "history"

    // Persistent Workspaces
    workspaces: [],
    activeWorkspaceId: "default",
    workspaceHistory: { samples: [], pipeline_runs: [], ai_analyses: [] },

    // AI Model Config & Embedded Analyses
    aiConfig: null,
    aiPresets: [],
    aiTestResult: null,
    aiTesting: false,
    aiLoading: {}, // module -> bool
    aiSelectedByModule: {}, // module -> analysis_id

    doctor: null,

    // DEX Inspector sub-state
    dex: {
      list: [],
      selectedDex: null,
      tab: "classes", // "classes" | "strings"
      query: "",
      health: "",
      pkg: "",
      classesPage: null,
      selectedClass: null,
      classDetail: null,
      selectedMethodKey: null,
      disasm: null,
      stringsQuery: "",
      stringsHits: [],
    },

    // VMP / Native sub-state
    vmpTab: "stubs", // "stubs" | "native" | "xref"
    vmpSearch: "",

    // Repair / Verify sub-state
    verifySummary: null,
    repairResult: null,

    // Deep Pipeline Studio & Repack sub-state
    pipeline: defaultPipelineState(),
    repackResult: null,
    fartResult: null,

    // Report preview sub-state
    reportFormat: "html",
    reportPreviewHtml: "",
    reportPreviewText: "",

    // Jobs & SSE
    jobs: [],
    activeJobId: null,
    activeJob: null,
    sseSource: null,
    drawerOpen: false,

    // Loading flags
    busy: {},
  };

  Store.setTheme = function (theme) {
    Store.theme = theme === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", Store.theme);
    try {
      localStorage.setItem("unpack_studio_theme", Store.theme);
    } catch (_) {}
    Store.updateThemeLabel();
  };

  Store.updateThemeLabel = function () {
    const lbl = document.getElementById("themeLabel");
    if (!lbl) return;
    const t = global.UnpackI18n ? global.UnpackI18n.t : (k) => k;
    lbl.textContent = Store.theme === "dark" ? t("nav.theme.light") : t("nav.theme.dark");
  };

  Store.setJourneyVisible = function (visible) {
    Store.journeyVisible = Boolean(visible);
    try {
      localStorage.setItem("unpack_studio_journey", Store.journeyVisible ? "1" : "0");
    } catch (_) {}
  };

  Store.resetSampleSubState = function () {
    Store.dex = {
      list: [],
      selectedDex: null,
      tab: "classes",
      query: "",
      health: "",
      pkg: "",
      classesPage: null,
      selectedClass: null,
      classDetail: null,
      selectedMethodKey: null,
      disasm: null,
      stringsQuery: "",
      stringsHits: [],
    };
    Store.verifySummary = null;
    Store.repairResult = null;
    Store.pipeline = defaultPipelineState();
    Store.repackResult = null;
    Store.fartResult = null;
    Store.reportPreviewHtml = "";
    Store.reportPreviewText = "";
  };

  global.UnpackStore = Store;
})(window);
