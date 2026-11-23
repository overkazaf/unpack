/**
 * UNPACK Studio — Centralized Client State
 */
(function (global) {
  "use strict";

  const savedTheme = localStorage.getItem("unpack_studio_theme") || "dark";

  const Store = {
    view: "samples",
    theme: savedTheme,
    samples: [],
    activeSampleId: null,
    activeSample: null,

    localLibrary: { roots: [], items: [] },
    localFilter: "",
    localKindFilter: "all",

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

    // Pipeline / Repack sub-state
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
    localStorage.setItem("unpack_studio_theme", Store.theme);
    const lbl = document.getElementById("themeLabel");
    if (lbl) lbl.textContent = Store.theme === "dark" ? "Light" : "Dark";
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
    Store.repackResult = null;
    Store.fartResult = null;
    Store.reportPreviewHtml = "";
    Store.reportPreviewText = "";
  };

  global.UnpackStore = Store;
})(window);
