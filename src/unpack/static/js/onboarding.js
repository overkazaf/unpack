/**
 * UNPACK Studio — Commercial Onboarding, Interactive 6-Step Spotlight Tour & Workflow Journey Strip
 */
(function (global) {
  "use strict";

  const ONBOARD_KEY = "unpack_studio_onboarded";

  function t(key, params) {
    return global.UnpackI18n ? global.UnpackI18n.t(key, params) : key;
  }

  function esc(v) {
    return global.UnpackUI ? global.UnpackUI.esc(v) : String(v || "");
  }

  let welcomeOpen = false;
  let tourActive = false;
  let tourStepIndex = 0;
  let tourSeq = 0;

  const TOUR_STEPS = [
    {
      id: "samples",
      view: "samples",
      selector: "#tourSamplesLibrary",
      fallbackSelector: "#uploadDropzone",
      titleKey: "tour.step1.title",
      bodyKey: "tour.step1.body",
      tipKey: "tour.step1.tip",
    },
    {
      id: "overview",
      view: "overview",
      selector: "#tourVerdictBanner",
      fallbackSelector: "#workspaceViewport",
      titleKey: "tour.step2.title",
      bodyKey: "tour.step2.body",
      tipKey: "tour.step2.tip",
    },
    {
      id: "inspector",
      view: "inspector",
      selector: "#tourDexLayout",
      fallbackSelector: "#workspaceViewport",
      titleKey: "tour.step3.title",
      bodyKey: "tour.step3.body",
      tipKey: "tour.step3.tip",
    },
    {
      id: "pipeline",
      view: "pipeline",
      selector: "#tourPipelineStudio",
      fallbackSelector: "#workspaceViewport",
      titleKey: "tour.step4.title",
      bodyKey: "tour.step4.body",
      tipKey: "tour.step4.tip",
    },
    {
      id: "reports",
      view: "reports",
      selector: "#tourReportsPanel",
      fallbackSelector: "#workspaceViewport",
      titleKey: "tour.step5.title",
      bodyKey: "tour.step5.body",
      tipKey: "tour.step5.tip",
    },
    {
      id: "chrome",
      view: null,
      selector: "#tourGlobalControls",
      fallbackSelector: "#navFooter",
      titleKey: "tour.step6.title",
      bodyKey: "tour.step6.body",
      tipKey: "tour.step6.tip",
    },
  ];

  // =========================================================================
  // 1. Workflow Journey Stepper Strip
  // =========================================================================

  function renderJourneyStrip() {
    const host = document.getElementById("journeyStripHost");
    if (!host) return;
    const Store = global.UnpackStore;

    if (!Store.journeyVisible) {
      host.innerHTML = `
        <div class="journey-collapsed">
          <button class="btn btn-ghost btn-xs" type="button" data-action="toggle-journey">
            <span>▾ ${esc(t("journey.show"))}</span>
          </button>
        </div>
      `;
      return;
    }

    const s = Store.activeSample;
    const step1Done = Boolean(s);
    const step2Done = Boolean(s && (s.scan_result || s.inspect_result));
    const step3Done = Boolean(
      s &&
        (s.repair_diffs ||
          s.vmp_result ||
          (Store.jobs || []).some((j) => j.sample_id === s.id && j.status === "done"))
    );
    const step4Done = Boolean(s && Store.view === "reports");

    let ctaLabel = t("journey.cta.select");
    let ctaAction = "journey-next";
    let ctaTarget = "samples";
    if (!step1Done) {
      ctaLabel = t("journey.cta.select");
      ctaTarget = "samples";
    } else if (!step2Done && s.kind === "apk") {
      ctaLabel = t("journey.cta.scan");
      ctaTarget = "overview";
    } else if (!step3Done) {
      ctaLabel = t("journey.cta.pipeline");
      ctaTarget = "pipeline";
    } else {
      ctaLabel = t("journey.cta.report");
      ctaTarget = "reports";
    }

    const steps = [
      { key: "samples", label: t("journey.step1"), done: step1Done, active: Store.view === "samples" },
      { key: "overview", label: t("journey.step2"), done: step2Done, active: Store.view === "overview" || Store.view === "inspector" },
      { key: "pipeline", label: t("journey.step3"), done: step3Done, active: Store.view === "pipeline" || Store.view === "repair" || Store.view === "vmp" },
      { key: "reports", label: t("journey.step4"), done: step4Done, active: Store.view === "reports" },
    ];

    host.innerHTML = `
      <div class="journey-strip" id="journeyStrip">
        <div class="journey-left">
          <span class="journey-kicker mono">${esc(t("journey.label"))}</span>
          <div class="journey-steps">
            ${steps
              .map(
                (st, idx) => `
              <button class="journey-step ${st.done ? "done" : ""} ${st.active ? "active" : ""}" type="button" data-action="nav" data-view="${st.key}">
                <span class="journey-dot">${st.done ? "✓" : idx + 1}</span>
                <span>${esc(st.label)}</span>
              </button>
              ${idx < steps.length - 1 ? `<span class="journey-arrow" aria-hidden="true">›</span>` : ""}
            `
              )
              .join("")}
          </div>
        </div>
        <div class="journey-right">
          <button class="btn btn-primary btn-xs" type="button" data-action="${ctaAction}" data-target="${ctaTarget}">${esc(ctaLabel)}</button>
          <button class="btn btn-ghost btn-xs" type="button" data-action="toggle-journey" title="${esc(t("journey.hide"))}">✕</button>
        </div>
      </div>
    `;
  }

  // =========================================================================
  // 2. Welcome & Quick-Start Guide Modal
  // =========================================================================

  function renderWelcomeModal() {
    const backdrop = document.getElementById("onboardBackdrop");
    if (!backdrop) return;
    if (!welcomeOpen) {
      backdrop.hidden = true;
      backdrop.innerHTML = "";
      return;
    }

    const alreadyDismissed = localStorage.getItem(ONBOARD_KEY) === "1";

    backdrop.innerHTML = `
      <div class="onboard-dialog" role="dialog" aria-modal="true" aria-label="${esc(t("onboard.title"))}">
        <div class="onboard-head">
          <div>
            <span class="badge badge-accent">${esc(t("onboard.badge"))}</span>
            <h2>${esc(t("onboard.hero_title"))}</h2>
            <p>${esc(t("onboard.hero_desc"))}</p>
          </div>
          <button class="btn btn-ghost btn-xs" type="button" data-action="close-welcome" aria-label="${esc(t("common.close"))}">✕</button>
        </div>

        <div class="onboard-caps">
          <div class="onboard-cap offline">
            <div class="onboard-cap-title">
              <span class="badge badge-ok">${esc(t("pipe.tag.offline"))}</span>
              <strong>${esc(t("onboard.cap_offline_title"))}</strong>
            </div>
            <p>${esc(t("onboard.cap_offline_desc"))}</p>
          </div>
          <div class="onboard-cap device">
            <div class="onboard-cap-title">
              <span class="badge badge-violet">${esc(t("pipe.tag.device"))}</span>
              <strong>${esc(t("onboard.cap_device_title"))}</strong>
            </div>
            <p>${esc(t("onboard.cap_device_desc"))}</p>
          </div>
        </div>

        <div class="onboard-cta-banner">
          <div>
            <strong>${esc(t("onboard.cta_demo"))}</strong>
            <div class="onboard-cta-sub">${esc(t("onboard.cta_demo_sub"))}</div>
          </div>
          <button class="btn btn-primary" type="button" id="btnStartDemoTour" data-action="start-demo-tour">
            ▶ ${esc(t("onboard.cta_demo"))}
          </button>
        </div>

        <div class="onboard-section-label">${esc(t("onboard.goals_title"))}</div>
        <div class="onboard-goals">
          <button class="goal-card" type="button" data-action="onboard-goal" data-goal="overview">
            <div class="goal-title">${esc(t("onboard.goal1.title"))}</div>
            <div class="goal-desc">${esc(t("onboard.goal1.desc"))}</div>
          </button>
          <button class="goal-card" type="button" data-action="onboard-goal" data-goal="inspector">
            <div class="goal-title">${esc(t("onboard.goal2.title"))}</div>
            <div class="goal-desc">${esc(t("onboard.goal2.desc"))}</div>
          </button>
          <button class="goal-card" type="button" data-action="onboard-goal" data-goal="pipeline">
            <div class="goal-title">${esc(t("onboard.goal3.title"))}</div>
            <div class="goal-desc">${esc(t("onboard.goal3.desc"))}</div>
          </button>
          <button class="goal-card" type="button" data-action="onboard-goal" data-goal="repair">
            <div class="goal-title">${esc(t("onboard.goal4.title"))}</div>
            <div class="goal-desc">${esc(t("onboard.goal4.desc"))}</div>
          </button>
        </div>

        <div class="onboard-foot">
          <label class="checkbox-row" style="padding:0">
            <input type="checkbox" id="onboardDontShow" ${alreadyDismissed ? "checked" : ""}>
            <span>${esc(t("onboard.dont_show"))}</span>
          </label>
          <button class="btn btn-subtle btn-sm" type="button" data-action="close-welcome">${esc(t("onboard.cta_skip"))}</button>
        </div>
      </div>
    `;
    backdrop.hidden = false;
  }

  function openWelcomeModal() {
    if (tourActive) endTour();
    welcomeOpen = true;
    renderWelcomeModal();
  }

  function closeWelcomeModal() {
    const chk = document.getElementById("onboardDontShow");
    if (!chk || chk.checked) {
      try {
        localStorage.setItem(ONBOARD_KEY, "1");
      } catch (_) {}
    }
    welcomeOpen = false;
    renderWelcomeModal();
  }

  function shouldAutoShowWelcome() {
    try {
      const sp = new URLSearchParams(global.location.search || "");
      if (sp.get("tour") === "0") return false;
      if (sp.get("tour") === "1") return true;
      return localStorage.getItem(ONBOARD_KEY) !== "1";
    } catch (_) {
      return false;
    }
  }

  function maybeAutoOpenWelcome() {
    if (shouldAutoShowWelcome()) {
      openWelcomeModal();
    }
  }

  async function ensureDemoSampleMounted(preferredKind) {
    const Store = global.UnpackStore;
    const App = global.UnpackApp;
    if (Store.activeSample && (!preferredKind || Store.activeSample.kind === preferredKind)) {
      return Store.activeSample;
    }
    if (Store.samples && Store.samples.length && App) {
      const match =
        (preferredKind && Store.samples.find((s) => s.kind === preferredKind)) || Store.samples[0];
      await App.selectSample(match.id);
      return Store.activeSample;
    }
    const localItems = (Store.localLibrary && Store.localLibrary.items) || [];
    if (!localItems.length || !App) return null;

    // Prefer a quick/known APK like com.android.bankabc.apk or smallest APK for snappy demo
    let pick = null;
    if (preferredKind === "dex_dir") {
      pick = localItems.find((i) => i.kind === "dex_dir" || i.kind === "dex") || localItems[0];
    } else {
      pick =
        localItems.find((i) => i.name === "com.android.bankabc.apk") ||
        localItems.find((i) => i.kind === "apk" && i.size_bytes < 50 * 1024 * 1024) ||
        localItems.find((i) => i.kind === "apk") ||
        localItems[0];
    }
    if (!pick) return null;
    await App.importLocalSilent(pick.path);
    return Store.activeSample;
  }

  async function handleGoalClick(goalView) {
    closeWelcomeModal();
    const App = global.UnpackApp;
    if (!App) return;
    if (!global.UnpackStore.activeSample) {
      const pref = goalView === "repair" ? "dex_dir" : "apk";
      await ensureDemoSampleMounted(pref);
    }
    if (global.UnpackStore.activeSample) {
      await App.switchView(goalView);
    } else {
      await App.switchView("samples");
    }
  }

  async function startDemoTour() {
    try {
      localStorage.setItem(ONBOARD_KEY, "1");
    } catch (_) {}
    welcomeOpen = false;
    renderWelcomeModal();

    if (global.UnpackUI) {
      global.UnpackUI.toast(t("onboard.mounting_demo"), "accent");
    }
    await ensureDemoSampleMounted("apk");
    await startTour(0);
  }

  // =========================================================================
  // 3. Interactive 6-Step Spotlight Coachmark Tour
  // =========================================================================

  function getTourHost() {
    return document.getElementById("spotlightLayer");
  }

  function findTargetEl(step) {
    return document.querySelector(step.selector) || document.querySelector(step.fallbackSelector);
  }

  function positionSpotlight() {
    const host = getTourHost();
    if (!host || !tourActive) return;

    const step = TOUR_STEPS[tourStepIndex];
    const target = findTargetEl(step);
    const pad = 8;
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    let rect = { left: vw / 2 - 200, top: vh / 2 - 120, width: 400, height: 240, right: vw / 2 + 200, bottom: vh / 2 + 120 };
    if (target) {
      target.scrollIntoView({ behavior: "instant", block: "nearest" });
      const r = target.getBoundingClientRect();
      if (r.width > 0 && r.height > 0) {
        const left = Math.max(8, r.left - pad);
        const top = Math.max(8, r.top - pad);
        const width = Math.min(vw - left - 8, r.width + pad * 2);
        const height = Math.min(vh - top - 8, Math.min(r.height + pad * 2, vh * 0.62));
        rect = { left, top, width, height, right: left + width, bottom: top + height };
      }
    }

    const ring = host.querySelector(".spotlight-ring");
    if (ring) {
      ring.style.left = `${Math.round(rect.left)}px`;
      ring.style.top = `${Math.round(rect.top)}px`;
      ring.style.width = `${Math.round(rect.width)}px`;
      ring.style.height = `${Math.round(rect.height)}px`;
    }

    const card = host.querySelector(".coachmark-card");
    if (card) {
      const cw = 390;
      const ch = card.offsetHeight || 230;
      let left = rect.left;
      let top = rect.bottom + 14;

      // Prefer below, else above, else right, else inside bottom-right
      if (top + ch > vh - 16) {
        if (rect.top - ch - 14 >= 16) {
          top = rect.top - ch - 14;
        } else if (rect.right + cw + 16 <= vw - 16) {
          left = rect.right + 14;
          top = Math.max(16, Math.min(rect.top, vh - ch - 16));
        } else {
          top = Math.max(16, vh - ch - 20);
          left = Math.max(16, vw - cw - 20);
        }
      }
      left = Math.max(16, Math.min(left, vw - cw - 16));
      top = Math.max(16, Math.min(top, vh - ch - 16));

      card.style.left = `${Math.round(left)}px`;
      card.style.top = `${Math.round(top)}px`;
    }
  }

  function renderTourOverlay() {
    const host = getTourHost();
    if (!host) return;
    if (!tourActive) {
      host.hidden = true;
      host.innerHTML = "";
      return;
    }

    const step = TOUR_STEPS[tourStepIndex];
    const total = TOUR_STEPS.length;
    const isFirst = tourStepIndex === 0;
    const isLast = tourStepIndex === total - 1;

    host.innerHTML = `
      <div class="spotlight-click-shield" data-action="tour-noop"></div>
      <div class="spotlight-ring" aria-hidden="true"></div>
      <div class="coachmark-card" role="dialog" aria-modal="true" aria-label="${esc(t(step.titleKey))}">
        <div class="coachmark-head">
          <span class="badge badge-accent mono">${esc(t("tour.step_counter", { cur: tourStepIndex + 1, total }))}</span>
          <div class="coachmark-dots">
            ${TOUR_STEPS.map((_, i) => `<span class="coachmark-dot ${i === tourStepIndex ? "active" : i < tourStepIndex ? "done" : ""}"></span>`).join("")}
          </div>
          <button class="btn btn-ghost btn-xs" type="button" data-action="tour-end" aria-label="${esc(t("tour.skip"))}">✕</button>
        </div>
        <h3 class="coachmark-title">${esc(t(step.titleKey))}</h3>
        <p class="coachmark-body">${esc(t(step.bodyKey))}</p>
        <div class="coachmark-tip">${esc(t(step.tipKey))}</div>
        <div class="coachmark-actions">
          <button class="btn btn-ghost btn-xs" type="button" data-action="tour-end">${esc(t("tour.skip"))}</button>
          <div class="toolbar">
            ${!isFirst ? `<button class="btn btn-subtle btn-sm" type="button" data-action="tour-prev">${esc(t("tour.prev"))}</button>` : ""}
            <button class="btn btn-primary btn-sm" type="button" data-action="${isLast ? "tour-end" : "tour-next"}">
              ${esc(isLast ? t("tour.finish") : t("tour.next"))}
            </button>
          </div>
        </div>
      </div>
    `;
    host.hidden = false;
    requestAnimationFrame(() => positionSpotlight());
  }

  function startTour(idx = 0) {
    tourSeq += 1;
    const mySeq = tourSeq;
    tourActive = true;
    tourStepIndex = Math.max(0, Math.min(idx, TOUR_STEPS.length - 1));
    const step = TOUR_STEPS[tourStepIndex];
    if (step.view && global.UnpackApp) {
      // Switch view immediately (do not block popover on slow inspect/plan fetches)
      global.UnpackApp.switchView(step.view).then(() => {
        if (tourActive && tourSeq === mySeq) {
          positionSpotlight();
        }
      });
    }
    renderTourOverlay();
    setTimeout(() => {
      if (tourActive && tourSeq === mySeq) positionSpotlight();
    }, 120);
  }

  function nextStep() {
    if (!tourActive) return;
    if (tourStepIndex + 1 >= TOUR_STEPS.length) {
      endTour();
      return;
    }
    startTour(tourStepIndex + 1);
  }

  function prevStep() {
    if (!tourActive) return;
    startTour(Math.max(0, tourStepIndex - 1));
  }

  function endTour() {
    tourSeq += 1;
    tourActive = false;
    renderTourOverlay();
  }

  function reposition() {
    if (tourActive) {
      requestAnimationFrame(() => positionSpotlight());
    }
  }

  function onLangChange() {
    renderJourneyStrip();
    if (welcomeOpen) renderWelcomeModal();
    if (tourActive) renderTourOverlay();
  }

  window.addEventListener("resize", () => {
    if (tourActive) positionSpotlight();
  });

  global.UnpackOnboarding = {
    renderJourneyStrip,
    openWelcomeModal,
    closeWelcomeModal,
    maybeAutoOpenWelcome,
    handleGoalClick,
    startDemoTour,
    startTour,
    nextStep,
    prevStep,
    endTour,
    reposition,
    onLangChange,
    isTourActive: () => tourActive,
    isWelcomeOpen: () => welcomeOpen,
  };
})(window);
