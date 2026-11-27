/* ==========================================================================
   UNPACK Commercial Product Site — Shared Interactivity (Zero External CDN)
   Theme switcher · Bilingual zh/en switcher · Mobile drawer · SVG/PNG/PDF
   export · Code copy · CLI interactive search & category filter
   ========================================================================== */

(function () {
  "use strict";

  const THEME_KEY = "unpack-docs-theme";
  const LANG_KEY = "unpack-docs-lang";

  function safeStorageGet(key) {
    try {
      return window.localStorage.getItem(key);
    } catch (_) {
      return null;
    }
  }

  function safeStorageSet(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch (_) {
      // Ignore private-mode / sandboxed storage errors
    }
  }

  function applyTheme(theme) {
    const resolved = theme === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", resolved);
    safeStorageSet(THEME_KEY, resolved);
    document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
      btn.setAttribute("aria-pressed", resolved === "light" ? "true" : "false");
      const enLbl = resolved === "dark" ? "Light" : "Dark";
      const zhLbl = resolved === "dark" ? "浅色" : "深色";
      const lang = document.documentElement.getAttribute("data-lang") || "en";
      btn.textContent = (resolved === "dark" ? "☀ " : "☾ ") + (lang === "zh" ? zhLbl : enLbl);
    });
  }

  function applyLang(lang) {
    const resolved = lang === "zh" ? "zh" : "en";
    document.documentElement.setAttribute("data-lang", resolved);
    document.documentElement.setAttribute("lang", resolved === "zh" ? "zh-CN" : "en");
    safeStorageSet(LANG_KEY, resolved);

    // Update page <title> if localized data attributes are present on <html> or <body
    const root = document.documentElement;
    const titleAttr = resolved === "zh" ? root.getAttribute("data-title-zh") : root.getAttribute("data-title-en");
    if (titleAttr) {
      document.title = titleAttr;
    }

    // Update segmented lang toggle active states
    document.querySelectorAll("[data-set-lang]").forEach(function (btn) {
      const active = btn.getAttribute("data-set-lang") === resolved;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-pressed", active ? "true" : "false");
    });

    // Update localized placeholders & aria labels
    document.querySelectorAll("[data-ph-en][data-ph-zh]").forEach(function (el) {
      el.setAttribute("placeholder", resolved === "zh" ? el.getAttribute("data-ph-zh") : el.getAttribute("data-ph-en"));
    });

    // Refresh theme button label for the active language
    applyTheme(document.documentElement.getAttribute("data-theme") || "dark");
  }

  function initPreferences() {
    const savedTheme = safeStorageGet(THEME_KEY);
    const savedLang = safeStorageGet(LANG_KEY);

    const initialTheme = savedTheme || "dark";
    let initialLang = savedLang;
    if (!initialLang) {
      const navLang = (navigator.language || "en").toLowerCase();
      initialLang = navLang.startsWith("zh") ? "zh" : "en";
    }
    document.documentElement.setAttribute("data-theme", initialTheme);
    applyLang(initialLang);
  }

  function initControls() {
    document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const current = document.documentElement.getAttribute("data-theme") || "dark";
        applyTheme(current === "dark" ? "light" : "dark");
      });
    });

    document.querySelectorAll("[data-set-lang]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        applyLang(btn.getAttribute("data-set-lang"));
      });
    });

    const burger = document.querySelector("[data-nav-burger]");
    const drawer = document.getElementById("mobileDrawer");
    if (burger && drawer) {
      burger.addEventListener("click", function () {
        const isOpen = drawer.classList.toggle("open");
        burger.setAttribute("aria-expanded", isOpen ? "true" : "false");
      });
      drawer.querySelectorAll("a").forEach(function (link) {
        link.addEventListener("click", function () {
          drawer.classList.remove("open");
          burger.setAttribute("aria-expanded", "false");
        });
      });
    }
  }

  function flashButton(btn, label) {
    const original = btn.textContent;
    btn.textContent = label;
    btn.disabled = true;
    window.setTimeout(function () {
      btn.textContent = original;
      btn.disabled = false;
    }, 1800);
  }

  function initCodeCopy() {
    document.querySelectorAll(".code-block").forEach(function (block) {
      if (block.querySelector(".copy-code-btn")) return;
      const pre = block.querySelector("pre");
      if (!pre) return;
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "copy-code-btn";
      btn.textContent = "Copy";
      btn.addEventListener("click", function () {
        const text = pre.innerText || pre.textContent || "";
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text.trim()).then(function () {
            flashButton(btn, "Copied!");
          }).catch(function () {
            flashButton(btn, "Failed");
          });
        } else {
          flashButton(btn, "Copied!");
        }
      });
      block.appendChild(btn);
    });
  }

  /* Pure Client-Side SVG -> SVG / 2x PNG / Clipboard / Print-PDF Export */
  function serializeDiagramSvg(svg) {
    const clone = svg.cloneNode(true);
    clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    const vb = (svg.getAttribute("viewBox") || "0 0 1000 800").split(/\s+/).map(Number);
    const width = vb[2] || 1000;
    const height = vb[3] || 800;
    clone.setAttribute("width", String(width));
    clone.setAttribute("height", String(height));

    // Inject self-contained background & typography so exported file renders identically everywhere
    const style = document.createElementNS("http://www.w3.org/2000/svg", "style");
    style.textContent = 'text { font-family: "JetBrains Mono", ui-monospace, Menlo, Consolas, monospace; dominant-baseline: central; }';
    const defs = clone.querySelector("defs") || clone.insertBefore(document.createElementNS("http://www.w3.org/2000/svg", "defs"), clone.firstChild);
    defs.appendChild(style);

    const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    bg.setAttribute("width", String(width));
    bg.setAttribute("height", String(height));
    bg.setAttribute("fill", "#070d1b");
    clone.insertBefore(bg, defs.nextSibling);

    const xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(clone);
    return { xml: xml, width: width, height: height };
  }

  function svgToPngBlob(svg, scale) {
    return new Promise(function (resolve, reject) {
      const data = serializeDiagramSvg(svg);
      const blob = new Blob([data.xml], { type: "image/svg+xml;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const img = new Image();
      img.onload = function () {
        try {
          const canvas = document.createElement("canvas");
          const s = scale || 2;
          canvas.width = data.width * s;
          canvas.height = data.height * s;
          const ctx = canvas.getContext("2d");
          ctx.fillStyle = "#070d1b";
          ctx.fillRect(0, 0, canvas.width, canvas.height);
          ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
          URL.revokeObjectURL(url);
          canvas.toBlob(function (pngBlob) {
            if (pngBlob) resolve(pngBlob);
            else reject(new Error("Canvas export failed"));
          }, "image/png");
        } catch (err) {
          URL.revokeObjectURL(url);
          reject(err);
        }
      };
      img.onerror = function (err) {
        URL.revokeObjectURL(url);
        reject(err);
      };
      img.src = url;
    });
  }

  function initDiagramExports() {
    document.querySelectorAll("[data-export-action]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const action = btn.getAttribute("data-export-action");
        const name = btn.getAttribute("data-export-name") || "unpack-diagram";
        const card = btn.closest(".diagram-card") || document;
        const svg = card.querySelector("svg[data-exportable]") || card.querySelector("svg");

        if (action === "pdf") {
          window.print();
          return;
        }
        if (!svg) return;

        if (action === "svg") {
          const data = serializeDiagramSvg(svg);
          const blob = new Blob([data.xml], { type: "image/svg+xml;charset=utf-8" });
          const a = document.createElement("a");
          a.href = URL.createObjectURL(blob);
          a.download = name + ".svg";
          a.click();
          window.setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
          flashButton(btn, "✓ SVG");
          return;
        }

        if (action === "png") {
          svgToPngBlob(svg, 2).then(function (pngBlob) {
            const a = document.createElement("a");
            a.href = URL.createObjectURL(pngBlob);
            a.download = name + ".png";
            a.click();
            window.setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
            flashButton(btn, "✓ PNG");
          }).catch(function () {
            flashButton(btn, "✗ Error");
          });
          return;
        }

        if (action === "copy") {
          svgToPngBlob(svg, 2).then(function (pngBlob) {
            if (navigator.clipboard && window.ClipboardItem) {
              return navigator.clipboard.write([new window.ClipboardItem({ "image/png": pngBlob })]);
            }
            throw new Error("Clipboard image API unavailable");
          }).then(function () {
            flashButton(btn, "✓ Copied");
          }).catch(function () {
            flashButton(btn, "✗ Copy N/A");
          });
        }
      });
    });
  }

  /* Interactive Search & Category Filter for CLI Reference Page */
  function initCliFilter() {
    const searchInput = document.getElementById("cliSearchInput");
    const countEl = document.getElementById("cliResultCount");
    const cards = Array.prototype.slice.call(document.querySelectorAll(".cmd-card"));
    const pills = Array.prototype.slice.call(document.querySelectorAll("[data-cli-cat]"));
    if (!cards.length) return;

    let activeCat = "all";

    function applyFilter() {
      const q = searchInput ? searchInput.value.trim().toLowerCase() : "";
      let visible = 0;
      cards.forEach(function (card) {
        const cat = card.getAttribute("data-cat") || "";
        const hay = (card.getAttribute("data-search") || card.textContent || "").toLowerCase();
        const matchCat = activeCat === "all" || cat === activeCat;
        const matchQuery = !q || hay.indexOf(q) !== -1;
        const show = matchCat && matchQuery;
        card.hidden = !show;
        if (show) visible += 1;
      });
      if (countEl) {
        countEl.textContent = String(visible) + " / " + String(cards.length);
      }
    }

    if (searchInput) {
      searchInput.addEventListener("input", applyFilter);
    }
    pills.forEach(function (pill) {
      pill.addEventListener("click", function () {
        activeCat = pill.getAttribute("data-cli-cat") || "all";
        pills.forEach(function (p) {
          const isAct = p === pill;
          p.classList.toggle("active", isAct);
          p.setAttribute("aria-pressed", isAct ? "true" : "false");
        });
        applyFilter();
      });
    });

    applyFilter();
  }

  document.addEventListener("DOMContentLoaded", function () {
    initPreferences();
    initControls();
    initCodeCopy();
    initDiagramExports();
    initCliFilter();
  });
})();
