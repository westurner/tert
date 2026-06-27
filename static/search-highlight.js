/**
 * search-highlight.js – v3
 *
 * FTS search-result highlighting panel for Datasette table pages.
 *
 * Features
 * --------
 *  • Per-term highlight colors — native <input type="color"> picker.
 *  • Per-term toggle — show/hide each term independently (● / ○).
 *  • Per-term case sensitivity toggle  [Aa].
 *  • Per-term regex mode toggle        [.*]   (with invalid-pattern error indicator).
 *  • Master toggle  — show/hide all highlights at once.
 *  • Next / Prev navigation — cycle through matches in document order,
 *    scroll to each, highlight the current match distinctly.
 *  • Nav exit [X] — leave cycle and un-highlight the current match.
 *  • Add / Remove terms live.
 *  • State persisted in localStorage.
 *
 * Exported (window.FtsHighlight) for unit tests
 * ----------------------------------------------
 *  .extractTokens(query)   – strip FTS5 syntax → plain word tokens
 *  .tokensFromUrl()        – collect tokens from ?_search=… params
 *  .buildRegex(tokens)     – build combined case-insensitive RegExp
 *  .escapeRegex(str)       – escape a string for use in a RegExp
 *  .highlightElement(el,r) – compat shim
 *  .DEFAULT_COLORS         – resolved color palette array
 *  .getState()             – return live state object (for tests)
 *  .navGetIndex()          – current nav index (-1 = not navigating)
 *  .navGetCount()          – count of navigable (visible) marks
 */
(function () {
  'use strict';

  /* ------------------------------------------------------------------ */
  /* Color palettes                                                       */
  /* ------------------------------------------------------------------ */

  /**
   * Viridis perceptually-uniform palette (8 samples), lightened 70% toward
   * white so they work as readable highlight backgrounds.
   *
   * Source colormap: Nathaniel J. Smith and Stéfan van der Walt, "A Better
   * Default Colormap for Matplotlib", SciPy 2015.
   * License: CC0.  https://bids.github.io/colormap/
   *
   * Derivation: sample viridis at t = 0, 1/7, 2/7, …, 1; then blend each
   * sRGB channel toward white at 70%: c' = c + (255 − c) × 0.70.
   */
  var VIRIDIS_COLORS = [
    '#c7b3cc',  // t=0.000 — deep purple lightened
    '#c8c2d8',  // t=0.143 — purple lightened
    '#c3cedd',  // t=0.286 — blue lightened
    '#bed9dd',  // t=0.429 — teal lightened
    '#bce3db',  // t=0.571 — teal-green lightened
    '#c9ecd3',  // t=0.714 — green lightened
    '#e2f4c4',  // t=0.857 — yellow-green lightened
    '#fef8be'   // t=1.000 — yellow lightened
  ];

  /** Legacy hand-picked pastel palette (pre-viridis default). */
  var PASTEL_COLORS = [
    '#fff176',  // yellow
    '#b3f0ff',  // cyan
    '#c8f7c5',  // green
    '#ffcba4',  // peach
    '#e8b4ff',  // purple
    '#ffd4d4',  // pink-red
    '#d4e4ff',  // blue
    '#ffe4b5'   // amber
  ];

  /**
   * Glasbey bw_minc_20 categorical palette (32 samples), lightened 60% toward
   * white so they work as readable highlight backgrounds.
   *
   * Original colors: colorcet.glasbey_bw_minc_20 — maximally-distinct
   * categorical colors that each maintain contrast against both black and
   * white backgrounds (minimum lightness contrast = 20).
   *
   * Sources
   * -------
   * colorcet: https://colorcet.holoviz.org/user_guide/Categorical.html
   *
   * Glasbey, Chris; van der Heijden, Gerie & Toh, Vivian F. K. et al. (2007)
   * "Colour displays for categorical images",
   * Color Research & Application 32.4: 304-309.
   * https://strathprints.strath.ac.uk/30312/1/colorpaper_2006.pdf
   *
   * Derivation: first 32 entries from colorcet.glasbey_bw_minc_20
   * (ordered by maximum mutual distinctness); each sRGB channel blended
   * 60% toward white: c' = round(c + (255 − c) × 0.60).
   */
  var GLASBEY_BW_MINC_20_COLORS = [
    '#ef9999',  //  0: #d70000 lightened — red
    '#d1b1ff',  //  1: #8c3cff lightened — purple
    '#9acf99',  //  2: #028800 lightened — green
    '#99dee9',  //  3: #00acc7 lightened — teal
    '#d6ff99',  //  4: #98ff00 lightened — lime
    '#ffcced',  //  5: #ff7fd1 lightened — pink
    '#c499b9',  //  6: #6c004f lightened — mauve
    '#ffdbac',  //  7: #ffa530 lightened — orange
    '#bcb199',  //  8: #583b00 lightened — dark brown
    '#99bcbd',  //  9: #005759 lightened — dark teal
    '#9999f1',  // 10: #0000dd lightened — blue
    '#99feec',  // 11: #00fdcf lightened — cyan-mint
    '#d9c8c3',  // 12: #a1756a lightened — dusty rose
    '#e4e2ff',  // 13: #bcb7ff lightened — lavender
    '#d5e1c9',  // 14: #95b578 lightened — sage
    '#e69be3',  // 15: #c004b9 lightened — magenta
    '#c1bbc7',  // 16: #645474 lightened — muted purple
    '#c99999',  // 17: #790000 lightened — dark red
    '#9cc7ef',  // 18: #0774d8 lightened — sky blue
    '#fffbd3',  // 19: #fef590 lightened — pale yellow
    '#99b799',  // 20: #004b00 lightened — dark green
    '#d2ca99',  // 21: #8f7a00 lightened — olive
    '#ffc7c2',  // 22: #ff7266 lightened — salmon
    '#f8e3e3',  // 23: #eeb9b9 lightened — blush
    '#bfcbc2',  // 24: #5e7e66 lightened — muted sage
    '#d7f4ff',  // 25: #9be4ff lightened — pale cyan
    '#f799c9',  // 26: #ec0077 lightened — hot pink
    '#dbcae3',  // 27: #a67bb9 lightened — soft violet
    '#bd99db',  // 28: #5a00a4 lightened — indigo
    '#9be899',  // 29: #04c600 lightened — bright green
    '#d8b799',  // 30: #9e4b00 lightened — burnt sienna
    '#d7b1b9'   // 31: #9c3b50 lightened — dusty burgundy
  ];

  /* ------------------------------------------------------------------ */
  /* Config resolution (reads window.FTS_HIGHLIGHT_CONFIG)               */
  /* ------------------------------------------------------------------ */

  /**
   * Resolve the active color palette from a config object.
   *
   *   cfg.colors === 'viridis'           → VIRIDIS_COLORS (default)
   *   cfg.colors === 'pastel'            → PASTEL_COLORS (legacy)
   *   cfg.colors === 'glasbey_bw_minc_20'→ GLASBEY_BW_MINC_20_COLORS
   *   cfg.colors === [...array]          → that array (custom)
   *   cfg.colors === null/undef          → VIRIDIS_COLORS
   *
   * Exported on FtsHighlight for unit tests.
   */
  function resolveColors(cfg) {
    var c = cfg && cfg.colors;
    if (!c || c === 'viridis') return VIRIDIS_COLORS;
    if (c === 'pastel') return PASTEL_COLORS;
    if (c === 'glasbey_bw_minc_20') return GLASBEY_BW_MINC_20_COLORS;
    if (Array.isArray(c) && c.length > 0) return c;
    return VIRIDIS_COLORS;
  }

  // Read user config (set by fts-highlight-config.js loaded before this file)
  var _cfg = window.FTS_HIGHLIGHT_CONFIG || {};
  var STORAGE_KEY   = _cfg.storageKey || 'tert-fts-hl';
  var DEFAULT_COLORS = resolveColors(_cfg);

  /* ------------------------------------------------------------------ */
  /* Exported API (window.FtsHighlight) — pure logic, no DOM             */
  /* ------------------------------------------------------------------ */
  var FtsHighlight = {};

  /**
   * Extract plain-text tokens from a FTS5 query string.
   * Strips: AND / OR / NOT keywords, NEAR(…) expressions, quoted phrases
   * (kept as one token), column filters ({col}: …), and wildcard/boost chars.
   */
  FtsHighlight.extractTokens = function (query) {
    var tokens = [];

    // 1. Pull out quoted phrases and keep them as single tokens
    var withoutQuotes = query.replace(/"([^"]*)"/g, function (_, phrase) {
      if (phrase.trim().length > 0) tokens.push(phrase.trim());
      return ' ';
    });

    // 2. Strip FTS5 structural syntax from the remainder
    var remainder = withoutQuotes
      .replace(/NEAR\s*\([^)]*\)/gi, ' ')
      .replace(/\b(AND|OR|NOT)\b/gi, ' ')
      .replace(/[{}\[\]^*:]/g, ' ')
      .trim();

    // 3. Split on whitespace, keep tokens with 2+ chars
    var words = remainder.split(/\s+/).filter(function (w) { return w.length > 1; });
    tokens = tokens.concat(words);

    // 4. Deduplicate (case-insensitive), sort longest first for greedy matching
    var seen = Object.create(null);
    var unique = [];
    tokens.forEach(function (t) {
      var k = t.toLowerCase();
      if (!seen[k]) { seen[k] = true; unique.push(t); }
    });
    unique.sort(function (a, b) { return b.length - a.length; });
    return unique;
  };

  /**
   * Read all search tokens from the current page URL.
   * Collects ?_search=… and ?_search_COLNAME=… parameters.
   */
  FtsHighlight.tokensFromUrl = function () {
    var params = new URLSearchParams(window.location.search);
    var tokens = [];
    params.forEach(function (val, key) {
      if (key === '_search' || key.indexOf('_search_') === 0) {
        tokens = tokens.concat(FtsHighlight.extractTokens(val));
      }
    });
    var seen = Object.create(null);
    return tokens.filter(function (t) {
      var k = t.toLowerCase();
      if (seen[k]) return false;
      seen[k] = true;
      return true;
    });
  };

  /**
   * Build a combined RegExp from an array of string tokens.
   * Tokens sorted longest-first so longer matches win.
   */
  FtsHighlight.buildRegex = function (tokens) {
    var escaped = tokens.map(function (t) {
      return t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    });
    escaped.sort(function (a, b) { return b.length - a.length; });
    return new RegExp('(' + escaped.join('|') + ')', 'gi');
  };

  /** Viridis lightened palette (exported for tests). */
  FtsHighlight.VIRIDIS_COLORS = VIRIDIS_COLORS;

  /** Legacy pastel palette (exported for tests). */
  FtsHighlight.PASTEL_COLORS = PASTEL_COLORS;

  /** Glasbey bw_minc_20 lightened palette (exported for tests). */
  FtsHighlight.GLASBEY_BW_MINC_20_COLORS = GLASBEY_BW_MINC_20_COLORS;

  /** Resolve color palette from config object (exported for tests). */
  FtsHighlight.resolveColors = resolveColors;

  /** Escape a string so it is safe to embed in a RegExp pattern. */
  FtsHighlight.escapeRegex = escapeRegex;

  /** Return current nav index (-1 = not navigating). */
  FtsHighlight.navGetIndex = function () { return navIndex; };

  /** Return count of currently navigable (visible) marks. */
  FtsHighlight.navGetCount = function () { return getVisibleMarks().length; };

  /** Default color palette — resolved from config (exported for backward compat). */
  FtsHighlight.DEFAULT_COLORS = DEFAULT_COLORS;

  /** Return the live state object (for integration/browser tests). */
  FtsHighlight.getState = function () { return state; };

  /**
   * Compatibility shim — v1 API.  Applies the regex to text nodes inside
   * `root` using the old single-class mark approach.
   */
  FtsHighlight.highlightElement = function (root, re) {
    _walkAndMark(root, [], re, function () { return 0; });
  };

  /* ------------------------------------------------------------------ */
  /* ------------------------------------------------------------------ */
  /* Module-level mutable state                                           */
  /* ------------------------------------------------------------------ */
  /**
   * @type {{
   *   allEnabled: boolean,
   *   terms: Array<{
   *     text: string, color: string, enabled: boolean,
   *     regex: boolean, caseSensitive: boolean
   *   }>
   * }}
   */
  var state = { allEnabled: true, terms: [] };
  var panelEl = null;    // injected panel <div>
  var styleEl = null;    // injected <style> element

  // Navigation state
  var navIndex = -1;     // -1 = not navigating
  var navMarks  = [];    // ordered list of visible marks (recomputed on each nav step)

  // Per-rerender error tracking (idx → true) for invalid regex patterns
  var termErrors = {};

  /* ------------------------------------------------------------------ */
  /* Persistence                                                          */
  /* ------------------------------------------------------------------ */
  function loadState() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      var parsed = JSON.parse(raw);
      if (parsed && Array.isArray(parsed.terms)) {
        // Migrate older saved states that lack the regex / caseSensitive fields
        parsed.terms.forEach(function (t) {
          if (t.regex        === undefined) t.regex        = false;
          if (t.caseSensitive === undefined) t.caseSensitive = false;
        });
        return parsed;
      }
    } catch (e) { /* ignore */ }
    return null;
  }

  function saveState() {
    try {
      if (state.terms.length === 0) {
        // All terms removed — clear persisted state so the next page load
        // re-seeds from URL params instead of showing a permanently empty panel.
        localStorage.removeItem(STORAGE_KEY);
      } else {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
      }
    } catch (e) { /* ignore */ }
  }

  /* ------------------------------------------------------------------ */
  /* Dynamic stylesheet                                                   */
  /* ------------------------------------------------------------------ */
  /**
   * Rebuild the <style id="fts-hl-styles"> element.
   * Each enabled term gets a background-color rule keyed on data-idx.
   * Disabled terms get display:none.  If allEnabled is false, everything hides.
   */
  function updateStylesheet() {
    if (!styleEl) return;
    var css = '';
    if (!state.allEnabled) {
      css = 'mark.fts-hl { display: none !important; }\n';
    } else {
      state.terms.forEach(function (t, i) {
        if (t.enabled) {
          css += 'mark.fts-hl[data-idx="' + i + '"] {'
            + ' background-color: ' + t.color + ';'
            + ' color: inherit;'
            + ' border-radius: 2px;'
            + ' padding: 0 1px;'
            + ' font-family: inherit;'
            + ' font-size: inherit; }\n';
        } else {
          css += 'mark.fts-hl[data-idx="' + i + '"] { display: none; }\n';
        }
      });
    }
    styleEl.textContent = css;
  }

  /* ------------------------------------------------------------------ */
  /* DOM: apply / remove marks                                            */
  /* ------------------------------------------------------------------ */

  /** Remove every <mark class="fts-hl"> from the table and normalize text nodes. */
  function removeAllMarks() {
    document.querySelectorAll('mark.fts-hl').forEach(function (mark) {
      var p = mark.parentNode;
      while (mark.firstChild) p.insertBefore(mark.firstChild, mark);
      p.removeChild(mark);
    });
    document.querySelectorAll('table.rows-and-columns td').forEach(function (td) {
      td.normalize();
    });
  }

  /**
   * Walk text nodes inside `root`, wrapping matches in <mark class="fts-hl"
   * data-idx="N">.
   *
   * @param {Element}   root
   * @param {Array}     termMap  [{text, idx}, …] for index look-up
   * @param {RegExp}    re       combined regex (with 'g' flag)
   * @param {Function}  [idxFn] optional override: (matchText)→idx
   */
  function _walkAndMark(root, termMap, re, idxFn) {
    var walker = document.createTreeWalker(
      root,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode: function (node) {
          var tag = node.parentElement && node.parentElement.tagName;
          if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'MARK') {
            return NodeFilter.FILTER_REJECT;
          }
          return NodeFilter.FILTER_ACCEPT;
        }
      }
    );

    var textNodes = [];
    while (walker.nextNode()) textNodes.push(walker.currentNode);

    textNodes.forEach(function (textNode) {
      var text = textNode.nodeValue;
      re.lastIndex = 0;
      if (!re.test(text)) return;

      var frag = document.createDocumentFragment();
      var last = 0;
      re.lastIndex = 0;
      var m;
      while ((m = re.exec(text)) !== null) {
        if (m.index > last) {
          frag.appendChild(document.createTextNode(text.slice(last, m.index)));
        }

        // Find which term index this match belongs to
        var matchLower = m[0].toLowerCase();
        var matchedIdx = 0;
        if (idxFn) {
          matchedIdx = idxFn(matchLower);
        } else {
          for (var j = 0; j < termMap.length; j++) {
            if (matchLower === termMap[j].text.toLowerCase()) {
              matchedIdx = termMap[j].idx;
              break;
            }
          }
        }

        var mark = document.createElement('mark');
        mark.className = 'fts-hl';
        mark.setAttribute('data-idx', String(matchedIdx));
        mark.textContent = m[0];
        frag.appendChild(mark);
        last = re.lastIndex;
      }
      if (last < text.length) {
        frag.appendChild(document.createTextNode(text.slice(last)));
      }
      textNode.parentNode.replaceChild(frag, textNode);
    });
  }

  /** Escape a string so it is safe to embed in a RegExp pattern. */
  function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /** Apply marks for ALL defined terms across every <td>.
   *  Each term is processed in a separate pass so per-term regex flags
   *  (caseSensitive, regex) are respected independently.
   *  The TreeWalker rejects existing MARK nodes, so earlier terms take
   *  precedence over later ones for overlapping text.
   */
  function applyAllMarks() {
    var cells = document.querySelectorAll('table.rows-and-columns td');
    if (cells.length === 0) return;

    state.terms.forEach(function (t, i) {
      if (!t.text || !t.text.trim()) return;
      var flags      = t.caseSensitive ? 'g' : 'gi';
      var patternStr = t.regex ? t.text : escapeRegex(t.text);
      var re;
      try {
        re = new RegExp('(' + patternStr + ')', flags);
      } catch (e) {
        termErrors[i] = true;   // flag invalid regex for UI error indicator
        return;
      }
      var termIdx = i;  // capture for closure
      cells.forEach(function (td) {
        _walkAndMark(td, [], re, function () { return termIdx; });
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* Navigation (next / prev / exit cycle)                               */
  /* ------------------------------------------------------------------ */

  /** Collect all marks that are currently visible (enabled + allEnabled). */
  function getVisibleMarks() {
    return Array.prototype.filter.call(
      document.querySelectorAll('mark.fts-hl'),
      function (m) {
        if (!state.allEnabled) return false;
        var idx = parseInt(m.getAttribute('data-idx'), 10);
        return state.terms[idx] && state.terms[idx].enabled;
      }
    );
  }

  /** Move the fts-current class to navMarks[idx] and scroll to it. */
  function navSetCurrent(idx) {
    document.querySelectorAll('mark.fts-hl.fts-current').forEach(function (m) {
      m.classList.remove('fts-current');
    });
    if (idx >= 0 && idx < navMarks.length) {
      navMarks[idx].classList.add('fts-current');
      navMarks[idx].scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }

  /** Remove the current-mark highlight without triggering a full re-render. */
  function navReset() {
    document.querySelectorAll('mark.fts-hl.fts-current').forEach(function (m) {
      m.classList.remove('fts-current');
    });
    navIndex = -1;
    navMarks  = [];
  }

  function navNext() {
    navMarks = getVisibleMarks();
    if (navMarks.length === 0) return;
    navIndex = (navIndex + 1) % navMarks.length;
    navSetCurrent(navIndex);
    renderPanel();
  }

  function navPrev() {
    navMarks = getVisibleMarks();
    if (navMarks.length === 0) return;
    navIndex = (navIndex - 1 + navMarks.length) % navMarks.length;
    navSetCurrent(navIndex);
    renderPanel();
  }

  function navExit() {
    navReset();
    renderPanel();
  }

  /* ------------------------------------------------------------------ */
  /* Full re-render (term list changed — add / remove)                   */
  /* ------------------------------------------------------------------ */
  function rerender() {
    navReset();        // stale nav positions are invalid after DOM rebuild
    termErrors = {};
    removeAllMarks();
    applyAllMarks();
    updateStylesheet();
    renderPanel();
    saveState();
  }

  /* ------------------------------------------------------------------ */
  /* UI — highlight panel                                                 */
  /* ------------------------------------------------------------------ */
  function renderPanel() {
    if (!panelEl) return;
    panelEl.innerHTML = '';

    // ── Master toggle ──────────────────────────────────────────────────
    var toggleAll = document.createElement('button');
    toggleAll.type = 'button';
    toggleAll.className = 'fts-btn fts-toggle-all';
    toggleAll.id = 'fts-highlight-toggle';  // kept for backward-compat tests
    toggleAll.setAttribute('aria-pressed', String(state.allEnabled));
    toggleAll.textContent = state.allEnabled ? 'All: ON' : 'All: OFF';
    toggleAll.title = 'Toggle all highlights on / off';
    toggleAll.addEventListener('click', function () {
      state.allEnabled = !state.allEnabled;
      navReset();
      updateStylesheet();
      renderPanel();
      saveState();
    });
    panelEl.appendChild(toggleAll);

    // ── Navigation bar ─────────────────────────────────────────────────
    var totalVisible = getVisibleMarks().length;
    if (totalVisible > 0 || navIndex >= 0) {
      var navBar = document.createElement('div');
      navBar.className = 'fts-nav-bar';

      var prevBtn = document.createElement('button');
      prevBtn.type = 'button';
      prevBtn.className = 'fts-btn fts-nav-btn';
      prevBtn.textContent = '◄';
      prevBtn.title = 'Previous match';
      prevBtn.setAttribute('aria-label', 'Previous match');
      prevBtn.addEventListener('click', navPrev);
      navBar.appendChild(prevBtn);

      var countSpan = document.createElement('span');
      countSpan.className = 'fts-nav-count';
      if (navIndex >= 0 && navMarks.length > 0) {
        countSpan.textContent = (navIndex + 1) + '\u2009/\u2009' + navMarks.length;
      } else {
        countSpan.textContent = totalVisible + '\u00a0match' + (totalVisible === 1 ? '' : 'es');
      }
      navBar.appendChild(countSpan);

      // Create nextBtn early so the exit-confirmation closure can insertBefore it
      var nextBtn = document.createElement('button');
      nextBtn.type = 'button';
      nextBtn.className = 'fts-btn fts-nav-btn';
      nextBtn.textContent = '►';
      nextBtn.title = 'Next match';
      nextBtn.setAttribute('aria-label', 'Next match');
      nextBtn.addEventListener('click', navNext);

      if (navIndex >= 0) {
        var exitBtn = document.createElement('button');
        exitBtn.type = 'button';
        exitBtn.className = 'fts-btn fts-nav-exit';
        exitBtn.textContent = '×';
        exitBtn.title = 'Exit navigation';
        exitBtn.addEventListener('click', (function (navBarEl, exitBtnEl, nextBtnEl) {
          return function () {
            // Enter confirmation state on the nav bar
            navBarEl.classList.add('fts-nav-bar--confirming');
            exitBtnEl.style.display = 'none';

            var confirmBtn = document.createElement('button');
            confirmBtn.type = 'button';
            confirmBtn.className = 'fts-btn fts-term-remove-confirm';
            confirmBtn.textContent = '✓';
            confirmBtn.title = 'Yes, exit navigation';

            var cancelBtn = document.createElement('button');
            cancelBtn.type = 'button';
            cancelBtn.className = 'fts-btn fts-term-remove-cancel';
            cancelBtn.textContent = '✕';
            cancelBtn.title = 'Stay in navigation';

            confirmBtn.addEventListener('click', navExit);

            cancelBtn.addEventListener('click', function () {
              navBarEl.classList.remove('fts-nav-bar--confirming');
              navBarEl.removeChild(confirmBtn);
              navBarEl.removeChild(cancelBtn);
              exitBtnEl.style.display = '';
            });

            // Insert before ► so the confirmation sits between × and ►
            navBarEl.insertBefore(cancelBtn, nextBtnEl);
            navBarEl.insertBefore(confirmBtn, nextBtnEl);
          };
        })(navBar, exitBtn, nextBtn));
        navBar.appendChild(exitBtn);
      }

      navBar.appendChild(nextBtn);

      panelEl.appendChild(navBar);
    }

    // ── Per-term rows ──────────────────────────────────────────────────
    var list = document.createElement('div');
    list.className = 'fts-term-list';

    state.terms.forEach(function (t, i) {
      var hasError = !!termErrors[i];
      var row = document.createElement('div');
      row.className = 'fts-term-row' + (hasError ? ' fts-term-row--error' : '');
      row.setAttribute('data-idx', String(i));

      // Per-term visibility toggle (● / ○)
      var tog = document.createElement('button');
      tog.type = 'button';
      tog.className = 'fts-btn fts-term-toggle';
      tog.setAttribute('aria-pressed', String(t.enabled));
      tog.textContent = t.enabled ? '●' : '○';
      tog.title = (t.enabled ? 'Hide' : 'Show') + ' "' + t.text + '"';
      tog.addEventListener('click', (function (idx) {
        return function () {
          state.terms[idx].enabled = !state.terms[idx].enabled;
          navReset();
          updateStylesheet();
          renderPanel();
          saveState();
        };
      })(i));
      row.appendChild(tog);

      // Color picker
      var cp = document.createElement('input');
      cp.type = 'color';
      cp.className = 'fts-color-picker';
      cp.value = t.color;
      cp.title = 'Color for "' + t.text + '"';
      cp.addEventListener('input', (function (idx, el) {
        return function () {
          state.terms[idx].color = el.value;
          updateStylesheet();
          saveState();
        };
      })(i, cp));
      row.appendChild(cp);

      // Term label — click to edit inline
      var label = document.createElement('span');
      label.className = 'fts-term-label';
      label.textContent = t.text;
      label.title = hasError ? 'Invalid regex pattern — click to edit'
                              : 'Click to edit';
      // Self-contained click-to-edit handler (no module-level state needed)
      (function (idx, labelEl, rowEl) {
        labelEl.addEventListener('click', function () {
          var input = document.createElement('input');
          input.type  = 'text';
          input.className = 'fts-term-edit-input';
          input.value = state.terms[idx].text;
          rowEl.replaceChild(input, labelEl);
          input.focus();
          input.select();

          var committed = false;

          function commit() {
            if (committed) return;
            committed = true;
            var newText = input.value.trim();
            // Empty input — revert
            if (!newText) { committed = false; rowEl.replaceChild(labelEl, input); return; }
            // Duplicate of another term — revert
            for (var j = 0; j < state.terms.length; j++) {
              if (j !== idx && state.terms[j].text.toLowerCase() === newText.toLowerCase()) {
                committed = false; rowEl.replaceChild(labelEl, input); return;
              }
            }
            // Unchanged — revert display only
            if (newText === state.terms[idx].text) {
              committed = false; rowEl.replaceChild(labelEl, input); return;
            }
            state.terms[idx].text = newText;
            rerender();
          }

          input.addEventListener('blur', commit);
          input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter')  { e.preventDefault(); input.blur(); }
            if (e.key === 'Escape') {
              committed = true;              // suppress blur→commit
              rowEl.replaceChild(labelEl, input);
            }
          });
        });
      })(i, label, row);
      row.appendChild(label);

      // Case-sensitivity toggle [Aa]
      var caseTog = document.createElement('button');
      caseTog.type = 'button';
      caseTog.className = 'fts-btn fts-term-case';
      caseTog.setAttribute('aria-pressed', String(!!t.caseSensitive));
      caseTog.textContent = 'Aa';
      caseTog.title = t.caseSensitive ? 'Case-sensitive — click to ignore case'
                                       : 'Case-insensitive — click to match case';
      caseTog.addEventListener('click', (function (idx) {
        return function () {
          state.terms[idx].caseSensitive = !state.terms[idx].caseSensitive;
          rerender();
        };
      })(i));
      row.appendChild(caseTog);

      // Regex-mode toggle [.*]
      var regexTog = document.createElement('button');
      regexTog.type = 'button';
      regexTog.className = 'fts-btn fts-term-regex';
      regexTog.setAttribute('aria-pressed', String(!!t.regex));
      regexTog.textContent = '.*';
      regexTog.title = t.regex ? 'Regex mode — click for literal'
                                : 'Literal mode — click for regex';
      regexTog.addEventListener('click', (function (idx) {
        return function () {
          state.terms[idx].regex = !state.terms[idx].regex;
          rerender();
        };
      })(i));
      row.appendChild(regexTog);

      // Remove button — first click enters confirmation mode, ✓ confirms, ✗ cancels
      var rm = document.createElement('button');
      rm.type = 'button';
      rm.className = 'fts-btn fts-term-remove';
      rm.textContent = '×';
      rm.title = 'Remove “' + t.text + '”';
      rm.addEventListener('click', (function (idx, rowEl, rmBtn) {
        return function () {
          // Enter confirmation state
          rowEl.classList.add('fts-term-row--confirming');
          rmBtn.style.display = 'none';

          var confirmBtn = document.createElement('button');
          confirmBtn.type = 'button';
          confirmBtn.className = 'fts-btn fts-term-remove-confirm';
          confirmBtn.textContent = '✓';
          confirmBtn.title = 'Yes, remove “' + state.terms[idx].text + '”';

          var cancelBtn = document.createElement('button');
          cancelBtn.type = 'button';
          cancelBtn.className = 'fts-btn fts-term-remove-cancel';
          cancelBtn.textContent = '✕';
          cancelBtn.title = 'Keep term';

          confirmBtn.addEventListener('click', function () {
            state.terms.splice(idx, 1);
            rerender();
          });

          cancelBtn.addEventListener('click', function () {
            rowEl.classList.remove('fts-term-row--confirming');
            rowEl.removeChild(confirmBtn);
            rowEl.removeChild(cancelBtn);
            rmBtn.style.display = '';
          });

          rowEl.appendChild(cancelBtn);
          rowEl.appendChild(confirmBtn);
        };
      })(i, row, rm));
      row.appendChild(rm);

      list.appendChild(row);
    });
    panelEl.appendChild(list);

    // ── Add-term row ───────────────────────────────────────────────────
    var addRow = document.createElement('div');
    addRow.className = 'fts-add-row';

    var textInput = document.createElement('input');
    textInput.type = 'text';
    textInput.className = 'fts-add-input';
    textInput.placeholder = 'Add term…';
    textInput.setAttribute('aria-label', 'New term to highlight');

    var nextColor = DEFAULT_COLORS[state.terms.length % DEFAULT_COLORS.length];
    var newCp = document.createElement('input');
    newCp.type = 'color';
    newCp.className = 'fts-color-picker';
    newCp.value = nextColor;
    newCp.title = 'Color for new term';

    var addBtn = document.createElement('button');
    addBtn.type = 'button';
    addBtn.className = 'fts-btn fts-add-btn';
    addBtn.textContent = '+';
    addBtn.title = 'Add highlight term';

    function doAdd() {
      var text = textInput.value.trim();
      if (!text) return;
      var lower = text.toLowerCase();
      for (var i = 0; i < state.terms.length; i++) {
        if (state.terms[i].text.toLowerCase() === lower) {
          textInput.value = '';
          textInput.focus();
          return;  // duplicate — silently ignore
        }
      }
      state.terms.push({ text: text, color: newCp.value, enabled: true,
                         regex: false, caseSensitive: false });
      textInput.value = '';
      rerender();
      var fresh = panelEl.querySelector('.fts-add-input');
      if (fresh) fresh.focus();
    }

    addBtn.addEventListener('click', doAdd);
    textInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') doAdd();
    });

    addRow.appendChild(textInput);
    addRow.appendChild(newCp);
    addRow.appendChild(addBtn);
    panelEl.appendChild(addRow);

    // ── Page-scope note ────────────────────────────────────────────────
    var note = document.createElement('p');
    note.className = 'fts-panel-note';
    note.textContent = 'ⓘ Highlights apply to this page only — '
      + 'use ◄ / ► to page through results and re-apply.';
    panelEl.appendChild(note);
  }

  /* ------------------------------------------------------------------ */
  /* Initialise                                                           */
  /* ------------------------------------------------------------------ */
  function init() {
    var tableWrapper = document.querySelector('.table-wrapper');
    if (!tableWrapper) return;  // Only inject on table pages

    var urlTokens = FtsHighlight.tokensFromUrl();

    // Seed state: prefer localStorage, fall back to URL params
    var saved = loadState();
    if (saved) {
      state = saved;
    } else {
      // No saved state — seed terms from URL if present; otherwise start empty
      state.allEnabled = true;
      state.terms = urlTokens.map(function (tok, i) {
        return { text: tok, color: DEFAULT_COLORS[i % DEFAULT_COLORS.length],
                 enabled: true, regex: false, caseSensitive: false };
      });
    }

    // Always inject panel on table pages (user can add terms even on non-search pages)
    styleEl = document.createElement('style');
    styleEl.id = 'fts-hl-styles';
    document.head.appendChild(styleEl);

    panelEl = document.createElement('div');
    panelEl.id = 'fts-highlight-panel';
    panelEl.className = 'fts-highlight-panel';
    tableWrapper.insertAdjacentElement('beforebegin', panelEl);

    applyAllMarks();
    updateStylesheet();
    renderPanel();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.FtsHighlight = FtsHighlight;
})();
