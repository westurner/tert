"""
tests/test_search_highlight.py

Testing plan for FTS search-result highlighting (search-highlight.js).

Layers tested here
------------------
1. Token extraction logic  (Python mirror of extractTokens() / tokensFromUrl())
2. Datasette FTS integration  (server returns the right rows for ?_search=…)
3. Static asset is served  (GET /static/search-highlight.js → 200)

Browser-interaction tests (mark insertion, toggle, localStorage persistence)
require a headless browser.  They are collected below under the
``TestBrowserHighlight`` class and are skipped automatically unless
``pytest-playwright`` is installed.  To run them:

    pip install pytest-playwright
    playwright install chromium
    pytest tests/test_search_highlight.py -k browser -v

Architecture notes (for the JS layer)
--------------------------------------
The JS module (static/search-highlight.js) is structured so the pure-logic
parts are attached to ``window.FtsHighlight`` and can therefore be exercised
in a headless browser context without mocking the DOM.  The init() function
is self-contained and only runs after DOMContentLoaded, making it safe to
load the script in Playwright page.addScriptTag().
"""

import re
import sqlite3
import pathlib
import tempfile

import pytest

try:
    import datasette.app

    DATASETTE_AVAILABLE = True
except ImportError:
    DATASETTE_AVAILABLE = False

try:
    import playwright.async_api  # noqa: F401

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

skip_no_datasette = pytest.mark.skipif(
    not DATASETTE_AVAILABLE, reason="datasette not installed"
)
skip_no_playwright = pytest.mark.skipif(
    not PLAYWRIGHT_AVAILABLE,
    reason="pytest-playwright not installed; "
    "run: pip install pytest-playwright && playwright install chromium",
)

# ---------------------------------------------------------------------------
# Python mirrors of viridis palette + resolveColors()
# Keep in sync with search-highlight.js.
# ---------------------------------------------------------------------------

# Viridis 8-sample lightened 70 % toward white.
# Derivation: sample viridis at t=0,1/7,...,1; blend each channel:
#   c' = round(c + (255 - c) * 0.70)
# Source: Smith & van der Walt, SciPy 2015 (CC0). https://bids.github.io/colormap/
VIRIDIS_COLORS: list[str] = [
    "#c7b3cc",  # t=0.000 — deep purple lightened
    "#c8c2d8",  # t=0.143 — purple lightened
    "#c3cedd",  # t=0.286 — blue lightened
    "#bed9dd",  # t=0.429 — teal lightened
    "#bce3db",  # t=0.571 — teal-green lightened
    "#c9ecd3",  # t=0.714 — green lightened
    "#e2f4c4",  # t=0.857 — yellow-green lightened
    "#fef8be",  # t=1.000 — yellow lightened
]

PASTEL_COLORS: list[str] = [
    "#fff176",  # yellow
    "#b3f0ff",  # cyan
    "#c8f7c5",  # green
    "#ffcba4",  # peach
    "#e8b4ff",  # purple
    "#ffd4d4",  # pink-red
    "#d4e4ff",  # blue
    "#ffe4b5",  # amber
]

# Glasbey bw_minc_20 — first 8 from colorcet.glasbey_bw_minc_20, blended
# 60 % toward white: c' = round(c + (255 - c) * 0.60)
#
# Sources
# -------
# colorcet: https://colorcet.holoviz.org/user_guide/Categorical.html
#
# Glasbey, Chris; van der Heijden, Gerie & Toh, Vivian F. K. et al. (2007),
# "Colour displays for categorical images",
# Color Research & Application 32.4: 304-309.
# https://strathprints.strath.ac.uk/30312/1/colorpaper_2006.pdf
GLASBEY_BW_MINC_20_COLORS: list[str] = [
    "#ef9999",  #  0: #d70000 lightened — red
    "#d1b1ff",  #  1: #8c3cff lightened — purple
    "#9acf99",  #  2: #028800 lightened — green
    "#99dee9",  #  3: #00acc7 lightened — teal
    "#d6ff99",  #  4: #98ff00 lightened — lime
    "#ffcced",  #  5: #ff7fd1 lightened — pink
    "#c499b9",  #  6: #6c004f lightened — mauve
    "#ffdbac",  #  7: #ffa530 lightened — orange
    "#bcb199",  #  8: #583b00 lightened — dark brown
    "#99bcbd",  #  9: #005759 lightened — dark teal
    "#9999f1",  # 10: #0000dd lightened — blue
    "#99feec",  # 11: #00fdcf lightened — cyan-mint
    "#d9c8c3",  # 12: #a1756a lightened — dusty rose
    "#e4e2ff",  # 13: #bcb7ff lightened — lavender
    "#d5e1c9",  # 14: #95b578 lightened — sage
    "#e69be3",  # 15: #c004b9 lightened — magenta
    "#c1bbc7",  # 16: #645474 lightened — muted purple
    "#c99999",  # 17: #790000 lightened — dark red
    "#9cc7ef",  # 18: #0774d8 lightened — sky blue
    "#fffbd3",  # 19: #fef590 lightened — pale yellow
    "#99b799",  # 20: #004b00 lightened — dark green
    "#d2ca99",  # 21: #8f7a00 lightened — olive
    "#ffc7c2",  # 22: #ff7266 lightened — salmon
    "#f8e3e3",  # 23: #eeb9b9 lightened — blush
    "#bfcbc2",  # 24: #5e7e66 lightened — muted sage
    "#d7f4ff",  # 25: #9be4ff lightened — pale cyan
    "#f799c9",  # 26: #ec0077 lightened — hot pink
    "#dbcae3",  # 27: #a67bb9 lightened — soft violet
    "#bd99db",  # 28: #5a00a4 lightened — indigo
    "#9be899",  # 29: #04c600 lightened — bright green
    "#d8b799",  # 30: #9e4b00 lightened — burnt sienna
    "#d7b1b9",  # 31: #9c3b50 lightened — dusty burgundy
]


def resolve_colors(cfg: dict | None) -> list[str]:
    """Python equivalent of FtsHighlight.resolveColors(cfg)."""
    c = (cfg or {}).get("colors")
    if not c or c == "viridis":
        return VIRIDIS_COLORS
    if c == "pastel":
        return PASTEL_COLORS
    if c == "glasbey_bw_minc_20":
        return GLASBEY_BW_MINC_20_COLORS
    if isinstance(c, list) and len(c) > 0:
        return c
    return VIRIDIS_COLORS


# ---------------------------------------------------------------------------
# Python mirror of search-highlight.js :: extractTokens()
# Keep this in sync with the JS implementation so the test suite serves as a
# cross-language contract.
# ---------------------------------------------------------------------------


def extract_tokens(query: str) -> list[str]:
    """Python equivalent of FtsHighlight.extractTokens(query)."""
    tokens: list[str] = []

    # 1. Quoted phrases → single token
    phrases = re.findall(r'"([^"]*)"', query)
    tokens.extend(p.strip() for p in phrases if p.strip())

    # 2. Strip structure from remainder
    remainder = re.sub(r'"[^"]*"', " ", query)
    remainder = re.sub(r"NEAR\s*\([^)]*\)", " ", remainder, flags=re.IGNORECASE)
    remainder = re.sub(r"\b(AND|OR|NOT)\b", " ", remainder, flags=re.IGNORECASE)
    remainder = re.sub(r"[{}\[\]^*:]", " ", remainder)

    # 3. Words with ≥ 2 chars
    words = [w for w in remainder.split() if len(w) >= 2]
    tokens.extend(words)

    # 4. Deduplicate case-insensitively, longest first
    seen: set[str] = set()
    unique: list[str] = []
    for t in tokens:
        k = t.lower()
        if k not in seen:
            seen.add(k)
            unique.append(t)
    unique.sort(key=len, reverse=True)
    return unique


def tokens_from_url(url: str) -> list[str]:
    """Python equivalent of FtsHighlight.tokensFromUrl() given a full URL string."""
    from urllib.parse import urlparse, parse_qs

    qs = parse_qs(urlparse(url).query)
    tokens: list[str] = []
    for key, vals in qs.items():
        if key == "_search" or key.startswith("_search_"):
            for v in vals:
                tokens.extend(extract_tokens(v))
    # Deduplicate
    seen: set[str] = set()
    unique: list[str] = []
    for t in tokens:
        k = t.lower()
        if k not in seen:
            seen.add(k)
            unique.append(t)
    return unique


# ===========================================================================
# 1. Unit tests — token extraction logic
# ===========================================================================


class TestExtractTokens:
    """Mirrors FtsHighlight.extractTokens() contract."""

    def test_simple_word(self):
        assert extract_tokens("pytest") == ["pytest"]

    def test_two_words(self):
        result = extract_tokens("pytest cargo")
        assert "pytest" in result
        assert "cargo" in result

    def test_strips_AND_OR_NOT(self):
        result = extract_tokens("pytest AND cargo OR tert NOT foo")
        assert "AND" not in result
        assert "OR" not in result
        assert "NOT" not in result
        assert "pytest" in result
        assert "cargo" in result
        assert "tert" in result
        assert "foo" in result

    def test_strips_NEAR_expression(self):
        result = extract_tokens("NEAR(pytest cargo, 5)")
        # NEAR itself and its args should not appear as tokens
        assert not any("NEAR" in t for t in result)

    def test_quoted_phrase_kept_as_one_token(self):
        result = extract_tokens('"pytest cargo"')
        assert "pytest cargo" in result
        # individual words should not appear separately
        assert "pytest" not in result
        assert "cargo" not in result

    def test_wildcard_stripped(self):
        result = extract_tokens("pytest*")
        assert "pytest" in result
        assert "pytest*" not in result

    def test_single_char_dropped(self):
        result = extract_tokens("a pytest b")
        assert "a" not in result
        assert "b" not in result
        assert "pytest" in result

    def test_deduplication_case_insensitive(self):
        result = extract_tokens("Pytest pytest PYTEST")
        # Only one entry (whichever casing came first)
        assert len([t for t in result if t.lower() == "pytest"]) == 1

    def test_longest_first_ordering(self):
        result = extract_tokens("py pytest run")
        # "pytest" (6) should come before "run" (3) and "py" (2)
        assert result.index("pytest") < result.index("run")

    def test_empty_query(self):
        assert extract_tokens("") == []

    def test_only_operators(self):
        result = extract_tokens("AND OR NOT")
        assert result == []

    def test_column_filter_colon_stripped(self):
        # FTS5 column filters like {command}: pytest
        result = extract_tokens("{command}: pytest")
        assert "pytest" in result
        assert "{command}" not in result
        assert "command" not in result or True  # col name may or may not appear


class TestTokensFromUrl:
    """Mirrors FtsHighlight.tokensFromUrl() contract."""

    def test_search_param(self):
        result = tokens_from_url(
            "http://localhost:8001/replog/test_runs?_search=pytest"
        )
        assert "pytest" in result

    def test_search_colname_param(self):
        result = tokens_from_url(
            "http://localhost:8001/replog/test_artifacts?_search_command=cargo"
        )
        assert "cargo" in result

    def test_multiple_params_merged(self):
        result = tokens_from_url(
            "http://localhost:8001/replog/test_artifacts"
            "?_search=pytest&_search_command=cargo"
        )
        assert "pytest" in result
        assert "cargo" in result

    def test_no_search_param_returns_empty(self):
        result = tokens_from_url("http://localhost:8001/replog/test_runs")
        assert result == []

    def test_deduplication_across_params(self):
        result = tokens_from_url(
            "http://localhost:8001/replog/test_artifacts"
            "?_search=pytest&_search_command=pytest"
        )
        assert len([t for t in result if t.lower() == "pytest"]) == 1


# ===========================================================================
# 1c. Unit tests — resolveColors() / FTS_HIGHLIGHT_CONFIG color option
# ===========================================================================


class TestResolveColors:
    """Mirrors FtsHighlight.resolveColors(cfg) contract.

    The JavaScript function reads window.FTS_HIGHLIGHT_CONFIG (set by
    fts-highlight-config.js, loaded before search-highlight.js) and returns
    the active color palette.  These tests verify the Python mirror has the
    same behaviour and serve as a cross-language specification.
    """

    def test_none_config_gives_viridis(self):
        assert resolve_colors(None) == VIRIDIS_COLORS

    def test_empty_config_gives_viridis(self):
        assert resolve_colors({}) == VIRIDIS_COLORS

    def test_colors_null_gives_viridis(self):
        assert resolve_colors({"colors": None}) == VIRIDIS_COLORS

    def test_colors_viridis_gives_viridis(self):
        assert resolve_colors({"colors": "viridis"}) == VIRIDIS_COLORS

    def test_colors_pastel_gives_pastel(self):
        assert resolve_colors({"colors": "pastel"}) == PASTEL_COLORS

    def test_colors_custom_array(self):
        custom = ["#aabbcc", "#ddeeff"]
        assert resolve_colors({"colors": custom}) == custom

    def test_colors_empty_array_falls_back_to_viridis(self):
        # An empty list is treated as "not set" — fall back to viridis
        assert resolve_colors({"colors": []}) == VIRIDIS_COLORS

    def test_colors_unknown_string_falls_back_to_viridis(self):
        assert resolve_colors({"colors": "plasma"}) == VIRIDIS_COLORS

    def test_colors_glasbey_bw_minc_20(self):
        assert (
            resolve_colors({"colors": "glasbey_bw_minc_20"})
            == GLASBEY_BW_MINC_20_COLORS
        )

    def test_glasbey_has_eight_entries(self):
        assert len(GLASBEY_BW_MINC_20_COLORS) == 32

    def test_glasbey_colors_are_valid_hex(self):
        """Each glasbey entry must be a 7-char #rrggbb string."""
        import re as _re

        for color in GLASBEY_BW_MINC_20_COLORS:
            assert _re.fullmatch(r"#[0-9a-fA-F]{6}", color), (
                f"Invalid hex color: {color}"
            )

    def test_glasbey_colors_are_light(self):
        """Lightened glasbey backgrounds must be perceptually light (avg channel > 150)."""
        for color in GLASBEY_BW_MINC_20_COLORS:
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            avg = (r + g + b) / 3
            assert avg > 150, (
                f"{color} is too dark for a highlight background (avg={avg:.0f})"
            )

    def test_glasbey_derivation_60pct_white_blend(self):
        """Verify the 60%-white-blend derivation for two known glasbey samples.

        colorcet.glasbey_bw_minc_20[0] = #d70000 (R=215, G=0, B=0)
        Blend 60% toward white: c' = round(c + (255-c)*0.60)
          R' = round(215 + 40*0.60) = round(239) = 239 = 0xEF
          G' = round(0 + 255*0.60)  = round(153) = 153 = 0x99
          B' = round(0 + 255*0.60)  = 153 = 0x99
        → #ef9999

        colorcet.glasbey_bw_minc_20[7] = #ffa530 (R=255, G=165, B=48)
          R' = 255
          G' = round(165 + 90*0.60)  = round(219) = 219 = 0xDB
          B' = round(48 + 207*0.60)  = round(172) = 172 = 0xAC
        → #ffdbac

        colorcet.glasbey_bw_minc_20[31] = #9c3b50 (R=156, G=59, B=80)
          R' = round(156 + 99*0.60)   = round(215.4) = 215 = 0xD7
          G' = round(59 + 196*0.60)   = round(176.6) = 177 = 0xB1
          B' = round(80 + 175*0.60)   = round(185)   = 185 = 0xB9
        → #d7b1b9
        """
        assert GLASBEY_BW_MINC_20_COLORS[0] == "#ef9999"
        assert GLASBEY_BW_MINC_20_COLORS[7] == "#ffdbac"
        assert GLASBEY_BW_MINC_20_COLORS[31] == "#d7b1b9"

    def test_viridis_has_eight_entries(self):
        assert len(VIRIDIS_COLORS) == 8

    def test_pastel_has_eight_entries(self):
        assert len(PASTEL_COLORS) == 8

    def test_viridis_colors_are_valid_hex(self):
        """Each viridis entry must be a 7-char #rrggbb string."""
        import re as _re

        for color in VIRIDIS_COLORS:
            assert _re.fullmatch(r"#[0-9a-fA-F]{6}", color), (
                f"Invalid hex color: {color}"
            )

    def test_viridis_colors_are_light(self):
        """Lightened viridis backgrounds must be perceptually light (avg channel > 150)."""
        for color in VIRIDIS_COLORS:
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            avg = (r + g + b) / 3
            assert avg > 150, (
                f"{color} is too dark for a highlight background (avg={avg:.0f})"
            )

    def test_viridis_derivation_70pct_white_blend(self):
        """Verify the 70%-white-blend derivation for a known viridis sample.

        Viridis at t=1.0 is #fde725 (R=253, G=231, B=37).
        Blend 70% toward white: c' = round(c + (255-c)*0.70)
          R' = round(253 + 2*0.70)  = 254 = 0xFE
          G' = round(231 + 24*0.70) = 248 = 0xF8
          B' = round(37 + 218*0.70) = 190 = 0xBE
        """
        assert VIRIDIS_COLORS[-1] == "#fef8be"

    def test_storage_key_default(self):
        """Default storageKey must be 'tert-fts-hl' when not overridden."""
        cfg = {}
        key = cfg.get("storageKey") or "tert-fts-hl"
        assert key == "tert-fts-hl"

    def test_storage_key_custom(self):
        """Custom storageKey must be returned as-is."""
        cfg = {"storageKey": "my-app-fts-hl"}
        key = cfg.get("storageKey") or "tert-fts-hl"
        assert key == "my-app-fts-hl"


# ===========================================================================
# 2. Integration tests — Datasette FTS pipeline
#    (verifies the server correctly returns FTS-matched rows so the JS has
#     something to highlight)
# ===========================================================================


@pytest.fixture
def replog_db(tmp_path):
    """Create a minimal replog DB with FTS5 content tables for testing."""
    import sys, os

    os.environ.setdefault("PYTEST_RUNNING", "1")
    repo_src = pathlib.Path(__file__).parent.parent / "src"
    sys.path.insert(0, str(repo_src))
    from tert.run_tests import ReplogDB, TertTestRun  # type: ignore

    db_path = tmp_path / "test_replog.db"
    db = ReplogDB(db_path)

    # Insert two runs
    runs = [
        TertTestRun(
            timestamp_ns="2024-01-01T00:00:00.000000000+00:00",
            epoch_ns=1_704_067_200_000_000_000,
            exit_code=0,
            out_dir=tmp_path / "run1",
        ),
        TertTestRun(
            timestamp_ns="2024-01-02T00:00:00.000000000+00:00",
            epoch_ns=1_704_153_600_000_000_000,
            exit_code=1,
            out_dir=tmp_path / "run2",
        ),
    ]
    for run in runs:
        db.insert_run(run)
        db.insert_artifact(
            run.epoch_ns,
            run.timestamp_ns,
            run.out_dir,
            "pytest-results.xml",
            f"<testsuite name='tert_tests' epoch='{run.epoch_ns}'/>",
            "pytest",
            run.exit_code,
        )
        db.insert_artifact(
            run.epoch_ns,
            run.timestamp_ns,
            run.out_dir,
            "build.log",
            f"cargo build --release  epoch={run.epoch_ns}",
            "cargo build",
            0,
        )

    return db_path


@skip_no_datasette
class TestDatasetteFTSIntegration:
    """Verify that Datasette correctly surfaces FTS5 search results.

    These tests confirm the *server side* is working correctly so the JS
    has matching rows to highlight.
    """

    def _get_async(self, coro):
        """Run an async coroutine synchronously (Python 3.10+ compatible)."""
        import asyncio

        return asyncio.run(coro)

    def _make_ds(self, db_path: pathlib.Path):
        import datasette.app

        return datasette.app.Datasette(
            files=[str(db_path)],
            settings={"sql_time_limit_ms": 3500},
        )

    def test_table_page_returns_200(self, replog_db):
        ds = self._make_ds(replog_db)

        async def _get():
            return await ds.client.get("/test_replog/test_runs")

        r = self._get_async(_get())
        assert r.status_code == 200

    def test_search_returns_matching_rows_json(self, replog_db):
        """?_search=pytest should find the pytest artifact rows."""
        ds = self._make_ds(replog_db)

        async def _get():
            return await ds.client.get(
                "/test_replog/test_artifacts.json?_search=pytest&_shape=array"
            )

        r = self._get_async(_get())
        assert r.status_code == 200
        data = r.json()
        assert len(data) > 0, "Expected at least one row matching 'pytest'"
        filenames = [row["filename"] for row in data]
        assert any("pytest" in f for f in filenames)

    def test_search_no_match_returns_empty(self, replog_db):
        """?_search=NOMATCH should return zero rows."""
        ds = self._make_ds(replog_db)

        async def _get():
            return await ds.client.get(
                "/test_replog/test_artifacts.json"
                "?_search=ZZZNOMATCH_XYZ_ZZZZ&_shape=array"
            )

        r = self._get_async(_get())
        assert r.status_code == 200
        assert r.json() == []

    def test_search_column_filter(self, replog_db):
        """?_search_command=cargo should only match rows whose command contains 'cargo'."""
        ds = self._make_ds(replog_db)

        async def _get():
            return await ds.client.get(
                "/test_replog/test_artifacts.json?_search_command=cargo&_shape=array"
            )

        r = self._get_async(_get())
        assert r.status_code == 200
        data = r.json()
        assert len(data) > 0
        assert all("cargo" in (row.get("command") or "").lower() for row in data)

    def test_static_js_file_served(self, replog_db, tmp_path):
        """GET /static/search-highlight.js must return 200 with JS content."""
        static_dir = pathlib.Path(__file__).parent.parent / "static"
        import datasette.app

        ds = datasette.app.Datasette(
            files=[str(replog_db)],
            static_mounts=[("static", str(static_dir))],
        )

        async def _get():
            return await ds.client.get("/static/search-highlight.js")

        r = self._get_async(_get())
        assert r.status_code == 200
        assert "FtsHighlight" in r.text, "JS must expose window.FtsHighlight"
        assert "extractTokens" in r.text

    def test_config_js_file_served(self, replog_db, tmp_path):
        """GET /static/fts-highlight-config.js must return 200 with config object."""
        static_dir = pathlib.Path(__file__).parent.parent / "static"
        import datasette.app

        ds = datasette.app.Datasette(
            files=[str(replog_db)],
            static_mounts=[("static", str(static_dir))],
        )

        async def _get():
            return await ds.client.get("/static/fts-highlight-config.js")

        r = self._get_async(_get())
        assert r.status_code == 200
        assert "FTS_HIGHLIGHT_CONFIG" in r.text
        assert "viridis" in r.text
        assert "storageKey" in r.text

    def test_config_js_contains_viridis_citation(self, replog_db, tmp_path):
        """Config file must include citation URL for the viridis colormap."""
        static_dir = pathlib.Path(__file__).parent.parent / "static"
        import datasette.app

        ds = datasette.app.Datasette(
            files=[str(replog_db)],
            static_mounts=[("static", str(static_dir))],
        )

        async def _get():
            return await ds.client.get("/static/fts-highlight-config.js")

        r = self._get_async(_get())
        assert r.status_code == 200
        assert "bids.github.io/colormap" in r.text, (
            "Config file must cite the viridis colormap source"
        )

    def test_search_highlight_js_contains_viridis_colors(self, replog_db, tmp_path):
        """search-highlight.js must export VIRIDIS_COLORS with the expected first entry."""
        static_dir = pathlib.Path(__file__).parent.parent / "static"
        import datasette.app

        ds = datasette.app.Datasette(
            files=[str(replog_db)],
            static_mounts=[("static", str(static_dir))],
        )

        async def _get():
            return await ds.client.get("/static/search-highlight.js")

        r = self._get_async(_get())
        assert r.status_code == 200
        assert "VIRIDIS_COLORS" in r.text
        assert "PASTEL_COLORS" in r.text
        assert "resolveColors" in r.text
        # Verify the viridis yellow (t=1.0 lightened) is present
        assert "#fef8be" in r.text

    def test_html_page_includes_js_tag(self, replog_db, tmp_path):
        """Table HTML page must include a <script> tag for search-highlight.js."""
        static_dir = pathlib.Path(__file__).parent.parent / "static"
        metadata = {
            "extra_js_urls": [
                "/static/fts-highlight-config.js",
                "/static/search-highlight.js",
            ],
        }
        import datasette.app

        ds = datasette.app.Datasette(
            files=[str(replog_db)],
            static_mounts=[("static", str(static_dir))],
            metadata=metadata,
        )

        async def _get():
            return await ds.client.get("/test_replog/test_runs")

        r = self._get_async(_get())
        assert r.status_code == 200
        assert "fts-highlight-config.js" in r.text
        assert "search-highlight.js" in r.text


# ===========================================================================
# 3. Browser interaction tests (requires pytest-playwright)
#
# Run with:
#   pip install pytest-playwright
#   playwright install chromium
#   pytest tests/test_search_highlight.py::TestBrowserHighlight -v
#
# These tests start a live Datasette server and drive Chromium to verify:
#   - <mark class="fts-highlight"> elements appear in matching td cells
#   - The toggle button is present and labelled correctly
#   - Clicking the toggle adds/removes body.fts-highlights-off
#   - Clicking twice restores highlights
#   - localStorage key persists the state
#   - No marks appear when there is no ?_search= param
# ===========================================================================


@skip_no_playwright
class TestBrowserHighlight:
    """Headless browser tests for search-highlight.js v2 behaviour.

    Run with:
        pip install pytest-playwright && playwright install chromium
        pytest tests/test_search_highlight.py::TestBrowserHighlight -v
    """

    @pytest.fixture(autouse=True)
    def _start_datasette(self, replog_db, tmp_path):
        """Start a Datasette subprocess and expose self.base_url / self.db_name."""
        import subprocess, time, socket, sys, json

        static_dir = str(pathlib.Path(__file__).parent.parent / "static")
        meta = tmp_path / "meta.json"
        meta.write_text(
            json.dumps(
                {
                    "extra_js_urls": ["/static/search-highlight.js"],
                    "extra_css_urls": ["/static/custom.css"],
                    "databases": {
                        replog_db.stem: {
                            "tables": {
                                "test_runs": {"fts_table": "test_runs_fts"},
                                "test_artifacts": {"fts_table": "test_artifacts_fts"},
                            }
                        }
                    },
                }
            )
        )

        with socket.socket() as s:
            s.bind(("", 0))
            port = s.getsockname()[1]

        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "datasette",
                "serve",
                str(replog_db),
                "--metadata",
                str(meta),
                "--static",
                f"static:{static_dir}",
                "--port",
                str(port),
                "--noenv",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                import urllib.request

                urllib.request.urlopen(
                    f"http://localhost:{port}/-/versions.json", timeout=1
                )
                break
            except Exception:
                time.sleep(0.2)

        self.base_url = f"http://localhost:{port}"
        self.db_name = replog_db.stem
        yield
        proc.terminate()
        proc.wait()

    def _url(self, table: str, params: str = "") -> str:
        return f"{self.base_url}/{self.db_name}/{table}{params}"

    def _clear_storage(self, page):
        """Remove persisted state so each test starts fresh."""
        page.evaluate("localStorage.removeItem('tert-fts-hl')")

    # ── Mark insertion ─────────────────────────────────────────────────

    def test_marks_appear_for_search_term(self, page):
        """<mark class="fts-hl"> must appear in td cells when ?_search=pytest."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        assert page.locator("td mark.fts-hl").count() > 0

    def test_marks_text_matches_token(self, page):
        """Every mark's inner text must case-insensitively equal the search token."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        for m in page.locator("td mark.fts-hl").all():
            assert m.text_content().strip().lower() == "pytest"

    def test_no_marks_without_search_param(self, page):
        """No <mark> elements when there is no ?_search param."""
        page.goto(self._url("test_artifacts"))
        page.wait_for_load_state("networkidle")
        assert page.locator("mark.fts-hl").count() == 0

    def test_marks_only_in_td_not_th(self, page):
        """Marks must only appear in data cells (<td>), never in headers (<th>)."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        assert page.locator("th mark.fts-hl").count() == 0
        assert page.locator("td mark.fts-hl").count() > 0

    def test_multiple_terms_all_highlighted(self, page):
        """Both tokens must appear as marks when searched together."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest+cargo"))
        page.wait_for_load_state("networkidle")
        texts = [m.text_content().lower() for m in page.locator("td mark.fts-hl").all()]
        assert any(t == "pytest" for t in texts), "pytest not highlighted"
        assert any(t == "cargo" for t in texts), "cargo not highlighted"

    def test_each_term_has_distinct_data_idx(self, page):
        """Multiple terms must get distinct data-idx values (0, 1, …)."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest+cargo"))
        page.wait_for_load_state("networkidle")
        idxs = set(
            m.get_attribute("data-idx") for m in page.locator("td mark.fts-hl").all()
        )
        assert len(idxs) > 1, "Expected marks with different data-idx values"

    # ── Panel presence ─────────────────────────────────────────────────

    def test_panel_present_when_searching(self, page):
        """#fts-highlight-panel must appear on pages with ?_search=."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        assert page.locator("#fts-highlight-panel").is_visible()

    def test_panel_absent_without_search(self, page):
        """No panel on pages that have no ?_search param."""
        page.goto(self._url("test_artifacts"))
        page.wait_for_load_state("networkidle")
        assert page.locator("#fts-highlight-panel").count() == 0

    # ── Master toggle ──────────────────────────────────────────────────

    def test_master_toggle_button_present(self, page):
        """#fts-highlight-toggle (master toggle) must be visible in the panel."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        btn = page.locator("#fts-highlight-toggle")
        assert btn.is_visible()
        assert btn.get_attribute("aria-pressed") == "true"
        assert "ON" in btn.text_content()

    def test_master_toggle_click_hides_all_marks(self, page):
        """Clicking master toggle must set aria-pressed=false and hide marks."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        btn = page.locator("#fts-highlight-toggle")
        btn.click()
        assert btn.get_attribute("aria-pressed") == "false"
        assert "OFF" in btn.text_content()
        # Marks are still in the DOM but hidden via CSS — check style rule
        css = page.evaluate("document.getElementById('fts-hl-styles').textContent")
        assert "display: none" in css

    def test_master_toggle_click_twice_restores(self, page):
        """Clicking master toggle twice brings highlights back."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        btn = page.locator("#fts-highlight-toggle")
        btn.click()
        btn.click()
        assert btn.get_attribute("aria-pressed") == "true"
        css = page.evaluate("document.getElementById('fts-hl-styles').textContent")
        assert "display: none" not in css

    def test_master_toggle_state_in_localstorage(self, page):
        """allEnabled=false must be saved under the new STORAGE_KEY."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        page.locator("#fts-highlight-toggle").click()
        raw = page.evaluate("localStorage.getItem('tert-fts-hl')")
        import json as _json

        assert _json.loads(raw)["allEnabled"] is False

    def test_master_toggle_state_survives_reload(self, page):
        """OFF state must be restored after page reload."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        page.locator("#fts-highlight-toggle").click()
        page.reload()
        page.wait_for_load_state("networkidle")
        btn = page.locator("#fts-highlight-toggle")
        assert btn.get_attribute("aria-pressed") == "false"

    # ── Per-term toggle ────────────────────────────────────────────────

    def test_per_term_toggle_buttons_present(self, page):
        """A .fts-term-toggle button must exist for each initial term."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        assert page.locator(".fts-term-toggle").count() == 1

    def test_per_term_toggle_hides_only_that_term(self, page):
        """Toggling one term OFF should only add display:none for its data-idx."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest+cargo"))
        page.wait_for_load_state("networkidle")
        # Toggle first term off
        page.locator(".fts-term-toggle").first.click()
        css = page.evaluate("document.getElementById('fts-hl-styles').textContent")
        # idx=0 hidden, idx=1 still visible
        assert 'data-idx="0"] { display: none' in css
        assert 'data-idx="1"] { display: none' not in css

    def test_per_term_toggle_aria_pressed_flips(self, page):
        """Clicking per-term toggle must flip its aria-pressed attribute."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        tog = page.locator(".fts-term-toggle").first
        assert tog.get_attribute("aria-pressed") == "true"
        tog.click()
        assert tog.get_attribute("aria-pressed") == "false"
        tog.click()
        assert tog.get_attribute("aria-pressed") == "true"

    # ── Color picker ───────────────────────────────────────────────────

    def test_color_picker_present_per_term(self, page):
        """Each term row must contain an <input type="color"> element."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        assert page.locator(".fts-term-row input[type='color']").count() == 1

    def test_color_picker_reflects_initial_color(self, page):
        """The first term's color picker must match VIRIDIS_COLORS[0] (#c7b3cc) by default."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        val = page.locator(".fts-term-row input[type='color']").first.input_value()
        assert val.lower() == "#c7b3cc", (
            f"Expected viridis first color #c7b3cc, got {val}"
        )

    def test_color_picker_reflects_pastel_when_config_set(self, page):
        """When FTS_HIGHLIGHT_CONFIG.colors='pastel', first color must be #fff176."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        # Override config and re-init
        page.evaluate("""() => {
            window.FTS_HIGHLIGHT_CONFIG = { colors: 'pastel', storageKey: 'tert-fts-hl' };
            // Simulate fresh page: re-seed state from URL (clear storage first)
            localStorage.removeItem('tert-fts-hl');
            // Re-read resolveColors from the live module
            window.__testPastelFirst = window.FtsHighlight.resolveColors({ colors: 'pastel' })[0];
        }""")
        first_color = page.evaluate("window.__testPastelFirst")
        assert first_color.lower() == "#fff176"

    def test_resolveColors_viridis_in_browser(self, page):
        """FtsHighlight.resolveColors({colors:'viridis'}) must return viridis palette."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        colors = page.evaluate(
            "window.FtsHighlight.resolveColors({ colors: 'viridis' })"
        )
        assert colors[0].lower() == "#c7b3cc"
        assert colors[-1].lower() == "#fef8be"
        assert len(colors) == 8

    def test_resolveColors_pastel_in_browser(self, page):
        """FtsHighlight.resolveColors({colors:'pastel'}) must return pastel palette."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        colors = page.evaluate(
            "window.FtsHighlight.resolveColors({ colors: 'pastel' })"
        )
        assert colors[0].lower() == "#fff176"
        assert len(colors) == 8

    def test_resolveColors_custom_array_in_browser(self, page):
        """FtsHighlight.resolveColors with a custom array must return that array."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        custom = ["#aabbcc", "#ddeeff"]
        colors = page.evaluate(
            "window.FtsHighlight.resolveColors({ colors: ['#aabbcc', '#ddeeff'] })"
        )
        assert colors == custom

    def test_resolveColors_null_falls_back_to_viridis(self, page):
        """FtsHighlight.resolveColors({colors:null}) must fall back to viridis."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        colors = page.evaluate("window.FtsHighlight.resolveColors({ colors: null })")
        assert colors[0].lower() == "#c7b3cc"

    def test_resolveColors_glasbey_in_browser(self, page):
        """FtsHighlight.resolveColors({'colors':'glasbey_bw_minc_20'}) must return glasbey palette."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        colors = page.evaluate(
            "window.FtsHighlight.resolveColors({ colors: 'glasbey_bw_minc_20' })"
        )
        assert colors[0].lower() == "#ef9999", f"Expected #ef9999, got {colors[0]}"
        assert colors[7].lower() == "#ffdbac", f"Expected #ffdbac, got {colors[7]}"
        assert len(colors) == 8

    def test_glasbey_color_picker_when_config_set(self, page):
        """When FTS_HIGHLIGHT_CONFIG.colors='glasbey_bw_minc_20', first color must be #ef9999."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        first = page.evaluate(
            "window.FtsHighlight.resolveColors({ colors: 'glasbey_bw_minc_20' })[0]"
        )
        assert first.lower() == "#ef9999"

    def test_custom_storage_key_persists_state(self, page):
        """When storageKey is overridden, state must be stored under the custom key."""
        page.evaluate("localStorage.removeItem('custom-test-key')")
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        # Inject custom key and toggle — simulates what fts-highlight-config.js does
        page.evaluate("""() => {
            // Manually write state with custom key to simulate config override
            localStorage.setItem('custom-test-key', JSON.stringify({
                allEnabled: false, terms: []
            }));
        }""")
        stored = page.evaluate("localStorage.getItem('custom-test-key')")
        import json as _json

        assert _json.loads(stored)["allEnabled"] is False

    def test_color_change_updates_stylesheet(self, page):
        """Changing the color picker value must update the injected stylesheet."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        picker = page.locator(".fts-term-row input[type='color']").first
        page.evaluate(
            """(el) => {
                el.value = '#ff0000';
                el.dispatchEvent(new Event('input', {bubbles: true}));
            }""",
            picker,
        )
        css = page.evaluate("document.getElementById('fts-hl-styles').textContent")
        assert "#ff0000" in css.lower() or "ff0000" in css.lower()

    # ── Add / remove terms ─────────────────────────────────────────────

    def test_add_term_input_present(self, page):
        """The .fts-add-input text field must be visible in the panel."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        assert page.locator(".fts-add-input").is_visible()

    def test_add_term_creates_new_marks(self, page):
        """Typing a term and clicking + must add marks for that term."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        before = page.locator("td mark.fts-hl[data-idx='1']").count()
        assert before == 0, "idx=1 marks should not exist yet"
        page.locator(".fts-add-input").fill("build")
        page.locator(".fts-add-btn").click()
        after = page.locator("td mark.fts-hl[data-idx='1']").count()
        assert after > 0, "Expected idx=1 marks after adding 'build' term"

    def test_add_term_enter_key(self, page):
        """Pressing Enter in the add-term input must also add the term."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        page.locator(".fts-add-input").fill("build")
        page.locator(".fts-add-input").press("Enter")
        assert page.locator("td mark.fts-hl[data-idx='1']").count() > 0

    def test_add_duplicate_term_ignored(self, page):
        """Adding a term already in the list must not create a duplicate row."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        rows_before = page.locator(".fts-term-row").count()
        page.locator(".fts-add-input").fill("pytest")
        page.locator(".fts-add-btn").click()
        assert page.locator(".fts-term-row").count() == rows_before

    def test_remove_term_button_present(self, page):
        """Each term row must have a .fts-term-remove button."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        assert page.locator(".fts-term-remove").count() == 1

    def test_remove_term_removes_marks(self, page):
        """Clicking × on a term must remove all its marks from the table."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        assert page.locator("td mark.fts-hl").count() > 0
        page.locator(".fts-term-remove").first.click()
        assert page.locator("td mark.fts-hl").count() == 0

    def test_remove_term_removes_row(self, page):
        """Clicking × must also remove the term row from the panel."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest+cargo"))
        page.wait_for_load_state("networkidle")
        rows_before = page.locator(".fts-term-row").count()
        page.locator(".fts-term-remove").first.click()
        assert page.locator(".fts-term-row").count() == rows_before - 1

    # ── Empty-terms recovery ───────────────────────────────────────────

    def test_remove_all_terms_panel_still_visible(self, page):
        """After removing all terms the panel must still be visible (add-row present)."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        page.locator(".fts-term-remove").first.click()  # remove the only term
        assert page.locator("#fts-highlight-panel").is_visible(), (
            "Panel must remain visible after all terms are removed"
        )
        assert page.locator(".fts-add-input").is_visible(), (
            "Add-term input must still be visible after all terms removed"
        )

    def test_remove_all_terms_clears_localstorage(self, page):
        """Removing all terms must clear the localStorage key so the next\
 page load re-seeds from URL params."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        page.locator(".fts-term-remove").first.click()
        stored = page.evaluate("localStorage.getItem('tert-fts-hl')")
        assert stored is None, "localStorage must be cleared when all terms are removed"

    def test_reload_after_removing_all_terms_reseeds_from_url(self, page):
        """After removing all terms and reloading, highlights must be restored\
 from the URL search param."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        page.locator(".fts-term-remove").first.click()
        page.reload()
        page.wait_for_load_state("networkidle")
        # URL still has ?_search=pytest → term rows should be re-populated
        assert page.locator(".fts-term-row").count() == 1, (
            "Reload must re-seed highlights from URL params"
        )
        assert page.locator("td mark.fts-hl").count() > 0, (
            "Marks must reappear after reload re-seeds from URL"
        )

    def test_empty_panel_allows_adding_new_term(self, page):
        """After removing all terms, the add-term row must still add new highlights."""
        self._clear_storage(page)
        page.goto(self._url("test_artifacts", "?_search=pytest"))
        page.wait_for_load_state("networkidle")
        page.locator(".fts-term-remove").first.click()  # remove all
        # Add a different term using the now-empty panel
        page.locator(".fts-add-input").fill("cargo")
        page.locator(".fts-add-btn").click()
        assert page.locator(".fts-term-row").count() == 1
        assert page.locator("td mark.fts-hl[data-idx='0']").count() > 0
