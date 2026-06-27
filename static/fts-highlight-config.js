/**
 * fts-highlight-config.js
 *
 * User-editable configuration for the FTS search-result highlight panel
 * (search-highlight.js).  This file is loaded before search-highlight.js so
 * changes here take effect on the next page load without touching the main
 * script.
 *
 * Restart Datasette after editing, or force-reload the browser (Ctrl+Shift+R).
 */
window.FTS_HIGHLIGHT_CONFIG = {

  /**
   * Color palette used when assigning colors to new highlight terms.
   *
   * Accepted values
   * ---------------
   *   'viridis'           — (default) Lightened viridis perceptually-uniform colors.
   *                         Each color is sampled from the viridis colormap at an
   *                         evenly-spaced interval and blended 70 % toward white so
   *                         it reads well as a text-highlight background.
   *
   *                         Viridis was designed by Nathaniel J. Smith and Stéfan van
   *                         der Walt (SciPy 2015, CC0 license):
   *                         https://bids.github.io/colormap/
   *
   *   'glasbey_bw_minc_20' — Lightened Glasbey bw_minc_20 categorical colors.
   *                          The first 32 colors from colorcet.glasbey_bw_minc_20 are
   *                          selected (ordered by maximum mutual distinctness) and
   *                          blended 60 % toward white.
   *
   *                          The original palette is designed so every color maintains
   *                          contrast against both black and white backgrounds
   *                          (minimum lightness contrast = 20 in CIECAM02).
   *
   *                          Sources:
   *                            colorcet: https://colorcet.holoviz.org/user_guide/Categorical.html
   *                            Glasbey et al. (2007), "Colour displays for categorical images",
   *                            Color Research & Application 32.4: 304-309.
   *                            https://strathprints.strath.ac.uk/30312/1/colorpaper_2006.pdf
   *
   *   'pastel'     — Legacy hand-picked pastels (yellow, cyan, green, peach, …).
   *                  Used as the default before viridis was added.
   *
   *   [...strings] — Custom array of CSS color strings, cycled through in order.
   *                  Example: ['#ffccaa', '#aaffcc', '#ccaaff']
   *
   *   null         — Same as 'viridis'.
   */
//   colors: 'viridis',
//   colors: 'pastel',
  colors: 'glasbey_bw_minc_20', // TODO: rename to glasbey_bw_minc_20_lightened

  /**
   * localStorage key used to persist the highlight panel state across page
   * loads and navigation.  Change this if you run multiple Datasette instances
   * on the same origin and want them to maintain independent state.
   */
  storageKey: 'tert-fts-hl',

};
