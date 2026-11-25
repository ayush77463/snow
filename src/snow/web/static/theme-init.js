/**
 * SNOW V5 Early Theme Initializer
 * Loaded synchronously in <head> under strict CSP (script-src 'self') to prevent dark/light flash.
 */
(function () {
    try {
        var theme = localStorage.getItem("snow_theme") || "system";
        var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
        var isDark = theme === "dark" || (theme === "system" && prefersDark);
        document.documentElement.className = isDark ? "theme-dark" : "theme-light";
    } catch (e) {
        document.documentElement.className = "theme-dark";
    }
})();
