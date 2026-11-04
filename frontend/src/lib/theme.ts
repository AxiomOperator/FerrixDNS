export type Theme = "system" | "light" | "dark";

const STORAGE_KEY = "fx-theme";

/** Storage can be unavailable, in which case the theme just isn't remembered. */
export function storedTheme(): Theme {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return value === "light" || value === "dark" ? value : "system";
  } catch {
    return "system";
  }
}

export function setTheme(theme: Theme) {
  try {
    if (theme === "system") localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Still applies for this page view.
  }
  applyTheme(theme);
}

function applyTheme(theme: Theme) {
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
}

export function applyStoredTheme() {
  applyTheme(storedTheme());
}
