import {
  applyDocumentTheme,
  getDocumentTheme,
  type DocumentTheme,
} from "@openai/apps-sdk-ui/theme";
import { Moon, Sun } from "lucide-react";
import { useState } from "react";

const THEME_STORAGE_KEY = "forge-acquire-theme";

function storedTheme(): DocumentTheme | null {
  try {
    const value = window.localStorage.getItem(THEME_STORAGE_KEY);
    return value === "light" || value === "dark" ? value : null;
  } catch {
    return null;
  }
}

export function initializeDocumentTheme(): DocumentTheme {
  const theme = storedTheme()
    ?? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  applyDocumentTheme(theme);
  return theme;
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<DocumentTheme>(() => getDocumentTheme());
  const nextTheme: DocumentTheme = theme === "light" ? "dark" : "light";

  const toggleTheme = () => {
    applyDocumentTheme(nextTheme);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
    } catch {
      // Theme persistence is a convenience; the control remains usable if storage is unavailable.
    }
    setTheme(nextTheme);
  };

  return (
    <button
      className="theme-toggle icon-action"
      type="button"
      aria-label={`Switch to ${nextTheme} theme`}
      data-tooltip={`Switch to ${nextTheme} theme`}
      onClick={toggleTheme}
    >
      {theme === "light" ? <Moon aria-hidden="true" /> : <Sun aria-hidden="true" />}
      <span className="visually-hidden">Switch to {nextTheme} theme</span>
    </button>
  );
}
