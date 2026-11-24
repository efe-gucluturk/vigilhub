// The operator's API key lives in sessionStorage only: gone when the tab closes,
// never persisted across tabs or restarts, and never put in cookies, the URL or the bundle.
const KEY = "vigilhub.apiKey";

export function loadKey(): string {
  try {
    return window.sessionStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
}

export function saveKey(value: string): void {
  try {
    window.sessionStorage.setItem(KEY, value);
  } catch {
    /* storage unavailable: the key then lives in memory for this page only */
  }
}

export function clearKey(): void {
  try {
    window.sessionStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}
