// The admin token, kept for this browser tab only: it goes when the tab closes.
// Storage can be unavailable (private windows, blocked site data), so every access is guarded.

const KEY = "scp-admin-token";

export function readAdminToken(): string {
  try {
    return sessionStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
}

export function storeAdminToken(token: string): void {
  try {
    sessionStorage.setItem(KEY, token);
  } catch {
    // Not kept: the token is asked for again next time.
  }
}

export function forgetAdminToken(): void {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    // Nothing stored.
  }
}
