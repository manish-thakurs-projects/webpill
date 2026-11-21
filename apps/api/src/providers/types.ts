import type { ThreatProvider } from '@webpill/shared';

export type { ThreatProvider };

export function providerUnavailable(name: string, detail: string) {
  return { provider: name, available: false, found: null, detail };
}

export async function fetchWithTimeout(url: string, init: RequestInit = {}) {
  return fetch(url, { ...init, signal: AbortSignal.timeout(5_000) });
}
