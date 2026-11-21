import type { ThreatProvider } from './types.js';
import { fetchWithTimeout, providerUnavailable } from './types.js';

export class UrlhausProvider implements ThreatProvider {
  readonly name = 'URLhaus';
  constructor(private readonly apiKey = process.env.URLHAUS_API_KEY) {}

  async checkUrl(_url: string, domain: string) {
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'webpill/1.0 (website risk assessment)',
    };
    if (this.apiKey) headers['Auth-Key'] = this.apiKey;
    const response = await fetchWithTimeout('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers,
      body: new URLSearchParams({ host: domain }),
    });
    if (response.status === 401 || response.status === 403) {
      return providerUnavailable(this.name, 'The service requires an API key or access is restricted.');
    }
    if (!response.ok) throw new Error(`URLhaus returned HTTP ${response.status}.`);
    const data = await response.json() as { query_status?: string; urls?: unknown[] };
    if (data.query_status === 'no_results') return { provider: this.name, available: true, found: false };
    return {
      provider: this.name,
      available: true,
      found: Array.isArray(data.urls) && data.urls.length > 0,
      detail: `${data.urls?.length ?? 0} URL record(s) reported for this host.`,
    };
  }
}
