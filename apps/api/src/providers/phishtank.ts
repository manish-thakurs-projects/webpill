import type { ThreatProvider } from './types.js';
import { fetchWithTimeout, providerUnavailable } from './types.js';

export class PhishTankProvider implements ThreatProvider {
  readonly name = 'PhishTank';
  constructor(private readonly apiKey = process.env.PHISHTANK_API_KEY) {}

  async checkUrl(url: string) {
    if (!this.apiKey) return providerUnavailable(this.name, 'API key is not configured.');
    const response = await fetchWithTimeout('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'webpill/1.0' },
      body: new URLSearchParams({ url, format: 'json', app_key: this.apiKey }),
    });
    if (!response.ok) throw new Error(`PhishTank returned HTTP ${response.status}.`);
    const data = await response.json() as { results?: { in_database?: boolean; verified?: boolean } };
    return {
      provider: this.name,
      available: true,
      found: Boolean(data.results?.in_database && data.results.verified),
    };
  }
}
