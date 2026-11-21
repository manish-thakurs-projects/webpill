import type { ThreatProvider } from './types.js';
import { fetchWithTimeout, providerUnavailable } from './types.js';

export class GoogleSafeBrowsingProvider implements ThreatProvider {
  readonly name = 'Google Safe Browsing';
  constructor(private readonly apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY) {}

  async checkUrl(url: string) {
    if (!this.apiKey) return providerUnavailable(this.name, 'API key is not configured.');
    const endpoint = new URL('https://safebrowsing.googleapis.com/v4/threatMatches:find');
    endpoint.searchParams.set('key', this.apiKey);
    const response = await fetchWithTimeout(endpoint.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'webpill', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }),
    });
    if (!response.ok) throw new Error(`Google Safe Browsing returned HTTP ${response.status}.`);
    const data = await response.json() as { matches?: unknown[] };
    return { provider: this.name, available: true, found: Boolean(data.matches?.length) };
  }
}
