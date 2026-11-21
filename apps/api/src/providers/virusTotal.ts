import type { ThreatProvider } from './types.js';
import { fetchWithTimeout, providerUnavailable } from './types.js';

export class VirusTotalProvider implements ThreatProvider {
  readonly name = 'VirusTotal';
  constructor(private readonly apiKey = process.env.VIRUSTOTAL_API_KEY) {}

  async checkUrl(_url: string, domain: string) {
    if (!this.apiKey) return providerUnavailable(this.name, 'API key is not configured.');
    const response = await fetchWithTimeout(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
      headers: { 'x-apikey': this.apiKey },
    });
    if (!response.ok) throw new Error(`VirusTotal returned HTTP ${response.status}.`);
    const data = await response.json() as {
      data?: { attributes?: { last_analysis_stats?: { malicious?: number; suspicious?: number } } };
    };
    const stats = data.data?.attributes?.last_analysis_stats;
    return {
      provider: this.name,
      available: true,
      found: Boolean((stats?.malicious ?? 0) > 0 || (stats?.suspicious ?? 0) > 0),
      detail: stats ? `Malicious: ${stats.malicious ?? 0}; suspicious: ${stats.suspicious ?? 0}.` : 'No analysis statistics were returned.',
    };
  }
}
