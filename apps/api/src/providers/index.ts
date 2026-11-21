import type { ProviderResult, ThreatProvider } from '@webpill/shared';
import { GoogleSafeBrowsingProvider } from './googleSafeBrowsing.js';
import { PhishTankProvider } from './phishtank.js';
import { UrlhausProvider } from './urlhaus.js';
import { VirusTotalProvider } from './virusTotal.js';

const providers: ThreatProvider[] = [
  new GoogleSafeBrowsingProvider(),
  new VirusTotalProvider(),
  new UrlhausProvider(),
  new PhishTankProvider(),
];

export async function checkProviders(
  url: string,
  domain: string,
  configuredProviders: ThreatProvider[] = providers,
): Promise<ProviderResult[]> {
  return Promise.all(configuredProviders.map(async (provider) => {
    try {
      return await provider.checkUrl(url, domain);
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'Provider request failed.';
      console.warn(JSON.stringify({ level: 'warn', event: 'provider_failure', provider: provider.name, detail }));
      return { provider: provider.name, available: false, found: null, detail };
    }
  }));
}
