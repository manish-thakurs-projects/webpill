import brands from '@webpill/shared/brands.json' with { type: 'json' };
import {
  DEFAULT_RISK_THRESHOLDS,
  type PageSignals,
  type DomainSignals,
  type ProviderResult,
  type RiskAssessment,
  type RiskThresholds,
} from '@webpill/shared';

const suspiciousTlds = new Set([
  'zip', 'mov', 'click', 'top', 'xyz', 'work', 'gq', 'tk', 'country', 'stream',
]);
const suspiciousWords = /\b(login|signin|verify|secure|account|wallet|update|confirm|support|payment)\b/i;

export interface RiskInput {
  url: string;
  hostname?: string;
  pageSignals?: Partial<PageSignals>;
  providerResults?: ProviderResult[];
  domainSignals?: DomainSignals;
  thresholds?: RiskThresholds;
}

export interface PageRiskAnalyzer {
  analyze(input: RiskInput): Promise<RiskAssessment>;
}

export class DeterministicPageRiskAnalyzer implements PageRiskAnalyzer {
  async analyze(input: RiskInput) {
    return analyzeRisk(input);
  }
}

export function detectBrandMismatch(hostname: string, visibleText: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const text = visibleText.toLowerCase();
  return Object.entries(brands).some(([brand, allowedDomains]) => {
    const mentioned = new RegExp(`\\b${brand}\\b`).test(text);
    const owned = (allowedDomains as string[]).some(
      (domain) => host === domain || host.endsWith(`.${domain}`),
    );
    return mentioned && !owned;
  });
}

export function analyzeUrl(urlValue: string): {
  hostname: string;
  score: number;
  signals: Record<string, boolean | number>;
  reasons: Array<{ type: string; severity: 'positive' | 'info' | 'warning' | 'high'; message: string }>;
} {
  let url: URL;
  try {
    url = new URL(urlValue);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Unsupported protocol');
  } catch {
    throw new Error('A valid HTTP or HTTPS URL is required.');
  }

  const hostname = url.hostname.toLowerCase();
  const labels = hostname.split('.');
  const tld = labels.at(-1) ?? '';
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const urlEncoded = /%[0-9a-f]{2}/i.test(urlValue);
  const signals = {
    https: url.protocol === 'https:',
    longUrl: urlValue.length >= 100,
    subdomainCount: Math.max(0, labels.length - 2),
    ipAddress: ipv4 || hostname.includes(':'),
    punycode: hostname.split('.').some((label) => label.startsWith('xn--')),
    suspiciousTld: suspiciousTlds.has(tld),
    excessiveHyphens: (hostname.match(/-/g) ?? []).length >= 4,
    suspiciousKeyword: suspiciousWords.test(`${url.pathname} ${url.search}`),
    encodedCharacters: urlEncoded,
    unusualPort: Boolean(url.port && !['80', '443'].includes(url.port)),
    embeddedCredentials: Boolean(url.username || url.password),
  };

  let score = 0;
  const reasons: Array<{ type: string; severity: 'positive' | 'info' | 'warning' | 'high'; message: string }> = [];
  const add = (condition: boolean, points: number, type: string, message: string, severity: 'positive' | 'info' | 'warning' | 'high' = 'warning') => {
    if (!condition) return;
    score += points;
    reasons.push({ type, severity, message });
  };

  add(!signals.https, 15, 'https', 'This page is using an unencrypted HTTP connection.');
  add(signals.longUrl, 7, 'url_length', 'The URL is unusually long.');
  add(signals.subdomainCount > 3, 7, 'subdomains', 'The hostname contains an unusually large number of subdomains.');
  add(signals.ipAddress, 20, 'ip_address', 'The address uses an IP address instead of a regular domain name.');
  add(signals.punycode, 18, 'punycode', 'The hostname uses encoded international characters that can resemble other domains.');
  add(signals.suspiciousTld, 8, 'tld', 'This top-level domain is more frequently associated with abuse.');
  add(signals.excessiveHyphens, 5, 'hyphens', 'The hostname contains an unusually high number of hyphens.');
  add(signals.suspiciousKeyword, 4, 'url_keyword', 'The URL contains a security-sensitive keyword.');
  add(signals.encodedCharacters, 3, 'encoded_url', 'The URL contains encoded characters.');
  add(signals.unusualPort, 7, 'port', 'The website uses a non-standard network port.');
  add(signals.embeddedCredentials, 25, 'embedded_credentials', 'The URL includes embedded username or password information.', 'high');
  if (signals.https) reasons.push({ type: 'https', severity: 'positive', message: 'HTTPS is enabled for this connection.' });
  if (reasons.length === 0) reasons.push({ type: 'url', severity: 'positive', message: 'No notable URL warning signals were detected.' });
  return { hostname, score: Math.min(score, 100), signals, reasons };
}

export function calculateRiskLevel(score: number, thresholds: RiskThresholds = DEFAULT_RISK_THRESHOLDS) {
  if (score >= thresholds.high) return 'high' as const;
  if (score >= thresholds.suspicious) return 'suspicious' as const;
  if (score >= thresholds.caution) return 'caution' as const;
  return 'low' as const;
}

export function analyzeRisk(input: RiskInput): RiskAssessment {
  const urlAnalysis = analyzeUrl(input.url);
  const page = {
    hasPasswordForm: false,
    loginFormCount: 0,
    suspiciousPhraseCount: 0,
    externalDomains: [],
    redirectsObserved: 0,
    brandMismatch: false,
    ...input.pageSignals,
  };
  let score = urlAnalysis.score;
  const reasons = [...urlAnalysis.reasons];
  const addPageSignal = (condition: boolean, points: number, type: string, message: string) => {
    if (!condition) return;
    score += points;
    reasons.push({ type, severity: 'warning' as const, message });
  };
  addPageSignal(page.hasPasswordForm && !urlAnalysis.signals.https, 8, 'password_form', 'A password form is present on a page without HTTPS.');
  addPageSignal(page.hasPasswordForm && (page.brandMismatch || page.suspiciousPhraseCount > 0), 7, 'login_context', 'A password form appears alongside other suspicious page signals.');
  addPageSignal(page.suspiciousPhraseCount >= 2, 10, 'urgent_language', 'The page contains multiple urgent account or payment phrases.');
  addPageSignal(page.brandMismatch, 22, 'brand_mismatch', 'Page content mentions a brand not associated with this domain.');
  addPageSignal(page.redirectsObserved > 3, 7, 'redirects', 'Several redirects were observed while loading this page.');
  const domain = input.domainSignals;
  if (domain?.domainAgeDays !== null && domain?.domainAgeDays !== undefined && domain.domainAgeDays < 30) {
    score += domain.domainAgeDays < 7 ? 18 : 12;
    reasons.push({ type: 'domain_age', severity: 'warning', message: 'The domain has a recent public registration date.' });
  }
  if (domain?.dnsResolved === false) {
    score += 8;
    reasons.push({ type: 'dns', severity: 'warning', message: 'Public DNS did not return an address for this domain.' });
  }
  if (domain?.nameserverCount !== null && domain?.nameserverCount !== undefined && domain.nameserverCount < 2) {
    score += 3;
    reasons.push({ type: 'nameservers', severity: 'info', message: 'The domain has fewer than two public nameserver records.' });
  }
  if (domain?.certificateValid === false) {
    score += 18;
    reasons.push({ type: 'certificate', severity: 'high', message: 'The public TLS certificate could not be validated.' });
  } else if (domain?.certificateValid === true) {
    reasons.push({ type: 'certificate', severity: 'positive', message: 'The public TLS certificate validated successfully.' });
  }

  const providers = input.providerResults ?? [];
  const listed = providers.filter((provider) => provider.available && provider.found === true);
  if (listed.length) {
    score += Math.min(100, listed.length * 75);
    reasons.push({ type: 'threat_intelligence', severity: 'high', message: 'A configured threat intelligence provider reported a match.' });
  } else if (providers.some((provider) => provider.available && provider.found === false)) {
    reasons.push({ type: 'threat_intelligence', severity: 'positive', message: 'No known threat was found by the available reputation providers.' });
  } else {
    reasons.push({ type: 'threat_intelligence', severity: 'info', message: 'Reputation services were unavailable; this result uses local signals only.' });
  }

  score = Math.min(100, score);
  const thresholds = input.thresholds ?? DEFAULT_RISK_THRESHOLDS;
  const availableCount = providers.filter((provider) => provider.available).length;
  const metadataCount = domain ? [domain.rdapAvailable, domain.dnsAvailable, domain.certificateAvailable].filter(Boolean).length : 0;
  const confidence = Math.min(0.95, Math.round((0.38 + (availableCount ? 0.16 + availableCount * 0.08 : 0) + metadataCount * 0.04 + (page.brandMismatch ? 0.08 : 0)) * 100) / 100);
  const signals = {
    ...urlAnalysis.signals,
    hasPasswordForm: page.hasPasswordForm,
    loginFormCount: page.loginFormCount,
    suspiciousPhraseCount: page.suspiciousPhraseCount,
    externalDomainCount: page.externalDomains.length,
    redirectsObserved: page.redirectsObserved,
    brandMismatch: page.brandMismatch,
    availableReputationProviders: availableCount,
    domainAgeDays: domain?.domainAgeDays ?? null,
    dnsResolved: domain?.dnsResolved ?? null,
    nameserverCount: domain?.nameserverCount ?? null,
    certificateValid: domain?.certificateValid ?? null,
    rdapAvailable: domain?.rdapAvailable ?? false,
    dnsAvailable: domain?.dnsAvailable ?? false,
    certificateAvailable: domain?.certificateAvailable ?? false,
  };

  return {
    score,
    level: calculateRiskLevel(score, thresholds),
    confidence,
    reasons: reasons.slice(0, 12),
    signals,
  };
}
