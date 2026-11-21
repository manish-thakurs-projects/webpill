import { analyzeRisk, detectBrandMismatch } from '@webpill/risk-engine';
import { analysisResponseSchema, type AnalysisResponse, type DomainSignals, type ExtensionMessage, type PageSignals } from '@webpill/shared';
import { browser } from 'wxt/browser';
import { CACHE_PREFIX, parseSettings, SETTINGS_KEY, type WebpillSettings } from './settings';

export type ContentMessage = ExtensionMessage;

export async function getSettings(): Promise<WebpillSettings> {
  const stored = await browser.storage.local.get(SETTINGS_KEY);
  return parseSettings(stored[SETTINGS_KEY]);
}

export async function localAssessment(
  url: string,
  pageSignals: PageSignals,
  providers: AnalysisResponse['providerResults'] = [],
  domainSignals?: DomainSignals,
) {
  const risk = analyzeRisk({ url, pageSignals, providerResults: providers, domainSignals });
  return analysisResponseSchema.parse({
    domain: new URL(url).hostname,
    ...risk,
    providerResults: providers,
    checkedAt: new Date().toISOString(),
    limitedAnalysis: !providers.length || !providers.every((provider) => provider.available),
  });
}

async function makeCacheKey(url: string, pageSignals: PageSignals) {
  const normalized = new URL(url);
  normalized.username = '';
  normalized.password = '';
  normalized.hash = '';
  const bytes = new TextEncoder().encode(`${normalized.toString()}\n${JSON.stringify(pageSignals)}`);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function requestAnalysis(
  url: string,
  pageSignals: PageSignals,
  force = false,
): Promise<AnalysisResponse> {
  const local = await localAssessment(url, pageSignals);
  const settings = await getSettings();
  if (!settings.analyzeAutomatically && !force) return local;

  const key = `${CACHE_PREFIX}${await makeCacheKey(url, pageSignals)}`;
  const now = Date.now();
  if (!force) {
    const cached = await browser.storage.local.get(key);
    const entry = cached[key] as { result?: unknown; checkedAt?: unknown } | undefined;
    if (
      entry?.result
      && typeof entry.checkedAt === 'number'
      && Number.isFinite(entry.checkedAt)
      && entry.checkedAt <= now
      && now - entry.checkedAt < settings.cacheDurationHours * 3_600_000
    ) {
      const parsed = analysisResponseSchema.safeParse(entry.result);
      if (parsed.success) return parsed.data;
      try {
        await browser.storage.local.remove(key);
      } catch (error) {
        console.warn('[webpill] An invalid cached result could not be removed.', error);
      }
    }
  }

  const endpoint = new URL('/api/analyze', settings.apiBaseUrl).toString();
  let remote: AnalysisResponse;
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: new URL(url).origin,
        pageSignals: {
          hasPasswordForm: pageSignals.hasPasswordForm,
          loginFormCount: pageSignals.loginFormCount,
          suspiciousPhraseCount: pageSignals.suspiciousPhraseCount,
          externalDomains: [],
          redirectsObserved: pageSignals.redirectsObserved,
          brandMismatch: pageSignals.brandMismatch,
        },
      }),
      signal: AbortSignal.timeout(8_000),
    });
    if (!response.ok) throw new Error(`Analysis service returned HTTP ${response.status}.`);
    remote = analysisResponseSchema.parse(await response.json());
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'The analysis service is unavailable.';
    console.warn(`[webpill] Remote analysis unavailable: ${detail}`);
    return analysisResponseSchema.parse({
      ...local,
      limitedAnalysis: true,
      reasons: [
        ...local.reasons,
        { type: 'limited_analysis', severity: 'info', message: 'Some reputation services are unavailable. Local checks completed.' },
      ],
    });
  }

  const signal = remote.signals;
  const domainSignals: DomainSignals = {
    domainAgeDays: typeof signal.domainAgeDays === 'number' ? signal.domainAgeDays : null,
    dnsResolved: typeof signal.dnsResolved === 'boolean' ? signal.dnsResolved : null,
    nameserverCount: typeof signal.nameserverCount === 'number' ? signal.nameserverCount : null,
    certificateValid: typeof signal.certificateValid === 'boolean' ? signal.certificateValid : null,
    rdapAvailable: signal.rdapAvailable === true,
    dnsAvailable: signal.dnsAvailable === true,
    certificateAvailable: signal.certificateAvailable === true,
  };
  const combined = await localAssessment(url, pageSignals, remote.providerResults, domainSignals);
  const result = analysisResponseSchema.parse({ ...combined, limitedAnalysis: remote.limitedAnalysis });
  try {
    await browser.storage.local.set({ [key]: { result, checkedAt: now } });
  } catch (error) {
    console.warn('[webpill] Analysis succeeded, but the local cache could not be updated.', error);
  }
  return result;
}

export function collectPageSignals(hostname: string, enabled: boolean): PageSignals {
  const initial: PageSignals = {
    hasPasswordForm: false,
    loginFormCount: 0,
    suspiciousPhraseCount: 0,
    externalDomains: [],
    redirectsObserved: 0,
    brandMismatch: false,
  };
  if (!enabled) return initial;

  const forms = [...document.forms].slice(0, 40);
  initial.hasPasswordForm = forms.some((form) => Boolean(form.querySelector('input[type="password"]')));
  initial.loginFormCount = forms.filter((form) => Boolean(form.querySelector('input[type="password"]'))).length;
  let visibleText = '';
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let visited = 0;
  while (walker.nextNode() && visited < 300 && visibleText.length < 8_000) {
    const node = walker.currentNode;
    const parent = node.parentElement;
    if (parent && !parent.closest('script,style,noscript,svg,[hidden]')) {
      visibleText += ` ${node.textContent ?? ''}`.slice(0, 8_000 - visibleText.length).toLowerCase();
    }
    visited += 1;
  }
  const phrases = ['verify your account', 'your account will be suspended', 'urgent payment', 'confirm identity', 'security warning'];
  initial.suspiciousPhraseCount = phrases.filter((phrase) => visibleText.includes(phrase)).length;
  initial.externalDomains = [...new Set(
    [...document.querySelectorAll('a[href], iframe[src]')]
      .slice(0, 100)
      .map((element) => {
        const value = element instanceof HTMLAnchorElement ? element.href : (element as HTMLIFrameElement).src;
        try {
          return new URL(value).hostname.toLowerCase();
        } catch {
          return '';
        }
      })
      .filter((domain) => domain && domain !== hostname),
  )].slice(0, 50);
  initial.brandMismatch = detectBrandMismatch(hostname, visibleText);
  return initial;
}
