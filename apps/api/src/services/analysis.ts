import { createHash } from 'node:crypto';
import {
  analyzeRequestSchema,
  analysisResponseSchema,
  DEFAULT_RISK_THRESHOLDS,
  type AnalysisResponse,
  type RiskThresholds,
} from '@webpill/shared';
import { analyzeRisk, analyzeUrl } from '@webpill/risk-engine';
import { DomainAnalysisModel } from '../models/DomainAnalysis.js';
import { checkProviders } from '../providers/index.js';
import type { CachedDomainAnalysis } from '../models/DomainAnalysis.js';
import { inspectDomain } from './domainIntelligence.js';
import type { ThreatProvider } from '@webpill/shared';

const memoryCache = new Map<string, { result: AnalysisResponse; expiresAt: number }>();
const cacheTtlHours = Number(process.env.ANALYSIS_CACHE_TTL_HOURS ?? 24);
if (!Number.isFinite(cacheTtlHours) || cacheTtlHours <= 0 || cacheTtlHours > 720) {
  throw new Error('ANALYSIS_CACHE_TTL_HOURS must be a number greater than 0 and no more than 720.');
}
const cacheTtlMs = cacheTtlHours * 60 * 60 * 1000;
const thresholds: RiskThresholds = {
  caution: Number(process.env.RISK_THRESHOLD_CAUTION ?? DEFAULT_RISK_THRESHOLDS.caution),
  suspicious: Number(process.env.RISK_THRESHOLD_SUSPICIOUS ?? DEFAULT_RISK_THRESHOLDS.suspicious),
  high: Number(process.env.RISK_THRESHOLD_HIGH ?? DEFAULT_RISK_THRESHOLDS.high),
};
if (
  Object.values(thresholds).some((value) => !Number.isInteger(value) || value < 1 || value > 100)
  || thresholds.caution >= thresholds.suspicious
  || thresholds.suspicious >= thresholds.high
) {
  throw new Error('Risk thresholds must be increasing integers between 1 and 100.');
}

function cacheKey(url: string, pageSignals: object) {
  return createHash('sha256').update(JSON.stringify({ url, pageSignals })).digest('hex');
}

export async function analyzeWebsite(
  body: unknown,
  providerChecker: (url: string, domain: string, providers?: ThreatProvider[]) => Promise<AnalysisResponse['providerResults']> = checkProviders,
  testProviders?: ThreatProvider[],
  domainInspector: typeof inspectDomain = inspectDomain,
): Promise<AnalysisResponse> {
  const request = analyzeRequestSchema.parse(body);
  const { hostname } = analyzeUrl(request.url);
  const key = cacheKey(request.url, request.pageSignals);
  const now = Date.now();
  const cached = memoryCache.get(key);
  if (cached && cached.expiresAt > now) return cached.result;
  if (cached) memoryCache.delete(key);

  if (DomainAnalysisModel.db.readyState === 1) {
    try {
      const stored = await DomainAnalysisModel.findOne({ cacheKey: key, expiresAt: { $gt: new Date(now) } }).lean<CachedDomainAnalysis>();
      if (stored) {
        const result = analysisResponseSchema.parse(stored.result);
        memoryCache.set(key, { result, expiresAt: stored.expiresAt.getTime() });
        return result;
      }
    } catch (error) {
      console.warn(JSON.stringify({
        level: 'warn',
        event: 'analysis_cache_read_failed',
        detail: error instanceof Error ? error.message : 'Unknown database error',
        fallback: 'in-memory cache',
      }));
    }
  }

  const parsedUrl = new URL(request.url);
  const [providerResults, domainSignals] = await Promise.all([
    providerChecker(request.url, hostname, testProviders),
    domainInspector(hostname, parsedUrl.protocol),
  ]);
  const assessment = analyzeRisk({
    url: request.url,
    hostname,
    pageSignals: request.pageSignals,
    providerResults,
    domainSignals,
    thresholds,
  });
  const result = analysisResponseSchema.parse({
    domain: hostname,
    ...assessment,
    providerResults,
    checkedAt: new Date().toISOString(),
    limitedAnalysis: !providerResults.every((provider) => provider.available)
      || !domainSignals.rdapAvailable
      || !domainSignals.dnsAvailable
      || (parsedUrl.protocol === 'https:' && !domainSignals.certificateAvailable),
  });
  const expiresAt = new Date(now + cacheTtlMs);
  memoryCache.set(key, { result, expiresAt: expiresAt.getTime() });
  if (memoryCache.size > 500) {
    const first = memoryCache.keys().next().value as string | undefined;
    if (first) memoryCache.delete(first);
  }

  if (DomainAnalysisModel.db.readyState === 1) {
    try {
      await DomainAnalysisModel.updateOne(
        { cacheKey: key },
        { $set: { domain: hostname, result, createdAt: new Date(now), expiresAt } },
        { upsert: true },
      );
    } catch (error) {
      console.warn(JSON.stringify({
        level: 'warn',
        event: 'analysis_cache_write_failed',
        detail: error instanceof Error ? error.message : 'Unknown database error',
      }));
    }
  }
  return result;
}

export async function findLatestDomainAnalysis(domain: string) {
  const normalized = domain.toLowerCase().replace(/\.$/, '');
  if (DomainAnalysisModel.db.readyState === 1) {
    try {
      const stored = await DomainAnalysisModel.findOne({
        domain: normalized,
        expiresAt: { $gt: new Date() },
      }).sort({ createdAt: -1 }).lean<CachedDomainAnalysis>();
      if (stored) return analysisResponseSchema.parse(stored.result);
    } catch (error) {
      console.warn(JSON.stringify({
        level: 'warn',
        event: 'domain_cache_read_failed',
        detail: error instanceof Error ? error.message : 'Unknown database error',
        fallback: 'in-memory cache',
      }));
    }
  }
  for (const entry of memoryCache.values()) {
    if (entry.expiresAt > Date.now() && entry.result.domain === normalized) return entry.result;
  }
  return null;
}
