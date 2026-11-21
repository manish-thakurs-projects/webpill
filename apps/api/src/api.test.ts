import { afterEach, describe, expect, it } from 'vitest';
import type { ThreatProvider } from '@webpill/shared';
import { app } from './app.js';
import { checkProviders } from './providers/index.js';
import { analyzeWebsite } from './services/analysis.js';
import { isPublicAddress } from './services/domainIntelligence.js';

describe('API analysis', () => {
  let server: ReturnType<typeof app.listen> | undefined;

  afterEach(async () => {
    if (!server) return;
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
  });

  it('returns a clear validation error for an invalid request', async () => {
    server = app.listen(0);
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Test server failed to bind.');
    const response = await fetch(`http://127.0.0.1:${address.port}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'javascript:alert(1)' }),
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: 'Invalid analysis request.' });
  });

  it('continues with unavailable provider results when all checks fail', async () => {
    const failingProvider: ThreatProvider = {
      name: 'test-provider',
      async checkUrl() { throw new Error('offline'); },
    };
    const results = await checkProviders('https://example.org', 'example.org', [failingProvider]);
    expect(results).toEqual([{
      provider: 'test-provider',
      available: false,
      found: null,
      detail: 'offline',
    }]);
  });

  it('caches analyses without making a second provider call', async () => {
    const unique = `https://cache-${Date.now()}.example.org`;
    let providerCalls = 0;
    const providerChecker = async () => {
      providerCalls += 1;
      return [{ provider: 'test', available: true, found: false }];
    };
    const domainInspector = async () => ({
      domainAgeDays: 400,
      dnsResolved: true,
      nameserverCount: 2,
      certificateValid: true,
      rdapAvailable: true,
      dnsAvailable: true,
      certificateAvailable: true,
    });
    const first = await analyzeWebsite({ url: unique }, providerChecker, undefined, domainInspector);
    const second = await analyzeWebsite({ url: unique }, providerChecker, undefined, domainInspector);
    expect(first).toEqual(second);
    expect(providerCalls).toBe(1);
    expect(first.domain).toBe(new URL(unique).hostname);
    expect(first.disclaimer).toBe('Risk assessment is informational and cannot guarantee that a website is safe.');
  });

  it('permits only public IP addresses for certificate probes', () => {
    expect(isPublicAddress('8.8.8.8')).toBe(true);
    expect(isPublicAddress('127.0.0.1')).toBe(false);
    expect(isPublicAddress('169.254.169.254')).toBe(false);
    expect(isPublicAddress('::1')).toBe(false);
  });
});
