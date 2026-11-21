import { describe, expect, it } from 'vitest';
import { analyzeRisk, analyzeUrl, calculateRiskLevel, detectBrandMismatch, DeterministicPageRiskAnalyzer } from './index';

describe('risk engine', () => {
  it('applies configurable level thresholds', () => {
    expect(calculateRiskLevel(24)).toBe('low');
    expect(calculateRiskLevel(25)).toBe('caution');
    expect(calculateRiskLevel(50)).toBe('suspicious');
    expect(calculateRiskLevel(75)).toBe('high');
    expect(calculateRiskLevel(40, { caution: 10, suspicious: 35, high: 90 })).toBe('suspicious');
  });

  it('detects URL signals without making a single signal conclusive', () => {
    const result = analyzeUrl('http://test.example.com/account/login');
    expect(result.hostname).toBe('test.example.com');
    expect(result.score).toBeGreaterThan(0);
    expect(result.score).toBeLessThan(50);
    expect(analyzeUrl('https://example.com').score).toBe(0);
  });

  it('detects punycode and IP-based URLs', () => {
    expect(analyzeUrl('https://xn--pple-43d.com').signals.punycode).toBe(true);
    expect(analyzeUrl('http://192.0.2.10').signals.ipAddress).toBe(true);
  });

  it('flags a brand mention on an unrelated domain as a signal', () => {
    expect(detectBrandMismatch('paypal-security.example.xyz', 'PayPal login')).toBe(true);
    expect(detectBrandMismatch('accounts.google.com', 'Google sign in')).toBe(false);
  });

  it('combines page and reputation signals and clamps scores', () => {
    const assessment = analyzeRisk({
      url: 'http://192.0.2.10/verify',
      pageSignals: { brandMismatch: true, suspiciousPhraseCount: 4 },
      providerResults: [{ provider: 'test', available: true, found: true }],
    });
    expect(assessment.level).toBe('high');
    expect(assessment.score).toBe(100);
    expect(assessment.reasons.some((reason) => reason.type === 'brand_mismatch')).toBe(true);
  });

  it('adds domain age and certificate signals without treating unknown metadata as negative', () => {
    const recent = analyzeRisk({
      url: 'https://example.com',
      domainSignals: {
        domainAgeDays: 4,
        dnsResolved: true,
        nameserverCount: 2,
        certificateValid: false,
        rdapAvailable: true,
        dnsAvailable: true,
        certificateAvailable: true,
      },
    });
    const unknown = analyzeRisk({
      url: 'https://example.com',
      domainSignals: {
        domainAgeDays: null,
        dnsResolved: null,
        nameserverCount: null,
        certificateValid: null,
        rdapAvailable: false,
        dnsAvailable: false,
        certificateAvailable: false,
      },
    });
    expect(recent.score).toBe(36);
    expect(unknown.score).toBe(0);
  });

  it('provides an async analyzer contract for future local models', async () => {
    const analyzer = new DeterministicPageRiskAnalyzer();
    await expect(analyzer.analyze({ url: 'https://example.org' })).resolves.toMatchObject({ score: 0, level: 'low' });
  });
});
