import { z } from 'zod';

export const pageSignalsSchema = z.object({
  hasPasswordForm: z.boolean().default(false),
  loginFormCount: z.number().int().min(0).max(100).default(0),
  suspiciousPhraseCount: z.number().int().min(0).max(100).default(0),
  externalDomains: z.array(z.string().max(253)).max(50).default([]),
  redirectsObserved: z.number().int().min(0).max(20).default(0),
  brandMismatch: z.boolean().default(false),
});

export const analyzeRequestSchema = z.object({
  url: z.string().url().max(2048).refine((value) => {
    const protocol = new URL(value).protocol;
    return protocol === 'http:' || protocol === 'https:';
  }, 'Only HTTP and HTTPS URLs can be analyzed.'),
  pageSignals: pageSignalsSchema.optional().default({}),
});

export const riskLevelSchema = z.enum(['low', 'caution', 'suspicious', 'high']);

export const reasonSchema = z.object({
  type: z.string(),
  severity: z.enum(['positive', 'info', 'warning', 'high']),
  message: z.string(),
});

export const providerResultSchema = z.object({
  provider: z.string(),
  available: z.boolean(),
  found: z.boolean().nullable(),
  detail: z.string().optional(),
});

export const DISCLAIMER =
  'Risk assessment is informational and cannot guarantee that a website is safe.';

export const analysisResponseSchema = z.object({
  domain: z.string(),
  score: z.number().min(0).max(100),
  level: riskLevelSchema,
  confidence: z.number().min(0).max(1),
  reasons: z.array(reasonSchema),
  signals: z.record(z.union([z.string(), z.number(), z.boolean(), z.null()])),
  providerResults: z.array(providerResultSchema),
  checkedAt: z.string().datetime(),
  limitedAnalysis: z.boolean().default(false),
  disclaimer: z.literal(DISCLAIMER).default(DISCLAIMER),
});

export const extensionMessageSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('WEBPILL_ANALYZE'),
    url: z.string().url().max(2048),
    pageSignals: pageSignalsSchema,
    force: z.boolean().optional(),
  }),
  z.object({ type: z.literal('WEBPILL_GET_STATUS') }),
  z.object({ type: z.literal('WEBPILL_SHOW_WIDGET') }),
  z.object({ type: z.literal('WEBPILL_OPEN_PANEL') }),
  z.object({ type: z.literal('WEBPILL_OPEN_SETTINGS') }),
]);

export type PageSignals = z.infer<typeof pageSignalsSchema>;
export type AnalyzeRequest = z.infer<typeof analyzeRequestSchema>;
export type RiskLevel = z.infer<typeof riskLevelSchema>;
export type RiskReason = z.infer<typeof reasonSchema>;
export type ProviderResult = z.infer<typeof providerResultSchema>;
export type AnalysisResponse = z.infer<typeof analysisResponseSchema>;
export type ExtensionMessage = z.infer<typeof extensionMessageSchema>;

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  confidence: number;
  reasons: RiskReason[];
  signals: Record<string, string | number | boolean | null>;
}

export interface RiskThresholds {
  caution: number;
  suspicious: number;
  high: number;
}

export interface DomainSignals {
  domainAgeDays: number | null;
  dnsResolved: boolean | null;
  nameserverCount: number | null;
  certificateValid: boolean | null;
  rdapAvailable: boolean;
  dnsAvailable: boolean;
  certificateAvailable: boolean;
}

export interface ThreatProvider {
  readonly name: string;
  checkUrl(url: string, domain: string): Promise<ProviderResult>;
}

export const DEFAULT_RISK_THRESHOLDS: RiskThresholds = {
  caution: 25,
  suspicious: 50,
  high: 75,
};
