import { z } from 'zod';

export type WidgetAnchor = 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left';
export type WidgetPosition = { right: number; bottom: number; anchor: WidgetAnchor };
export type Theme = 'system' | 'light' | 'dark';

export interface WebpillSettings {
  enabled: boolean;
  position: WidgetPosition;
  analyzeAutomatically: boolean;
  pageContentAnalysis: boolean;
  cacheDurationHours: number;
  theme: Theme;
  detailedReasons: boolean;
  apiBaseUrl: string;
}

export const DEFAULT_SETTINGS: WebpillSettings = {
  enabled: true,
  position: { right: 18, bottom: 18, anchor: 'bottom-left' },
  analyzeAutomatically: true,
  pageContentAnalysis: false,
  cacheDurationHours: 24,
  theme: 'system',
  detailedReasons: true,
  apiBaseUrl: import.meta.env.WEBPILL_API_BASE_URL,
};

const settingsSchema = z.object({
  enabled: z.boolean().default(DEFAULT_SETTINGS.enabled),
  position: z.object({
    right: z.number().finite().min(0).default(DEFAULT_SETTINGS.position.right),
    bottom: z.number().finite().min(0).default(DEFAULT_SETTINGS.position.bottom),
    anchor: z.enum(['bottom-right', 'bottom-left', 'top-right', 'top-left']).default(DEFAULT_SETTINGS.position.anchor),
  }).default(DEFAULT_SETTINGS.position),
  analyzeAutomatically: z.boolean().default(DEFAULT_SETTINGS.analyzeAutomatically),
  pageContentAnalysis: z.boolean().default(DEFAULT_SETTINGS.pageContentAnalysis),
  cacheDurationHours: z.number().min(1).max(72).default(DEFAULT_SETTINGS.cacheDurationHours),
  theme: z.enum(['system', 'light', 'dark']).default(DEFAULT_SETTINGS.theme),
  detailedReasons: z.boolean().default(DEFAULT_SETTINGS.detailedReasons),
  apiBaseUrl: z.string().url().refine((value) => {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol)
      && !url.username
      && !url.password
      && url.pathname === '/'
      && !url.search
      && !url.hash;
  }, 'API URL must be an HTTP(S) origin without credentials or a path.').default(DEFAULT_SETTINGS.apiBaseUrl),
});

export function parseSettings(value: unknown): WebpillSettings {
  const stored = typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Partial<WebpillSettings>
    : {};
  const merged = {
    ...DEFAULT_SETTINGS,
    ...stored,
    position: {
      ...DEFAULT_SETTINGS.position,
      ...(stored.position && typeof stored.position === 'object' ? stored.position : {}),
    },
  };
  const parsed = settingsSchema.safeParse(merged);
  if (!parsed.success) throw new Error('Stored webpill settings are invalid.');
  return parsed.data;
}

export const CACHE_PREFIX = 'webpill:cache:';
export const SETTINGS_KEY = 'webpill:settings';
