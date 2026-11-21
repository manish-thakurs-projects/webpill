import { browser } from 'wxt/browser';
import { extensionMessageSchema } from '@webpill/shared';
import { getSettings, requestAnalysis, type ContentMessage } from './shared/analysis';
import { DEFAULT_SETTINGS, SETTINGS_KEY } from './shared/settings';

export default defineBackground(() => {
  browser.runtime.onInstalled.addListener(async () => {
    const stored = await browser.storage.local.get(SETTINGS_KEY);
    if (!stored[SETTINGS_KEY]) await browser.storage.local.set({ [SETTINGS_KEY]: DEFAULT_SETTINGS });
  });

  browser.runtime.onMessage.addListener((message: unknown) => {
    const parsed = extensionMessageSchema.safeParse(message);
    if (!parsed.success) return undefined;
    const request: ContentMessage = parsed.data;
    if (request.type === 'WEBPILL_ANALYZE') {
      return requestAnalysis(request.url, request.pageSignals, request.force);
    }
    if (request.type === 'WEBPILL_OPEN_SETTINGS') {
      return browser.runtime.openOptionsPage();
    }
    return undefined;
  });

  void getSettings().catch((error: unknown) => {
    console.error('[webpill] Could not initialize settings.', error);
  });
});
