import { describe, expect, it } from 'vitest';
import { extensionMessageSchema } from './index';

describe('extension message validation', () => {
  it('accepts a constrained analysis request', () => {
    const result = extensionMessageSchema.safeParse({
      type: 'WEBPILL_ANALYZE',
      url: 'https://example.com/path',
      pageSignals: { hasPasswordForm: false },
    });
    expect(result.success).toBe(true);
  });

  it('rejects unexpected message types and oversized URL values', () => {
    expect(extensionMessageSchema.safeParse({ type: 'RUN_SCRIPT' }).success).toBe(false);
    expect(extensionMessageSchema.safeParse({
      type: 'WEBPILL_ANALYZE',
      url: `https://example.com/${'a'.repeat(2100)}`,
      pageSignals: {},
    }).success).toBe(false);
  });
});
