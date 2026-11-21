import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { analyzeRisk } from '@webpill/risk-engine';
import { analysisResponseSchema, DISCLAIMER, type AnalysisResponse, type RiskLevel } from '@webpill/shared';
import { browser } from 'wxt/browser';
import { collectPageSignals, getSettings, type ContentMessage } from './shared/analysis';
import { DEFAULT_SETTINGS, SETTINGS_KEY, type WidgetPosition } from './shared/settings';

const riskCopy: Record<RiskLevel, { label: string; color: string }> = {
  low: { label: 'LOW DETECTED RISK', color: '#18864b' },
  caution: { label: 'CAUTION', color: '#8a6800' },
  suspicious: { label: 'SUSPICIOUS', color: '#c85b00' },
  high: { label: 'HIGH DETECTED RISK', color: '#c62828' },
};

function Widget({ hostname, url }: { hostname: string; url: string }) {
  const [open, setOpen] = useState(false);
  const [visible, setVisible] = useState(true);
  const [loading, setLoading] = useState(true);
  const [details, setDetails] = useState(false);
  const [position, setPosition] = useState<WidgetPosition>(DEFAULT_SETTINGS.position);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [theme, setTheme] = useState('system');
  const dragState = useRef<{ x: number; y: number; right: number; bottom: number } | null>(null);

  const analyze = async (force = false) => {
    setLoading(true);
    let pageContentAnalysis = false;
    let settingsAvailable = true;
    try {
      pageContentAnalysis = (await getSettings()).pageContentAnalysis;
    } catch (error) {
      settingsAvailable = false;
      console.error('[webpill] Browser settings could not be read; using URL-only local checks.', error);
    }
    const pageSignals = collectPageSignals(hostname, pageContentAnalysis);
    const local = analyzeRisk({ url, pageSignals });
    const localResult = analysisResponseSchema.parse({
      domain: hostname,
      ...local,
      providerResults: [],
      checkedAt: new Date().toISOString(),
      limitedAnalysis: true,
    });
    let nextResult = localResult;
    setResult(localResult);
    if (!settingsAvailable) {
      nextResult = analysisResponseSchema.parse({
        ...localResult,
        reasons: [
          ...localResult.reasons,
          { type: 'settings', severity: 'info', message: 'Browser settings could not be read; only local URL checks were completed.' },
        ],
      });
      setResult(nextResult);
      setLoading(false);
      return nextResult;
    }
    try {
      const remote = await browser.runtime.sendMessage({ type: 'WEBPILL_ANALYZE', url, pageSignals, force });
      const parsed = analysisResponseSchema.safeParse(remote);
      if (parsed.success) {
        nextResult = parsed.data;
        setResult(parsed.data);
      } else throw new Error('The analysis response was invalid.');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Analysis could not be completed.';
      console.warn(`[webpill] ${message}`);
      nextResult = analysisResponseSchema.parse({
        ...localResult,
        reasons: [
          ...localResult.reasons,
          { type: 'limited_analysis', severity: 'info', message: 'Some reputation services are unavailable. Local checks completed.' },
        ],
      });
      setResult(nextResult);
    } finally {
      setLoading(false);
    }
    return nextResult;
  };

  useEffect(() => {
    const host = document.getElementById('webpill-extension-root');
    if (host) {
      const horizontal = position.anchor.endsWith('right') ? 'right' : 'left';
      const vertical = position.anchor.startsWith('bottom') ? 'bottom' : 'top';
      host.style.right = horizontal === 'right' ? `${position.right}px` : 'auto';
      host.style.left = horizontal === 'left' ? `${position.right}px` : 'auto';
      host.style.bottom = vertical === 'bottom' ? `${position.bottom}px` : 'auto';
      host.style.top = vertical === 'top' ? `${position.bottom}px` : 'auto';
    }
  }, [position]);

  useEffect(() => {
    void getSettings().then((settings) => {
      setPosition(settings.position);
      setTheme(settings.theme);
      setDetails(settings.detailedReasons);
      setVisible(settings.enabled);
    }).catch((error: unknown) => {
      console.error('[webpill] Initial browser settings are invalid.', error);
    });
    void analyze();

    const listener = (changes: Record<string, { newValue?: unknown }>) => {
      if (changes[SETTINGS_KEY]?.newValue) {
        void getSettings().then((settings) => {
          setPosition(settings.position);
          setTheme(settings.theme);
          setDetails(settings.detailedReasons);
          setVisible(settings.enabled);
        }).catch((error: unknown) => {
          console.error('[webpill] Updated browser settings are invalid.', error);
        });
      }
    };
    browser.storage.onChanged.addListener(listener);
    return () => browser.storage.onChanged.removeListener(listener);
  }, []);

  useEffect(() => {
    const listener = (message: ContentMessage) => {
      if (message?.type === 'WEBPILL_GET_STATUS') {
        return Promise.resolve({ result, loading, hostname, visible });
      }
      if (message?.type === 'WEBPILL_SHOW_WIDGET') {
        setVisible(true);
        return Promise.resolve({ ok: true });
      }
      if (message?.type === 'WEBPILL_OPEN_PANEL') {
        setVisible(true);
        setOpen(true);
        return Promise.resolve({ ok: true });
      }
      if (message?.type === 'WEBPILL_OPEN_SETTINGS') {
        void browser.runtime.openOptionsPage();
        return Promise.resolve({ ok: true });
      }
      if (message?.type === 'WEBPILL_ANALYZE') {
        return analyze(Boolean(message.force));
      }
      return undefined;
    };
    browser.runtime.onMessage.addListener(listener);
    return () => browser.runtime.onMessage.removeListener(listener);
  }, [result, loading, hostname, url, visible]);

  const beginDrag = (event: React.PointerEvent<HTMLDivElement>) => {
    dragState.current = { x: event.clientX, y: event.clientY, right: position.right, bottom: position.bottom };
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const moveDrag = (event: React.PointerEvent<HTMLDivElement>) => {
    if (!dragState.current) return;
    const horizontal = position.anchor.endsWith('right') ? 'right' : 'left';
    const vertical = position.anchor.startsWith('bottom') ? 'bottom' : 'top';
    const next = {
      ...position,
      right: Math.max(0, Math.min(window.innerWidth - 52, dragState.current.right + (horizontal === 'right' ? -1 : 1) * (event.clientX - dragState.current.x))),
      bottom: Math.max(0, Math.min(window.innerHeight - 52, dragState.current.bottom + (vertical === 'bottom' ? 1 : -1) * (event.clientY - dragState.current.y))),
    };
    setPosition(next);
  };
  const endDrag = () => {
    dragState.current = null;
    void browser.storage.local.get(SETTINGS_KEY).then((stored) => {
      const settings = { ...DEFAULT_SETTINGS, ...(stored[SETTINGS_KEY] ?? {}), position };
      return browser.storage.local.set({ [SETTINGS_KEY]: settings });
    });
  };

  if (!visible) return null;
  const status = result ? riskCopy[result.level] : null;
  return (
    <div className={`widget theme-${theme}`} aria-label="webpill website risk assessment">
      {!open ? (
        <button className="pill" type="button" aria-label={`Open webpill assessment for ${hostname}`} onClick={() => setOpen(true)}>
          <span className="dot" style={{ backgroundColor: status?.color ?? '#777' }} />
          <span className="pill-label">{loading ? 'Checking' : status?.label ?? 'Analysis unavailable'}</span>
        </button>
      ) : (
        <section className="panel" aria-label="webpill security panel">
          <div className="drag" onPointerDown={beginDrag} onPointerMove={moveDrag} onPointerUp={endDrag} onPointerCancel={endDrag}>
            <div>
              <strong>{hostname}</strong>
              <span className="subtitle">webpill risk assessment</span>
            </div>
            <div className="header-actions">
              <button type="button" aria-label="Open webpill settings" onClick={() => void browser.runtime.openOptionsPage()}>⚙</button>
              <button type="button" aria-label="Hide webpill indicator" onClick={() => setVisible(false)}>×</button>
            </div>
          </div>
          <div className="score-row">
            <span className="status-dot" style={{ backgroundColor: status?.color ?? '#777' }} />
            <div>
              <strong>{loading ? 'CHECKING…' : status?.label ?? 'ANALYSIS UNAVAILABLE'}</strong>
              <span className="score">{result ? `${result.score} / 100` : 'Local checks running'}</span>
            </div>
          </div>
          <div className="reasons">
            {(result?.reasons ?? []).slice(0, details ? 12 : 4).map((reason, index) => (
              <div className="reason" key={`${reason.type}-${index}`}>
                <span className={reason.severity === 'positive' ? 'check' : 'reason-mark'}>{reason.severity === 'positive' ? '✓' : '•'}</span>
                <span>{reason.message}</span>
              </div>
            ))}
            {result?.limitedAnalysis && <p className="limited">Some reputation services are unavailable. Local checks completed.</p>}
            {!result?.reasons.length && <p className="limited">Analysis is in progress.</p>}
          </div>
          {details && result?.providerResults.map((provider) => (
            <div className="reason provider-reason" key={provider.provider}>
              <span>{provider.provider}</span>
              <span>{!provider.available ? 'Unavailable' : provider.found ? 'Match reported' : 'No match returned'}</span>
            </div>
          ))}
          <button className="text-button" type="button" onClick={() => setDetails((value) => !value)}>
            {details ? 'Show less' : 'View details'}
          </button>
          <p className="disclaimer">{result?.disclaimer ?? DISCLAIMER}</p>
          <div className="panel-footer">
            <button className="text-button" type="button" onClick={() => void analyze(true)}>Refresh</button>
            <button className="close-button" type="button" aria-label="Close webpill panel" onClick={() => setOpen(false)}>Close</button>
          </div>
        </section>
      )}
    </div>
  );
}

export default defineContentScript({
  matches: ['http://*/*', 'https://*/*'],
  runAt: 'document_idle',
  main() {
    if (!['http:', 'https:'].includes(location.protocol) || !location.hostname) return;
    const existing = document.getElementById('webpill-extension-root');
    if (existing) return;
    const host = document.createElement('div');
    host.id = 'webpill-extension-root';
    host.style.cssText = 'position:fixed;z-index:2147483647;left:18px;bottom:18px;pointer-events:none;';
    const shadow = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = `
      :host{all:initial;color-scheme:light dark}
      *{box-sizing:border-box}
      .widget{font:13px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#111;pointer-events:auto}
      .widget button{font:inherit;color:inherit}
      .pill{display:flex;align-items:center;gap:8px;background:#fff;border:1px solid #e5e5e5;border-radius:999px;padding:7px 11px;box-shadow:0 3px 16px #0002;cursor:pointer}
      .pill-label{font-size:11px;font-weight:650;letter-spacing:.02em}
      .dot,.status-dot{display:inline-block;width:11px;height:11px;border-radius:50%;flex:none}
      .panel{width:min(330px,calc(100vw - 28px));max-height:min(520px,calc(100vh - 36px));overflow:auto;border:1px solid #e5e5e5;border-radius:15px;background:#fff;box-shadow:0 8px 36px #0003;padding:15px}
      .drag{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin:-2px -2px 14px;cursor:move;touch-action:none}
      .drag strong{display:block;font-size:14px;overflow-wrap:anywhere}
      .subtitle,.score{display:block;color:#666;font-size:11px;margin-top:2px}
      .header-actions{display:flex;gap:4px}
      .header-actions button,.close-button{border:0;background:transparent;border-radius:7px;cursor:pointer;color:#555;padding:5px 7px}
      button:focus-visible{outline:2px solid #111;outline-offset:2px}
      .header-actions button:hover,.close-button:hover{background:#f5f5f5}
      .score-row{display:flex;align-items:center;gap:10px;border-block:1px solid #eee;padding:12px 0}
      .score-row strong{font-size:11px;letter-spacing:.04em}
      .reasons{padding:10px 0 2px}
      .reason{display:flex;gap:8px;margin:7px 0;color:#333;font-size:12px}
      .provider-reason{justify-content:space-between;color:#666;font-size:10px;border-top:1px solid #eee;padding-top:6px}
      .check{color:#18864b;font-weight:700}
      .reason-mark{color:#666;font-weight:700}
      .limited{font-size:11px;color:#666;margin:8px 0}
      .text-button{border:0;background:none;text-decoration:underline;cursor:pointer;padding:5px 0;font-size:12px}
      .disclaimer{font-size:10px;line-height:1.4;color:#666;border-top:1px solid #eee;padding-top:10px;margin:10px 0}
      .panel-footer{display:flex;align-items:center;justify-content:space-between}
      .theme-dark{color:#f5f5f5}
      .theme-dark .panel,.theme-dark .pill{background:#171717;color:#f5f5f5;border-color:#444}
      .theme-dark .reason,.theme-dark .subtitle,.theme-dark .score,.theme-dark .limited,.theme-dark .disclaimer{color:#ccc}
      .theme-dark .score-row,.theme-dark .disclaimer{border-color:#444}
      .theme-dark .header-actions button,.theme-dark .close-button{color:#eee}
      .theme-dark .header-actions button:hover,.theme-dark .close-button:hover{background:#333}
      @media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;transition:none!important}}
      @media(prefers-color-scheme:dark){.theme-system{color:#f5f5f5}.theme-system .panel,.theme-system .pill{background:#171717;color:#f5f5f5;border-color:#444}.theme-system .reason,.theme-system .subtitle,.theme-system .score,.theme-system .limited,.theme-system .disclaimer{color:#ccc}.theme-system .score-row,.theme-system .disclaimer{border-color:#444}.theme-system .header-actions button,.theme-system .close-button{color:#eee}.theme-system .header-actions button:hover,.theme-system .close-button:hover{background:#333}}
    `;
    shadow.append(style);
    const mount = document.createElement('div');
    mount.style.cssText = 'pointer-events:auto;';
    shadow.append(mount);
    document.documentElement.append(host);
    const root = createRoot(mount);
    root.render(<Widget hostname={location.hostname} url={location.href} />);
  },
});
