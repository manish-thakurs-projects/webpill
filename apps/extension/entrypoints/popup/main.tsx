import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { analysisResponseSchema, DISCLAIMER, type AnalysisResponse } from '@webpill/shared';
import { browser } from 'wxt/browser';
import type { ContentMessage } from '../shared/analysis';
import '../shared/ui.css';

function Popup() {
  const [domain, setDomain] = useState('No supported page selected');
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [hidden, setHidden] = useState(false);

  const load = async (force = false) => {
    setLoading(true);
    setError('');
    try {
      const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id || !tab.url || !/^https?:\/\//i.test(tab.url)) {
        setDomain('Not available on this page');
        setResult(null);
        return;
      }
      setDomain(new URL(tab.url).hostname);
      const request: ContentMessage = force
        ? { type: 'WEBPILL_ANALYZE', url: tab.url, pageSignals: { hasPasswordForm: false, loginFormCount: 0, suspiciousPhraseCount: 0, externalDomains: [], redirectsObserved: 0, brandMismatch: false }, force: true }
        : { type: 'WEBPILL_GET_STATUS' };
      const response = await browser.tabs.sendMessage(tab.id, request);
      const parsed = analysisResponseSchema.safeParse(response?.result ?? response);
      if (parsed.success) setResult(parsed.data);
      else setError('Open or reload a website to start a local assessment.');
      setHidden(response?.visible === false);
    } catch {
      setError('The webpill indicator is not available on this page. Try reloading the website.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);
  const level = result?.level ?? 'low';
  return (
    <main className="surface popup">
      <header className="brand-row">
        <span className="brand-dot" aria-hidden="true" />
        <h1>webpill</h1>
        <button className="icon-button" type="button" aria-label="Open settings" onClick={() => void browser.runtime.openOptionsPage()}>⚙</button>
      </header>
      <p className="eyebrow">CURRENT WEBSITE</p>
      <p className="domain">{domain}</p>
      <div className="risk-card">
        <span className={`risk-indicator risk-${level}`} aria-hidden="true" />
        <div>
          <strong>{loading ? 'CHECKING…' : result?.level.toUpperCase() === 'LOW' ? 'LOW DETECTED RISK' : result?.level.toUpperCase() ?? 'WAITING FOR ANALYSIS'}</strong>
          <span>{result ? `Score: ${result.score} / 100` : 'Local assessment available'}</span>
        </div>
      </div>
      {error && <p className="message" role="status">{error}</p>}
      {hidden && <p className="message" role="status">The floating indicator is hidden for this page.</p>}
      {result && <ul className="reason-list">{result.reasons.slice(0, 4).map((reason, index) => <li key={`${reason.type}-${index}`}>{reason.message}</li>)}</ul>}
      {result && <ul className="provider-list" aria-label="Reputation provider results">
        {result.providerResults.map((provider) => (
          <li key={provider.provider}>
            <span>{provider.provider}</span>
            <span>{!provider.available ? 'Unavailable' : provider.found ? 'Match reported' : 'No match returned'}</span>
          </li>
        ))}
      </ul>}
      {result?.limitedAnalysis && <p className="message">Limited analysis — local checks completed.</p>}
      <p className="disclaimer">{result?.disclaimer ?? DISCLAIMER}</p>
      <div className="button-row">
        <button className="button secondary" type="button" onClick={() => void load(true)} disabled={loading}>Refresh analysis</button>
        <button className="button" type="button" onClick={async () => {
          try {
            const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
            if (tab?.id) await browser.tabs.sendMessage(tab.id, { type: 'WEBPILL_OPEN_PANEL' });
            setHidden(false);
          } catch {
            setError('The webpill panel could not be opened on this page.');
          }
        }}>View details</button>
      </div>
      <nav className="links">
        <a href="#" onClick={(event) => { event.preventDefault(); void browser.runtime.openOptionsPage(); }}>Settings</a>
        <a href={browser.runtime.getURL('/privacy.html')} target="_blank" rel="noreferrer">Privacy</a>
      </nav>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(<Popup />);
