import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { browser } from 'wxt/browser';
import { CACHE_PREFIX, DEFAULT_SETTINGS, parseSettings, SETTINGS_KEY, type WebpillSettings } from '../shared/settings';
import '../shared/ui.css';

function Options() {
  const [settings, setSettings] = useState<WebpillSettings>(DEFAULT_SETTINGS);
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void browser.storage.local.get(SETTINGS_KEY).then((stored) => {
      setSettings(parseSettings(stored[SETTINGS_KEY]));
      setLoading(false);
    }).catch(() => {
      setMessage('Settings could not be loaded from local browser storage.');
      setLoading(false);
    });
  }, []);

  const update = <K extends keyof WebpillSettings>(key: K, value: WebpillSettings[K]) => {
    setSettings((current) => ({ ...current, [key]: value }));
  };
  const save = async () => {
    try {
      const apiUrl = new URL(settings.apiBaseUrl);
      if (
        !['http:', 'https:'].includes(apiUrl.protocol)
        || apiUrl.username
        || apiUrl.password
        || apiUrl.pathname !== '/'
        || apiUrl.search
        || apiUrl.hash
      ) {
        setMessage('Enter an HTTP or HTTPS API origin without paths, query strings, fragments, or embedded credentials.');
        return;
      }
      const granted = await browser.permissions.request({ origins: [`${apiUrl.origin}/*`] });
      if (!granted) {
        setMessage('The analysis API host permission was not granted; settings were not changed.');
        return;
      }
      await browser.storage.local.set({ [SETTINGS_KEY]: settings });
      setMessage('Settings saved on this device.');
    } catch {
      setMessage('Settings could not be saved. Check browser storage permissions.');
    }
  };
  const clearCache = async () => {
    try {
      const stored = await browser.storage.local.get(null);
      const keys = Object.keys(stored).filter((key) => key.startsWith(CACHE_PREFIX));
      await browser.storage.local.remove(keys);
      setMessage(`Cleared ${keys.length} cached assessment(s).`);
    } catch {
      setMessage('The local assessment cache could not be cleared.');
    }
  };

  if (loading) return <main className="settings-page"><h1>webpill</h1><p>Loading settings…</p></main>;
  return (
    <main className="surface settings-page">
      <h1>webpill settings</h1>
      <p className="page-intro">Manage the website assessment experience. Preferences and cached results stay in your browser.</p>
      <label className="setting-row"><span>Floating indicator<small>Show or hide the indicator on websites.</small></span><input type="checkbox" checked={settings.enabled} onChange={(event) => update('enabled', event.target.checked)} /></label>
      <label className="setting-row"><span>Indicator position</span><select value={settings.position.anchor} onChange={(event) => update('position', { ...settings.position, anchor: event.target.value as WebpillSettings['position']['anchor'] })}>
        <option value="bottom-right">Bottom right</option><option value="bottom-left">Bottom left</option><option value="top-right">Top right</option><option value="top-left">Top left</option>
      </select></label>
      <label className="setting-row"><span>Analyze automatically<small>Check newly opened pages when the extension is available.</small></span><input type="checkbox" checked={settings.analyzeAutomatically} onChange={(event) => update('analyzeAutomatically', event.target.checked)} /></label>
      <label className="setting-row"><span>Page-content signals<small>Inspect form presence and selected phrases locally. Page text is never sent.</small></span><input type="checkbox" checked={settings.pageContentAnalysis} onChange={(event) => update('pageContentAnalysis', event.target.checked)} /></label>
      <label className="setting-row"><span>Cache duration</span><select value={settings.cacheDurationHours} onChange={(event) => update('cacheDurationHours', Number(event.target.value))}>
        <option value={1}>1 hour</option><option value={6}>6 hours</option><option value={24}>24 hours</option><option value={72}>3 days</option>
      </select></label>
      <label className="setting-row"><span>Theme</span><select value={settings.theme} onChange={(event) => update('theme', event.target.value as WebpillSettings['theme'])}>
        <option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option>
      </select></label>
      <label className="setting-row"><span>Show detailed reasons</span><input type="checkbox" checked={settings.detailedReasons} onChange={(event) => update('detailedReasons', event.target.checked)} /></label>
      <label className="setting-row"><span>Analysis service URL<small>Default local API endpoint.</small></span><input aria-label="Analysis service URL" type="url" value={settings.apiBaseUrl} onChange={(event) => update('apiBaseUrl', event.target.value)} /></label>
      <div className="settings-actions">
        <button className="button" type="button" onClick={() => void save()}>Save settings</button>
        <button className="button secondary" type="button" onClick={() => void clearCache()}>Clear cached analysis</button>
        <a href={browser.runtime.getURL('/privacy.html')}>Privacy information</a>
      </div>
      {message && <p className="message" role="status">{message}</p>}
    </main>
  );
}

createRoot(document.getElementById('root')!).render(<Options />);
