import React from 'react';
import { createRoot } from 'react-dom/client';
import '../shared/ui.css';

function Privacy() {
  return (
    <main className="surface privacy-page">
      <h1>webpill privacy</h1>
      <p className="page-intro">webpill is a website risk assessment tool, not a website truth machine. Its findings are informational and cannot guarantee safety.</p>
      <h2>Processed locally</h2>
      <p>URL structure, hostname, HTTPS use, and (when enabled) the presence of password forms and selected risk phrases are assessed in your browser. A bounded text scan is held only in memory while those local signals are calculated. Page HTML or text is not uploaded or retained; form values, cookies, authentication tokens, private messages, and uploaded files are never read.</p>
      <h2>What the API receives</h2>
      <p>When remote analysis is enabled, webpill sends the website origin (scheme and hostname) and limited boolean or count-based signals to your configured analysis API. URL paths, query strings, and fragments are excluded from API requests. The API may query public DNS, RDAP registration dates, a TLS certificate handshake, and configured threat providers using the domain; it does not request or expose private WHOIS contact data.</p>
      <h2>Local storage and server cache</h2>
      <p>Extension preferences and assessment results are stored in browser-local storage. The optional API MongoDB cache stores a hashed cache key, domain, assessment result, and expiry time, not a URL path or permanent browsing history. Cached data expires automatically. You can clear local cached results from Settings.</p>
      <h2>Third-party reputation services</h2>
      <p>The API can query Google Safe Browsing, VirusTotal, URLhaus, and PhishTank. Providers without configured credentials are marked unavailable; local checks continue. Their respective privacy policies and terms apply when a check is made.</p>
      <h2>Limitations</h2>
      <p>A low detected risk does not mean a website is safe. Results depend on available signals and provider coverage and may be incomplete or incorrect.</p>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(<Privacy />);
