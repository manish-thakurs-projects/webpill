import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import * as tls from 'node:tls';
import type { DomainSignals } from '@webpill/shared';
import { fetchWithTimeout } from '../providers/types.js';

interface RData {
  Status?: number;
  Answer?: Array<{ data?: string }>;
}

interface RdapData {
  events?: Array<{ eventAction?: string; eventDate?: string }>;
}

export function isPublicAddress(address: string) {
  const version = isIP(address);
  if (version === 4) {
    const parts = address.split('.').map(Number);
    const [a, b, c] = parts;
    return !(
      a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99)))
      || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
      || (a === 203 && b === 0 && c === 113)
    );
  }
  if (version === 6) {
    const normalized = address.toLowerCase();
    const mappedIpv4 = normalized.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/)?.[1];
    if (mappedIpv4) return isPublicAddress(mappedIpv4);
    const firstHextet = Number.parseInt(normalized.split(':')[0] || '0', 16);
    return firstHextet >= 0x2000 && firstHextet <= 0x3fff
      && !normalized.startsWith('2001:db8:');
  }
  return false;
}

async function queryDns(domain: string) {
  const [addressResponse, nameserverResponse] = await Promise.all([
    fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`),
    fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=NS`),
  ]);
  if (!addressResponse.ok || !nameserverResponse.ok) throw new Error('Public DNS lookup failed.');
  const [addressData, nameserverData] = await Promise.all([
    addressResponse.json() as Promise<RData>,
    nameserverResponse.json() as Promise<RData>,
  ]);
  return {
    resolved: addressData.Status === 0 && Boolean(addressData.Answer?.length),
    nameserverCount: nameserverData.Status === 0
      ? new Set((nameserverData.Answer ?? []).map((answer) => answer.data?.toLowerCase()).filter(Boolean)).size
      : null,
  };
}

async function queryRegistrationAge(domain: string) {
  const response = await fetchWithTimeout(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
  if (!response.ok) throw new Error(`RDAP returned HTTP ${response.status}.`);
  const data = await response.json() as RdapData;
  const registeredAt = data.events?.find((event) => event.eventAction?.toLowerCase() === 'registration')?.eventDate;
  if (!registeredAt) return null;
  const age = Date.now() - new Date(registeredAt).getTime();
  return Number.isFinite(age) && age >= 0 ? Math.floor(age / 86_400_000) : null;
}

async function queryCertificate(domain: string) {
  if (isIP(domain)) return null;
  let addresses: Array<{ address: string }> = [];
  try {
    let timer: NodeJS.Timeout;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error('DNS lookup timed out.')), 5_000);
      timer.unref();
    });
    try {
      addresses = await Promise.race([lookup(domain, { all: true, verbatim: true }), timeout]);
    } finally {
      clearTimeout(timer!);
    }
  } catch {
    return null;
  }
  const publicAddress = addresses.find(({ address }) => isPublicAddress(address))?.address;
  if (!publicAddress) return null;

  return new Promise<boolean | null>((resolve) => {
    let settled = false;
    const finish = (value: boolean | null) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };
    const socket = tls.connect({
      host: publicAddress,
      port: 443,
      servername: domain,
      rejectUnauthorized: false,
      timeout: 5_000,
      checkServerIdentity: (_host, certificate) => tls.checkServerIdentity(domain, certificate),
    });
    socket.once('secureConnect', () => finish(socket.authorized));
    socket.once('error', () => finish(null));
    socket.once('timeout', () => finish(null));
  });
}

export async function inspectDomain(domain: string, protocol: string): Promise<DomainSignals> {
  const normalized = domain.toLowerCase().replace(/\.$/, '');
  const [registration, dns, certificate] = await Promise.allSettled([
    queryRegistrationAge(normalized),
    queryDns(normalized),
    protocol === 'https:' ? queryCertificate(normalized) : Promise.resolve(null),
  ]);
  const rdapAvailable = registration.status === 'fulfilled';
  const dnsAvailable = dns.status === 'fulfilled';
  const certificateAvailable = certificate.status === 'fulfilled' && certificate.value !== null;
  if (!rdapAvailable) console.warn(JSON.stringify({ level: 'warn', event: 'rdap_lookup_failed' }));
  if (!dnsAvailable) console.warn(JSON.stringify({ level: 'warn', event: 'dns_lookup_failed' }));
  if (protocol === 'https:' && !certificateAvailable) {
    console.warn(JSON.stringify({ level: 'warn', event: 'certificate_lookup_failed' }));
  }
  return {
    domainAgeDays: rdapAvailable ? registration.value : null,
    dnsResolved: dnsAvailable ? dns.value.resolved : null,
    nameserverCount: dnsAvailable ? dns.value.nameserverCount : null,
    certificateValid: certificateAvailable ? certificate.value : null,
    rdapAvailable,
    dnsAvailable,
    certificateAvailable,
  };
}
