const DATA_BASE = 'https://raw.githubusercontent.com/Linsars/ip-risk-data/main/dist';
const DATA_REV = '5420785';
const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*' };

function ip4ToInt(ip) {
  const p = String(ip || '').split('.').map(Number);
  if (p.length !== 4 || p.some(x => !Number.isInteger(x) || x < 0 || x > 255)) return null;
  return (((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3]) >>> 0;
}
function ip4InCidr(ip, cidr) {
  const n = ip4ToInt(ip);
  const m = String(cidr || '').trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (n === null || !m) return false;
  const base = ip4ToInt(m[1]);
  const bits = Number(m[2]);
  if (base === null || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (n & mask) === (base & mask);
}
function inList(ip, txt) {
  return String(txt || '').split(/\n+/).some(x => x.trim() === ip);
}
function inCidrList(ip, txt) {
  return String(txt || '').split(/\n+/).some(x => ip4InCidr(ip, x));
}
async function text(url, ttl = 3600) {
  const r = await fetch(url, { cf: { cacheTtl: ttl, cacheEverything: true } });
  return r.ok ? await r.text() : '';
}
async function json(url, ttl = 300) {
  const r = await fetch(url, { cf: { cacheTtl: ttl, cacheEverything: true } });
  return r.ok ? await r.json() : null;
}
function sevText(sev) {
  if (sev >= 4) return '极高';
  if (sev >= 3) return '高';
  if (sev >= 2) return '中';
  if (sev >= 1) return '低';
  return '低危';
}
async function check(ip) {
  const [tor, drop, edrop, cloudAsn, rules, pc, ipapi, shodan] = await Promise.allSettled([
    text(`${DATA_BASE}/tor-exit-v4.txt?v=${DATA_REV}`, 1800),
    text(`${DATA_BASE}/spamhaus-drop.txt?v=${DATA_REV}`, 3600),
    text(`${DATA_BASE}/spamhaus-edrop.txt?v=${DATA_REV}`, 3600),
    json(`${DATA_BASE}/cloud-asn.json?v=${DATA_REV}`, 3600),
    json(`${DATA_BASE}/tg-risk-rules.json?v=${DATA_REV}`, 3600),
    json(`https://proxycheck.io/v2/${encodeURIComponent(ip)}?vpn=1&asn=1&risk=1`, 300),
    json(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`, 300),
    json(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, 300)
  ]);
  const torTxt = tor.status === 'fulfilled' ? tor.value : '';
  const dropTxt = drop.status === 'fulfilled' ? drop.value : '';
  const edropTxt = edrop.status === 'fulfilled' ? edrop.value : '';
  const cloud = cloudAsn.status === 'fulfilled' && cloudAsn.value ? cloudAsn.value : {};
  const rule = rules.status === 'fulfilled' && rules.value ? rules.value : { thresholds: { payment: 70, email: 45, maybe: 25, slight: 10 } };
  const pcItem = pc.status === 'fulfilled' && pc.value ? pc.value[ip] || {} : {};
  const ia = ipapi.status === 'fulfilled' && ipapi.value ? ipapi.value : {};
  const sd = shodan.status === 'fulfilled' && shodan.value ? shodan.value : {};

  const asn = ia?.asn?.asn ? `AS${ia.asn.asn}` : (pcItem.asn || '');
  const cloudInfo = asn && cloud[asn] ? cloud[asn] : null;
  const ports = Array.isArray(sd.ports) ? sd.ports : [];
  const vulns = sd.vulns && typeof sd.vulns === 'object' ? Object.keys(sd.vulns) : [];
  const sensitivePorts = rule.sensitivePorts || [22,23,3389,5900,6379,9200,9300,11211];
  const sensitive = ports.filter(p => sensitivePorts.includes(Number(p)));
  const isTor = inList(ip, torTxt) || ia.is_tor === true;
  const spamhaus = inCidrList(ip, dropTxt) ? 'DROP' : (inCidrList(ip, edropTxt) ? 'EDROP' : '未命中');
  const proxy = String(pcItem.proxy || '').toLowerCase() === 'yes' || ia.is_proxy === true || ia.is_vpn === true;
  const proxyType = pcItem.type || (ia.is_vpn ? 'VPN' : (ia.is_proxy ? 'Proxy' : 'Clean'));
  const datacenter = ia.is_datacenter === true || String(ia?.company?.type || '').toLowerCase() === 'hosting' || String(ia?.asn?.type || '').toLowerCase() === 'hosting';
  const cloudLabel = cloudInfo ? cloudInfo.name : (datacenter ? (ia?.asn?.org || ia?.company?.name || pcItem.provider || '托管商') : '否');
  const fraud = Number(pcItem.risk || 0) || 0;
  let score = 0;
  if (isTor) score += 55;
  if (proxy) score += fraud >= 80 ? 30 : 20;
  if (datacenter) score += 14;
  if (cloudInfo) score += cloudInfo.tgWeight || 18;
  if (spamhaus !== '未命中') score += 40;
  if (vulns.length) score += 35;
  else if (sensitive.length) score += 12;
  if (fraud >= 80) score += 30; else if (fraud >= 60) score += 16;
  const th = rule.thresholds || { payment: 70, email: 45, maybe: 25, slight: 10 };
  const tg = score >= th.payment ? '邮箱/收费' : score >= th.email ? '易邮箱' : score >= th.maybe ? '可能风控' : score >= th.slight ? '稍有风险' : '大概率正常';
  const sev = score >= th.payment ? 4 : score >= th.email ? 3 : score >= th.maybe ? 2 : score >= th.slight ? 1 : 0;
  return {
    ip, updated_at: new Date().toISOString(), score, severity: sevText(sev), tg,
    asn, cloud: cloudLabel, proxy: proxy ? '是' : '否', proxy_type: proxyType, proxy_risk: pcItem.risk ?? null,
    tor: isTor ? '是' : '否', datacenter: datacenter ? '是' : '否', spamhaus,
    ports: ports.slice(0, 12), sensitive_ports: sensitive, vulns: vulns.slice(0, 10)
  };
}

addEventListener('fetch', event => {
  event.respondWith((async () => {
    const url = new URL(event.request.url);
    if (url.pathname === '/health') return new Response(JSON.stringify({ ok: true, service: 'ip-risk-api' }), { headers: JSON_HEADERS });
    if (url.pathname !== '/check') return new Response(JSON.stringify({ ok: false, error: 'use /check?ip=1.2.3.4' }), { status: 404, headers: JSON_HEADERS });
    const ip = url.searchParams.get('ip') || '';
    if (ip4ToInt(ip) === null) return new Response(JSON.stringify({ ok: false, error: 'invalid IPv4' }), { status: 400, headers: JSON_HEADERS });
    const result = await check(ip);
    return new Response(JSON.stringify({ ok: true, result }, null, 2), { headers: JSON_HEADERS });
  })());
});
