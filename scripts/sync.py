#!/usr/bin/env python3
import json, re, time, urllib.request, ipaddress
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'
DIST.mkdir(exist_ok=True)
UA = 'Linsars-ip-risk-data/1.0'

def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={'User-Agent': UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode('utf-8', 'replace')

def write(name, data):
    p = DIST / name
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, (dict, list)):
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
    else:
        p.write_text(str(data).rstrip() + '\n')
    return p

def cidrs_from_text(txt):
    out=[]
    for line in txt.splitlines():
        line=line.strip()
        if not line or line.startswith(';') or line.startswith('#'):
            continue
        m=re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', line)
        if m:
            try:
                out.append(str(ipaddress.ip_network(m.group(0), strict=False)))
            except Exception:
                pass
    return sorted(set(out), key=lambda x:(int(ipaddress.ip_network(x).network_address), ipaddress.ip_network(x).prefixlen))

def ips_from_text(txt):
    out=[]
    for line in txt.splitlines():
        line=line.strip()
        if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', line):
            out.append(line)
    return sorted(set(out), key=lambda x:int(ipaddress.ip_address(x)))

cloud_asn = {
  'AS16509': {'name':'AWS', 'type':'cloud', 'tgWeight':18},
  'AS14618': {'name':'AWS', 'type':'cloud', 'tgWeight':18},
  'AS15169': {'name':'Google', 'type':'cloud', 'tgWeight':18},
  'AS396982': {'name':'Google Cloud', 'type':'cloud', 'tgWeight':18},
  'AS8075': {'name':'Azure', 'type':'cloud', 'tgWeight':18},
  'AS31898': {'name':'Oracle Cloud', 'type':'cloud', 'tgWeight':18},
  'AS13335': {'name':'Cloudflare', 'type':'cloud', 'tgWeight':14},
  'AS14061': {'name':'DigitalOcean', 'type':'hosting', 'tgWeight':20},
  'AS63949': {'name':'Akamai/Linode', 'type':'hosting', 'tgWeight':18},
  'AS20473': {'name':'Vultr', 'type':'hosting', 'tgWeight':18},
  'AS24940': {'name':'Hetzner', 'type':'hosting', 'tgWeight':18},
  'AS16276': {'name':'OVH', 'type':'hosting', 'tgWeight':18},
  'AS45102': {'name':'Alibaba Cloud', 'type':'cloud', 'tgWeight':18},
  'AS132203': {'name':'Tencent Cloud', 'type':'cloud', 'tgWeight':18},
  'AS9009': {'name':'M247', 'type':'hosting', 'tgWeight':22},
  'AS38136': {'name':'Akari', 'type':'hosting', 'tgWeight':22},
  'AS40676': {'name':'Psychz', 'type':'hosting', 'tgWeight':20},
  'AS55286': {'name':'B2 Net', 'type':'hosting', 'tgWeight':20},
  'AS35916': {'name':'Multacom', 'type':'hosting', 'tgWeight':20},
  'AS174': {'name':'Cogent', 'type':'backbone', 'tgWeight':10},
  'AS1299': {'name':'Arelion', 'type':'backbone', 'tgWeight':10},
  'AS3257': {'name':'GTT', 'type':'backbone', 'tgWeight':10},
  'AS60068': {'name':'Datacamp', 'type':'hosting', 'tgWeight':20},
  'AS212238': {'name':'Datacamp/CDN77', 'type':'hosting', 'tgWeight':20},
  'AS199524': {'name':'G-Core', 'type':'hosting', 'tgWeight':18},
  'AS20278': {'name':'Nexeon', 'type':'hosting', 'tgWeight':20},
  'AS53667': {'name':'PonyNet/BuyVM', 'type':'hosting', 'tgWeight':18},
  'AS25820': {'name':'IT7/QuadraNet', 'type':'hosting', 'tgWeight':20},
  'AS8100': {'name':'QuadraNet', 'type':'hosting', 'tgWeight':20}
}

rules = {
  'version': 1,
  'weights': {
    'proxy': 24, 'tor': 55, 'datacenter': 14, 'cloudAsn': 18,
    'blacklist': 40, 'threat': 28, 'attack': 20, 'suspicious': 20,
    'sensitivePort': 12, 'fraudHigh': 30, 'fraudMedium': 16,
    'residentialBonus': -12, 'mobileBonus': -15
  },
  'thresholds': {'payment':70, 'email':45, 'maybe':25, 'slight':10},
  'sensitivePorts': [22,23,3389,5900,6379,9200,9300,11211]
}

meta={'updated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'sources': {}}

try:
    tor=ips_from_text(fetch('https://check.torproject.org/torbulkexitlist'))
    write('tor-exit-v4.txt', '\n'.join(tor))
    meta['sources']['tor-exit-v4']={'count':len(tor)}
except Exception as e:
    meta['sources']['tor-exit-v4']={'error':str(e)}

for name,url in [('spamhaus-drop','https://www.spamhaus.org/drop/drop.txt'),('spamhaus-edrop','https://www.spamhaus.org/drop/edrop.txt')]:
    try:
        cidrs=cidrs_from_text(fetch(url))
        write(name+'.txt', '\n'.join(cidrs))
        meta['sources'][name]={'count':len(cidrs)}
    except Exception as e:
        meta['sources'][name]={'error':str(e)}

write('cloud-asn.json', cloud_asn)
write('tg-risk-rules.json', rules)
write('version.json', meta)
print(json.dumps(meta, ensure_ascii=False, indent=2))
