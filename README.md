# ip-risk-data

Static IP risk data and Telegram login risk rules for Egern/Surge widgets.

## Generated files

- `dist/version.json` — sync metadata
- `dist/tg-risk-rules.json` — remote Telegram risk weights
- `dist/cloud-asn.json` — cloud/hosting ASN map
- `dist/tor-exit-v4.txt` — Tor exit IPv4 list
- `dist/spamhaus-drop.txt` — Spamhaus DROP CIDR list
- `dist/spamhaus-edrop.txt` — Spamhaus EDROP CIDR list

GitHub Actions refreshes data hourly. Scripts should treat this repository as a static mirror/rules source, not a realtime IP reputation API.
