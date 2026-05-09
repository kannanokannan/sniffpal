// Lightweight GeoIP lookup — curated major allocations, not a full database.
// Focused on private ranges, major US cloud/CDN (not suspicious),
// and country blocks relevant for IoT phone-home detection.

const ipToInt = ip =>
  ip.split('.').reduce((n, o) => (n << 8) | parseInt(o, 10), 0) >>> 0;

function buildRanges(raw) {
  return raw
    .map(([cidr, code, label, flag]) => {
      const [ipStr, prefixStr] = cidr.split('/');
      const bits = parseInt(prefixStr, 10);
      const start = ipToInt(ipStr);
      const mask = bits === 0 ? 0 : ((0xFFFFFFFF << (32 - bits)) >>> 0);
      const s = (start & mask) >>> 0;
      const e = (s | (~mask >>> 0)) >>> 0;
      return [s, e, code, label, flag];
    })
    .sort((a, b) => (a[0] >>> 0) - (b[0] >>> 0) || (a[1] >>> 0) - (b[1] >>> 0));
}

const RANGES = buildRanges([
  // ── Private / local (code: null — always skip) ───────────────────────────
  ['10.0.0.0/8',        null, 'Private',         '🏠'],
  ['100.64.0.0/10',     null, 'CGNAT',            '🏠'],
  ['127.0.0.0/8',       null, 'Loopback',         '🏠'],
  ['169.254.0.0/16',    null, 'Link-local',       '🏠'],
  ['172.16.0.0/12',     null, 'Private',          '🏠'],
  ['192.168.0.0/16',    null, 'Private',          '🏠'],
  ['224.0.0.0/4',       null, 'Multicast',        '🏠'],
  ['240.0.0.0/4',       null, 'Reserved',         '🏠'],

  // ── United States — major cloud/CDN (not suspicious for IoT) ─────────────
  ['3.0.0.0/8',         'US', 'AWS',              '🇺🇸'],
  ['13.32.0.0/15',      'US', 'AWS CloudFront',   '🇺🇸'],
  ['17.0.0.0/8',        'US', 'Apple',            '🇺🇸'],
  ['23.32.0.0/11',      'US', 'Akamai',           '🇺🇸'],
  ['23.64.0.0/14',      'US', 'Akamai',           '🇺🇸'],
  ['31.13.24.0/21',     'US', 'Meta/Facebook',    '🇺🇸'],
  ['34.0.0.0/8',        'US', 'Google Cloud',     '🇺🇸'],
  ['35.0.0.0/8',        'US', 'Google Cloud',     '🇺🇸'],
  ['52.0.0.0/11',       'US', 'AWS',              '🇺🇸'],
  ['54.0.0.0/8',        'US', 'AWS',              '🇺🇸'],
  ['64.233.160.0/19',   'US', 'Google',           '🇺🇸'],
  ['66.220.144.0/20',   'US', 'Meta/Facebook',    '🇺🇸'],
  ['74.125.0.0/16',     'US', 'Google',           '🇺🇸'],
  ['104.16.0.0/12',     'US', 'Cloudflare',       '🇺🇸'],
  ['108.160.0.0/12',    'US', 'Fastly',           '🇺🇸'],
  ['151.101.0.0/16',    'US', 'Fastly',           '🇺🇸'],
  ['157.240.0.0/17',    'US', 'Meta/Facebook',    '🇺🇸'],
  ['172.217.0.0/16',    'US', 'Google',           '🇺🇸'],
  ['185.199.108.0/22',  'US', 'GitHub',           '🇺🇸'],
  ['199.232.0.0/16',    'US', 'Fastly',           '🇺🇸'],
  ['204.246.168.0/22',  'US', 'AWS CloudFront',   '🇺🇸'],
  ['208.65.153.0/24',   'US', 'Wikimedia',        '🇺🇸'],
  ['216.58.192.0/19',   'US', 'Google',           '🇺🇸'],
  ['216.239.32.0/19',   'US', 'Google',           '🇺🇸'],

  // ── China (CN) ────────────────────────────────────────────────────────────
  ['1.0.1.0/24',        'CN', 'China Telecom',    '🇨🇳'],
  ['1.180.0.0/14',      'CN', 'China Telecom',    '🇨🇳'],
  ['14.17.0.0/16',      'CN', 'China Telecom',    '🇨🇳'],
  ['14.18.0.0/16',      'CN', 'China Telecom',    '🇨🇳'],
  ['36.0.0.0/13',       'CN', 'China Mobile',     '🇨🇳'],
  ['42.0.0.0/13',       'CN', 'China Broadband',  '🇨🇳'],
  ['47.52.0.0/14',      'CN', 'Alibaba Cloud',    '🇨🇳'],
  ['47.88.0.0/14',      'CN', 'Alibaba Cloud',    '🇨🇳'],
  ['47.92.0.0/14',      'CN', 'Alibaba Cloud',    '🇨🇳'],
  ['47.96.0.0/14',      'CN', 'Alibaba Cloud',    '🇨🇳'],
  ['47.100.0.0/14',     'CN', 'Alibaba Cloud',    '🇨🇳'],
  ['47.104.0.0/14',     'CN', 'Alibaba Cloud',    '🇨🇳'],
  ['47.108.0.0/14',     'CN', 'Alibaba Cloud',    '🇨🇳'],
  ['49.4.0.0/14',       'CN', 'China Unicom',     '🇨🇳'],
  ['58.192.0.0/11',     'CN', 'China Telecom',    '🇨🇳'],
  ['59.32.0.0/11',      'CN', 'China Telecom',    '🇨🇳'],
  ['60.0.0.0/12',       'CN', 'China Telecom',    '🇨🇳'],
  ['61.128.0.0/12',     'CN', 'China Telecom',    '🇨🇳'],
  ['101.32.0.0/12',     'CN', 'Tencent Cloud',    '🇨🇳'],
  ['106.52.0.0/14',     'CN', 'Tencent Cloud',    '🇨🇳'],
  ['110.0.0.0/12',      'CN', 'China Telecom',    '🇨🇳'],
  ['111.0.0.0/12',      'CN', 'China Unicom',     '🇨🇳'],
  ['112.0.0.0/12',      'CN', 'China Mobile',     '🇨🇳'],
  ['113.0.0.0/12',      'CN', 'CHINANET',         '🇨🇳'],
  ['114.0.0.0/12',      'CN', 'China Telecom',    '🇨🇳'],
  ['115.0.0.0/12',      'CN', 'China Telecom',    '🇨🇳'],
  ['116.0.0.0/12',      'CN', 'China Telecom',    '🇨🇳'],
  ['117.0.0.0/12',      'CN', 'China Unicom',     '🇨🇳'],
  ['118.64.0.0/12',     'CN', 'China Telecom',    '🇨🇳'],
  ['119.0.0.0/12',      'CN', 'China Telecom',    '🇨🇳'],
  ['120.0.0.0/12',      'CN', 'China Telecom',    '🇨🇳'],
  ['121.0.0.0/12',      'CN', 'China Telecom',    '🇨🇳'],
  ['122.0.0.0/12',      'CN', 'China Broadband',  '🇨🇳'],
  ['123.0.0.0/12',      'CN', 'China',            '🇨🇳'],
  ['123.207.0.0/16',    'CN', 'Tencent Cloud',    '🇨🇳'],
  ['124.0.0.0/12',      'CN', 'China',            '🇨🇳'],
  ['125.0.0.0/12',      'CN', 'China',            '🇨🇳'],
  ['150.109.0.0/16',    'CN', 'Tencent Cloud',    '🇨🇳'],
  ['175.0.0.0/12',      'CN', 'China',            '🇨🇳'],
  ['180.0.0.0/12',      'CN', 'China Mobile',     '🇨🇳'],
  ['182.0.0.0/12',      'CN', 'China',            '🇨🇳'],
  ['183.0.0.0/12',      'CN', 'China Mobile',     '🇨🇳'],
  ['211.136.0.0/13',    'CN', 'China Mobile',     '🇨🇳'],
  ['218.0.0.0/11',      'CN', 'China Telecom',    '🇨🇳'],
  ['220.0.0.0/11',      'CN', 'China',            '🇨🇳'],
  ['221.0.0.0/11',      'CN', 'China Telecom',    '🇨🇳'],
  ['222.0.0.0/11',      'CN', 'China Telecom',    '🇨🇳'],
  ['223.0.0.0/11',      'CN', 'China Mobile',     '🇨🇳'],

  // ── Russia (RU) ───────────────────────────────────────────────────────────
  ['5.8.0.0/16',        'RU', 'Russia',           '🇷🇺'],
  ['31.173.0.0/16',     'RU', 'MTS Russia',       '🇷🇺'],
  ['37.9.0.0/16',       'RU', 'Russia',           '🇷🇺'],
  ['45.89.0.0/16',      'RU', 'Russia',           '🇷🇺'],
  ['77.37.0.0/16',      'RU', 'MegaFon',          '🇷🇺'],
  ['82.148.0.0/15',     'RU', 'Russia',           '🇷🇺'],
  ['85.140.0.0/15',     'RU', 'Russia',           '🇷🇺'],
  ['92.53.0.0/16',      'RU', 'Selectel',         '🇷🇺'],
  ['94.25.0.0/16',      'RU', 'Russia',           '🇷🇺'],
  ['178.248.0.0/14',    'RU', 'Russia',           '🇷🇺'],
  ['188.143.0.0/16',    'RU', 'Russia',           '🇷🇺'],
  ['195.93.0.0/16',     'RU', 'Russia',           '🇷🇺'],
  ['213.24.0.0/14',     'RU', 'Russia',           '🇷🇺'],
  ['217.66.0.0/16',     'RU', 'Russia',           '🇷🇺'],

  // ── North Korea (KP) ──────────────────────────────────────────────────────
  ['175.45.176.0/22',   'KP', 'North Korea',      '🇰🇵'],

  // ── Iran (IR) ─────────────────────────────────────────────────────────────
  ['2.144.0.0/12',      'IR', 'Iran',             '🇮🇷'],
  ['5.22.0.0/15',       'IR', 'Iran',             '🇮🇷'],
  ['78.38.0.0/15',      'IR', 'Iran',             '🇮🇷'],
  ['80.191.0.0/16',     'IR', 'Iran',             '🇮🇷'],
  ['185.55.224.0/22',   'IR', 'Iran',             '🇮🇷'],
]);

// Binary search — O(log n) per lookup, safe to call per-packet via cache
export function lookupCountry(ip) {
  if (!ip || ip.includes(':')) return null; // skip IPv6
  const n = ipToInt(ip);
  let lo = 0, hi = RANGES.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const [start, end] = RANGES[mid];
    if (n < start) hi = mid - 1;
    else if (n > end) lo = mid + 1;
    else return { code: RANGES[mid][2], label: RANGES[mid][3], flag: RANGES[mid][4] };
  }
  return null; // not in database
}
