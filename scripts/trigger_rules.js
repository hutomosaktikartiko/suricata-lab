/* 
  Node.js script for triggering Suricata rules.
  Target default: http://localhost:8080
  Can be changed via env BASE_URL, example:
    BASE_URL=http://127.0.0.1:8080 node scripts/trigger_rules.js
*/

const http = require('http');
const { URL } = require('url');

const BASE_URL = process.env.BASE_URL || 'http://localhost:8080';
const base = new URL(BASE_URL.endsWith('/') ? BASE_URL.slice(0, -1) : BASE_URL);

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function httpGet(pathname, { headers = {} } = {}) {
  const url = new URL(pathname, base);
  const options = {
    hostname: url.hostname,
    port: url.port || 80,
    path: url.pathname + (url.search || ''),
    method: 'GET',
    headers: {
      'Host': base.hostname + (base.port ? `:${base.port}` : ''),
      'Connection': 'close',
      ...headers,
    },
  };
  return new Promise((resolve) => {
      const req = http.request(options, (res) => {
        // Consume data to close the connection cleanly
      res.on('data', () => {});
      res.on('end', () => resolve({ statusCode: res.statusCode }));
    });
    req.on('error', () => resolve({ statusCode: 0 }));
    req.end();
  });
}

async function triggerSqli() {
  console.log('== SQLi tautology: "\' or 1=1" (sid:100010)');
  const q1 = encodeURIComponent(`' or 1=1--`);
  await httpGet(`/?q=${q1}`);

  console.log('== SQLi UNION SELECT (sid:100011) — use "unionselect" to match distance:0');
  const q2 = 'unionselect%201,2,3';
  await httpGet(`/?q=${q2}`);
}

async function triggerXss() {
  console.log('== XSS <script> (sid:100020)');
  const q1 = encodeURIComponent('<script>alert(1)</script>');
  await httpGet(`/?q=${q1}`);

  console.log('== XSS javascript: URI (sid:100021)');
  const q2 = encodeURIComponent('javascript:alert(1)');
  await httpGet(`/?q=${q2}`);
}

async function triggerCmdi() {
  console.log('== CMDi ;curl (sid:100030) — no space after ; to satisfy distance:0');
  const q1 = encodeURIComponent(';curl http://example.com');
  await httpGet(`/?q=${q1}`);

  console.log('== CMDi ;wget (sid:100031) — no space after ; to satisfy distance:0');
  const q2 = encodeURIComponent(';wget http://example.com/file');
  await httpGet(`/?q=${q2}`);

  console.log('== CMDi && operator (sid:100032)');
  const q3 = encodeURIComponent('test&&id');
  await httpGet(`/?q=${q3}`);
}

async function triggerLfi() {
  console.log('== LFI ../../etc/passwd (sid:100040)');
  const q = encodeURIComponent('../../../../../../../../etc/passwd');
  await httpGet(`/?file=${q}`);
}

async function triggerAdmin() {
  console.log('== Admin endpoint /admin (sid:100050)');
  await httpGet('/admin');
}

async function triggerScannerUA() {
  console.log('== Scanner UA sqlmap (sid:100060)');
  await httpGet('/', { headers: { 'User-Agent': 'sqlmap/1.7' } });

  console.log('== Scanner UA nikto (sid:100061)');
  await httpGet('/', { headers: { 'User-Agent': 'Nikto/2.5.0' } });

  console.log('== Scanner UA nmap (sid:100062)');
  await httpGet('/', { headers: { 'User-Agent': 'nmap script' } });

  console.log('== Scanner UA gobuster (sid:100063)');
  await httpGet('/', { headers: { 'User-Agent': 'gobuster' } });

  console.log('== Scanner UA dirbuster (sid:100064)');
  await httpGet('/', { headers: { 'User-Agent': 'dirbuster' } });
}

async function triggerBruteForceThreshold() {
  console.log('== Burst 22 requests for threshold (sid:100070)');
  const requests = [];
  for (let i = 1; i <= 22; i += 1) {
    requests.push(httpGet(`/ping${i}`));
  }
  await Promise.all(requests);
}

async function triggerLongUri() {
  console.log('== Long URI > 2048 chars (sid:100080)');
  const long = 'A'.repeat(2501);
  await httpGet(`/?q=${long}`);
}

async function triggerGenericGet() {
  console.log('== Generic GET for GET rule (sid:100001)');
  await httpGet('/');
}

async function main() {
  console.log(`Base URL: ${base.href}`);
  await triggerGenericGet();

  await triggerSqli();
  await triggerXss();
  await triggerCmdi();
  await triggerLfi();
  await triggerAdmin();
  await triggerScannerUA();

  // give a little bit of delay before burst
  await sleep(250);
  await triggerBruteForceThreshold();

  await sleep(250);
  await triggerLongUri();

  console.log('Done triggering test traffic.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

