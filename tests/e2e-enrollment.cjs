/**
 * Browser test: forced redirect to /2fa/, TOTP enrollment, and 2FA on the next login.
 *
 * Usage (local DDEV only, throwaway user without 2FA):
 *   NODE_PATH=/www/e2e/node_modules BASE_URL=https://<site>.ddev.site \
 *   E2E_USER=<login> E2E_PASS=<password> node tests/e2e-enrollment.cjs
 */
const { chromium } = require('playwright');
const crypto = require('node:crypto');

const { BASE_URL, E2E_USER, E2E_PASS } = process.env;
const LOGIN_URL = `${BASE_URL}/wp/wp-login.php`;

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of input.replace(/=+$/, '').toUpperCase()) {
    bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  }
  const bytes = bits.match(/.{8}/g).map((b) => parseInt(b, 2));
  return Buffer.from(bytes);
}

function totp(secret, offsetSteps = 0) {
  // 8-byte big-endian time-step counter (RFC 6238).
  const step = Math.floor(Date.now() / 30000) + offsetSteps;
  const counter = Buffer.alloc(8);
  counter.writeUInt32BE(Math.floor(step / 2 ** 32), 0);
  counter.writeUInt32BE(step % 2 ** 32, 4);
  const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
  return String(code).padStart(6, '0');
}

function check(name, ok) {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`);
  if (!ok) process.exitCode = 1;
}

async function login(page) {
  await page.goto(`${LOGIN_URL}?redirect_to=${encodeURIComponent(`${BASE_URL}/`)}`);
  await page.fill('#user_login', E2E_USER);
  await page.fill('#user_pass', E2E_PASS);
  await page.click('#wp-submit');
  await page.waitForLoadState('domcontentloaded');
}

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();

  await login(page);
  await page.goto(`${BASE_URL}/`);
  check('unenrolled user is redirected to /2fa/', new URL(page.url()).pathname === '/2fa/');

  const setup = await page.goto(`${BASE_URL}/2fa/?utm=x`);
  check('setup page with query string does not loop', new URL(page.url()).pathname === '/2fa/');
  check('setup page is not cacheable', /no-store|no-cache/.test(setup.headers()['cache-control'] || ''));

  const form = page.locator('form.aiwos-two-factor[method="post"]');
  check('POST setup form is shown', (await form.count()) === 1);
  await page.waitForSelector('#two-factor-qr-code svg', { timeout: 10000 }).catch(() => {});
  check('QR code is drawn', (await page.locator('#two-factor-qr-code svg').count()) === 1);
  const secret = (await form.locator('code').innerText()).trim();

  await page.fill('#aiwos-two-factor-authcode', totp(secret));
  const [response] = await Promise.all([
    page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/2fa/')),
    form.locator('button[type="submit"]').click(),
  ]);
  const location = response.headers().location || '';
  check('POST answers with a redirect', response.status() === 302 || response.status() === 303);
  check('redirect carries status only, no secret', location.includes('aiwos-2fa=enrolled') && !location.includes(secret));
  check('POST body has no secret', !(response.request().postData() || '').includes(secret));
  await page.waitForLoadState('domcontentloaded');
  check('success message shown', (await page.locator('.feedback-success').count()) === 1);

  // Recovery codes for a lost phone: shown once, right after creating them.
  await page.locator('form.aiwos-two-factor__recovery button[type="submit"]').click();
  await page.waitForSelector('.aiwos-two-factor__codes', { timeout: 10000 }).catch(() => {});
  const recoveryCodes = await page.locator('.aiwos-two-factor__codes code').allInnerTexts();
  check('ten recovery codes shown', recoveryCodes.length === 10);
  await page.goto(`${BASE_URL}/2fa/`);
  check('recovery codes not shown again on a later visit', (await page.locator('.aiwos-two-factor__codes').count()) === 0);

  await page.goto(`${BASE_URL}/`);
  check('enrolled user is no longer redirected', new URL(page.url()).pathname !== '/2fa/');

  // Fresh browser: password alone must not be enough any more.
  const second = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
  await login(second);
  const authcode = second.locator('#authcode');
  check('next login asks for the authenticator code', (await authcode.count()) === 1);
  // Next time step: upstream rejects reuse of the code that was just used for enrollment.
  await second.waitForTimeout(31000);
  await authcode.fill(totp(secret));
  // Upstream's login script submits by itself once six digits are entered.
  await second.waitForURL((url) => !url.pathname.endsWith('wp-login.php'), { timeout: 15000 }).catch(() => second.click('#submit'));
  await second.goto(`${BASE_URL}/`);
  const loggedIn = await second.evaluate(() => document.body.classList.contains('logged-in'));
  check('login with authenticator code succeeds', loggedIn && new URL(second.url()).pathname !== '/2fa/');


  // Lost phone: log in with a recovery code instead of the app.
  const loginWithRecoveryCode = async (code) => {
    const p = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
    await login(p);
    await p.locator('.backup-methods-wrap a[href*="provider=Two_Factor_Backup_Codes"]').click();
    await p.waitForLoadState('domcontentloaded');
    if (process.env.DEBUG) console.log('recovery page:', p.url(), await p.locator('#authcode').getAttribute('name').catch(() => 'no #authcode'));
    await p.fill('#authcode', code);
    await p.waitForURL((url) => !url.pathname.endsWith('wp-login.php'), { timeout: 10000 }).catch(() => p.click('#submit').catch(() => {}));
    await p.waitForLoadState('domcontentloaded');
    if (process.env.DEBUG) console.log('after:', p.url(), (await p.locator('#login_error').allInnerTexts()).join('|'));
    return !new URL(p.url()).pathname.endsWith('wp-login.php');
  };
  check('login with a recovery code succeeds', await loginWithRecoveryCode(recoveryCodes[0]));
  check('a used recovery code is refused', !(await loginWithRecoveryCode(recoveryCodes[0])));

  await browser.close();
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
