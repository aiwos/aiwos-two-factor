/**
 * Browser tests on a local site (never production). Throwaway accounts, prepared by the caller:
 *   USER    regular user without 2FA            (E2E_USER / E2E_PASS)
 *   STAFF   account manager with an app linked  (STAFF_USER / STAFF_PASS / STAFF_SECRET),
 *           holding aiwos_reset_two_factor; STAFF_PAGE = path of a page with [two-factor-staff-reset]
 *   TARGET  regular user with an app linked      (TARGET_USER / TARGET_PASS / TARGET_EMAIL)
 *   MAILPIT_URL  local Mailpit, e.g. https://<site>.ddev.site:8026
 *
 *   NODE_PATH=/www/e2e/node_modules BASE_URL=https://<site>.ddev.site ... node tests/e2e-enrollment.cjs
 */
const { chromium, request } = require('playwright');
const crypto = require('node:crypto');

const env = process.env;
const BASE_URL = env.BASE_URL;
const LOGIN_URL = `${BASE_URL}/wp/wp-login.php`;

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of input.replace(/=+$/, '').toUpperCase()) {
    bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  }
  return Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
}

function totp(secret, offsetSteps = 0) {
  // 8-byte big-endian time-step counter (RFC 6238).
  const step = Math.floor(Date.now() / 30000) + offsetSteps;
  const counter = Buffer.alloc(8);
  counter.writeUInt32BE(Math.floor(step / 2 ** 32), 0);
  counter.writeUInt32BE(step % 2 ** 32, 4);
  const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(counter).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  return String((hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
}

// A code from a fresh 30 s window: never reuses a used step, never expires while typing.
async function freshTotp(secret) {
  const step = () => Math.floor(Date.now() / 30000);
  const start = step();
  while (step() === start) await new Promise((r) => setTimeout(r, 500));
  return totp(secret);
}

let failures = 0;
function check(name, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${ok || !detail ? '' : ` -- ${detail}`}`);
  if (!ok) failures++;
}

const path = (page) => new URL(page.url()).pathname;

async function login(browser, user, pass) {
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
  await page.goto(`${LOGIN_URL}?redirect_to=${encodeURIComponent(`${BASE_URL}/`)}`);
  await page.fill('#user_login', user);
  await page.fill('#user_pass', pass);
  await Promise.all([page.waitForNavigation({ waitUntil: 'domcontentloaded' }), page.click('#wp-submit')]);
  return page;
}

// Second login step; upstream's script submits by itself after the last digit.
async function secondFactor(page, code) {
  if (!(await page.waitForSelector('#authcode', { timeout: 15000 }).then(() => true, () => false))) {
    console.log(`  (no code field at ${page.url()}: ${(await page.locator('#login_error').allInnerTexts()).join(' ')})`);
    return null;
  }
  // Upstream clears the field 200 ms after load; fill after that.
  await page.waitForTimeout(400);
  await page.fill('#authcode', code);
  await page.waitForURL((url) => !url.pathname.endsWith('wp-login.php'), { timeout: 10000 }).catch(() => page.click('#submit').catch(() => {}));
  await page.waitForLoadState('domcontentloaded');
  return !path(page).endsWith('wp-login.php');
}

async function submit(page, formSelector) {
  await Promise.all([page.waitForLoadState('domcontentloaded'), page.locator(`${formSelector} button[type="submit"]`).click()]);
  await page.waitForLoadState('domcontentloaded');
}

async function enrollOnPage(page) {
  const form = page.locator('form.aiwos-two-factor[method="post"]');
  const secret = (await form.locator('code').innerText()).trim();
  await page.fill('#aiwos-two-factor-authcode', await freshTotp(secret));
  const [response] = await Promise.all([
    page.waitForResponse((r) => r.request().method() === 'POST' && r.url().includes('/2fa/')),
    form.locator('button[type="submit"]').click(),
  ]);
  await page.waitForLoadState('domcontentloaded');
  return { secret, response };
}

async function userScenario(browser) {
  const page = await login(browser, env.E2E_USER, env.E2E_PASS);
  await page.goto(`${BASE_URL}/`);
  check('user without 2FA is sent to /2fa/', path(page) === '/2fa/');
  const admin = await page.goto(`${BASE_URL}/wp/wp-admin/`);
  check('wp-admin sends user without 2FA to /2fa/ (or is blocked)', path(page) === '/2fa/' || admin.status() >= 400, page.url());
  const ajax = await page.request.post(`${BASE_URL}/wp/wp-admin/admin-ajax.php`, { form: { action: 'heartbeat' } });
  check('admin-ajax refused for user without 2FA', ajax.status() === 403, String(ajax.status()));
  const post = await page.request.post(`${BASE_URL}/`, { form: { probe: '1' }, maxRedirects: 0 });
  check('frontend POST refused for user without 2FA', post.status() === 403, String(post.status()));
  const rest = await page.request.get(`${BASE_URL}/wp-json/wp/v2/users/me`);
  check('REST refused for user without 2FA', rest.status() === 401 || rest.status() === 403, String(rest.status()));

  const setup = await page.goto(`${BASE_URL}/2fa/?utm=x`);
  check('setup page with query string does not loop', path(page) === '/2fa/');
  check('setup page is not cacheable', /no-store|no-cache/.test(setup.headers()['cache-control'] || ''));
  await page.waitForSelector('#two-factor-qr-code svg', { timeout: 10000 }).catch(() => {});
  check('QR code is drawn', (await page.locator('#two-factor-qr-code svg').count()) === 1);

  const { secret, response } = await enrollOnPage(page);
  const location = response.headers().location || '';
  check('enrollment answers with a redirect carrying only a status', [302, 303].includes(response.status()) && location.includes('aiwos-2fa=enrolled') && !location.includes(secret));
  check('secret not in the POST body', !(response.request().postData() || '').includes(secret));

  await submit(page, 'form.aiwos-two-factor__recovery_codes');
  const codes = await page.locator('.aiwos-two-factor__codes code').allInnerTexts();
  check('ten recovery codes shown', codes.length === 10, String(codes.length));
  await page.goto(`${BASE_URL}/2fa/`);
  check('recovery codes not shown again', (await page.locator('.aiwos-two-factor__codes').count()) === 0);

  const second = await login(browser, env.E2E_USER, env.E2E_PASS);
  check('next login asks for the code', await second.waitForSelector('#authcode', { timeout: 10000 }).then(() => true, () => false));
  check('login with the app succeeds', await secondFactor(second, await freshTotp(secret)));

  // Lost phone: recovery code, then replace the app on the frontend.
  const lost = await login(browser, env.E2E_USER, env.E2E_PASS);
  await lost.locator('.backup-methods-wrap a[href*="provider=Two_Factor_Backup_Codes"]').click();
  await lost.waitForLoadState('domcontentloaded');
  check('login with a recovery code succeeds', await secondFactor(lost, codes[0]));
  await lost.goto(`${BASE_URL}/2fa/`);
  await submit(lost, 'form.aiwos-two-factor__replace');
  check('replace shows a new QR code with cancel', (await lost.locator('#aiwos-two-factor-authcode').count()) === 1 && (await lost.locator('form.aiwos-two-factor__cancel').count()) === 1);
  const replaced = await enrollOnPage(lost);
  check('new app replaces the old one', (replaced.response.headers().location || '').includes('aiwos-2fa=replaced'));

  const again = await login(browser, env.E2E_USER, env.E2E_PASS);
  check('old app is refused', (await secondFactor(again, await freshTotp(secret))) === false);
  const fresh = await login(browser, env.E2E_USER, env.E2E_PASS);
  check('new app works', await secondFactor(fresh, await freshTotp(replaced.secret)));
  const used = await login(browser, env.E2E_USER, env.E2E_PASS);
  await used.locator('.backup-methods-wrap a[href*="provider=Two_Factor_Backup_Codes"]').click({ timeout: 3000 }).catch(() => {});
  await used.waitForLoadState('domcontentloaded');
  check('old recovery codes no longer work', (await used.locator('.backup-methods-wrap a[href*="Two_Factor_Backup_Codes"]').count()) === 0 && (await secondFactor(used, codes[1])) === false);
}

async function staffScenario(browser) {
  const staff = await login(browser, env.STAFF_USER, env.STAFF_PASS);
  check('staff logs in with app', await secondFactor(staff, await freshTotp(env.STAFF_SECRET)));
  await staff.goto(`${BASE_URL}${env.STAFF_PAGE}`);
  await staff.fill('#aiwos-two-factor-staff-account', env.TARGET_EMAIL);
  await staff.fill('#aiwos-two-factor-staff-reason', 'e2e: identity verified by call-back');
  await submit(staff, 'form.aiwos-two-factor-staff');
  check('staff reset started', staff.url().includes('aiwos-2fa-staff=started'), staff.url());

  // The password alone must not be enough to link a new app.
  const target = await login(browser, env.TARGET_USER, env.TARGET_PASS);
  await target.goto(`${BASE_URL}/`);
  check('reset user is sent to /2fa/', path(target) === '/2fa/');
  check('password alone shows no setup form', (await target.locator('#aiwos-two-factor-authcode').count()) === 0);

  const mail = await request.newContext({ ignoreHTTPSErrors: true });
  const search = await (await mail.get(`${env.MAILPIT_URL}/api/v1/search?query=${encodeURIComponent(`to:${env.TARGET_EMAIL}`)}`)).json();
  const message = search.messages && search.messages[0] ? await (await mail.get(`${env.MAILPIT_URL}/api/v1/message/${search.messages[0].ID}`)).json() : {};
  const link = ((message.Text || '').match(/https?:\/\/\S*aiwos-recovery=[0-9a-f]{64}/) || [])[0];
  check('recovery link mailed', Boolean(link));
  if (!link) return;

  // Logged out: to the login screen without the token in the URL.
  const anon = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();
  await anon.goto(link);
  check('logged-out link opens login without the token', anon.url().includes('wp-login.php') && !anon.url().includes('aiwos-recovery'), anon.url());

  await target.goto(link);
  check('link shows a confirm button (no change on GET)', (await target.locator('form.aiwos-two-factor__redeem').count()) === 1 && (await target.locator('#aiwos-two-factor-authcode').count()) === 0);
  await submit(target, 'form.aiwos-two-factor__redeem');
  check('link accepted, token gone from the address bar', target.url().includes('aiwos-2fa=recovery_ok') && !target.url().includes('aiwos-recovery='), target.url());
  const { secret, response } = await enrollOnPage(target);
  check('new app linked after recovery', (response.headers().location || '').includes('aiwos-2fa=enrolled'));
  const reuse = await login(browser, env.TARGET_USER, env.TARGET_PASS);
  check('target logs in with the new app', await secondFactor(reuse, await freshTotp(secret)));
  await reuse.goto(link);
  check('used link offers nothing', (await reuse.locator('form.aiwos-two-factor__redeem').count()) === 0 && (await reuse.locator('#aiwos-two-factor-authcode').count()) === 0);
}

(async () => {
  const browser = await chromium.launch();
  try {
    await userScenario(browser);
    if (env.STAFF_USER) await staffScenario(browser);
  } catch (error) {
    check('no unexpected error', false, error.message.split('\n')[0]);
  } finally {
    await browser.close();
  }
  console.log(`\n${failures} failed`);
  process.exit(failures ? 1 : 0);
})();
