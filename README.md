# Aiwos Two Factor

Frontend TOTP enrollment and mandatory 2FA on top of the **upstream** [Two Factor](https://wordpress.org/plugins/two-factor/) plugin (0.17+).

Up to 1.x this package was a customized copy of Two Factor. Since 2.0 it is an add-on: install upstream `two-factor` next to it. It also replaces `aiwos/force-two-factor` and the customized fork `aiwos/two-factor` 0.13.0.2 (mijn.afk.nl). With this add-on Two Factor itself is never patched again, so upstream security releases can be installed as-is.

## What it does

- **Shortcode `[two-factor-set-totp]`** (same name as the fork, so existing `/2fa/` pages keep working). It shows a QR code, the secret and a code field.
  - The form uses a plain POST to the same page. The secret is generated and kept server-side (user meta `_aiwos_two_factor_pending_key`) until the user proves a code, so it never travels in a URL or form field.
  - After a valid code:
    - TOTP is enabled and set as primary.
    - The current session counts as a 2FA login.
    - All other sessions of that user are logged out.
    - The code is recorded as used, so it cannot be replayed at the next login.
  - Users who already have TOTP see a confirmation and no form.
  - Users on another method (e.g. email codes) must first confirm a current code (upstream revalidation).
- **Mandatory 2FA.** Logged-in users without 2FA are redirected from any frontend page to `/2fa/`.
  - It honours the existing filter `aiwos/force-two-factor/force-2fa-condition`, so site plugins that exempt users keep working.
  - Administrators are not exempt.
- **`/2fa/` always exists.** A published page with slug `2fa` holding the shortcode is used when present, so a site can add its own text and layout. Without such a page the plugin serves a plain built-in page.
- **Lost phone.**
  - *Recovery codes.* After linking the app, users can create 10 one-time recovery codes on `/2fa/`.
    - The codes are shown once.
    - At login, "Use a recovery code" lets them in without the app.
    - On `/2fa/` they can then link a new app.
  - *Staff reset.* Anyone who may edit the user sees "Reset two-factor" in the user's row on Users.
    - It removes the app link and the recovery codes, and logs the user out everywhere.
    - At the next login the user signs in with the password only and is sent to `/2fa/` to link a new app.
- **Notification mails.** The user gets a mail when an app is linked to their account and when an admin resets their 2FA, so a misuse is noticed. Disable with the filter `aiwos/two-factor/notify-user` (return `false`).

### Why not upstream's REST/JS setup screen

Our sites block the REST API for non-admins (`aiwos-access`, `aiwos-default` "secure endpoints"). Upstream's setup UI saves through `/wp-json/two-factor/1.0/totp`, so it fails there. That is also why the old fork saved through a (GET) form.

### Why a separate plugin and not an aiwos-default option

- **DUS-I fit:** the DUS-I sites that force 2FA (portal, portal2, co) don't run aiwos-default.
- **Tick risk:** a settings tick would let any admin switch mandatory 2FA off.
- **Module pattern:** aiwos-default modules have no frontend routes or tests.
- **Release cadence:** security fixes here need their own release cycle.

## Filters

| Filter | Default | Purpose |
|---|---|---|
| `aiwos/force-two-factor/force-2fa-condition` | `true` | Return `false` to skip the redirect. Second argument: the `WP_User`. |
| `aiwos/two-factor/notify-user` | `true` | Return `false` to stop the notification mails. Second argument: the `WP_User`. |

A published page with slug `2fa` must hold the shortcode; otherwise unpublish it and the built-in page is used.

## Migrating a site

1. Require upstream `two-factor` (0.17+) and `aiwos/aiwos-two-factor` `^2.0`, instead of `aiwos/two-factor` or `aiwos/aiwos-two-factor` `^1.0`.
2. Remove `aiwos/force-two-factor`.
3. Do 1 and 2 in the same deploy. The add-on stays inactive (admin notice only) while the old fork is installed, so removing `force-two-factor` first leaves 2FA unenforced. After the deploy, check that the admin notice is gone.

Existing TOTP links keep working, because the fork already used upstream's meta keys.

Note: upstream only registers `Two_Factor_Dummy` when `WP_DEBUG` is on. Users whose stored method is Dummy fall back to email codes on production.

## Tests

Run from a host site where upstream Two Factor and this plugin are active.

```bash
# Checks against live WordPress (creates and removes throwaway users)
ddev wp eval-file web/app/plugins/aiwos-two-factor/tests/run.php

# Browser flow: redirect, enrollment, recovery codes, next login asks for the code,
# login with a recovery code.
# Needs a throwaway user without 2FA.
NODE_PATH=/www/e2e/node_modules BASE_URL=https://<site>.ddev.site \
  E2E_USER=<login> E2E_PASS=<password> node tests/e2e-enrollment.cjs
```
