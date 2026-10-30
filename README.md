# Aiwos Two Factor

Frontend authenticator setup, mandatory 2FA and account recovery on top of the **upstream** [Two Factor](https://wordpress.org/plugins/two-factor/) plugin (0.17+).

Up to 1.x this package was a customized copy of Two Factor. Since 2.0 it is an add-on: install upstream `two-factor` next to it. It also replaces `aiwos/force-two-factor` and the customized fork `aiwos/two-factor` 0.13.0.2 (mijn.afk.nl). Two Factor itself is never patched again, so upstream security releases can be installed as-is.

Everything works without wp-admin and without the REST API. Our sites block both for regular users, so all forms are plain POST forms on the frontend.

## What it does

### Setup page (`/2fa/`)

- **Shortcode `[two-factor-set-totp]`.** It has the same name as the fork's shortcode, so existing `/2fa/` pages keep working.
  - A published page with slug `2fa` holding the shortcode is used when present.
  - Without one, the plugin serves a plain built-in page at `/2fa/`.
- **Linking an app.**
  - The secret is generated and kept server-side (user meta `_aiwos_two_factor_pending`) until a code from the app proves it. It never travels in a URL or form field.
  - The secret expires after 30 minutes.
  - The code must be exactly 6 digits.
- **After a valid code:**
  - TOTP is enabled and becomes the primary method.
  - The code is recorded as used, so it cannot be replayed at the next login.
  - The current session counts as a 2FA login, and all other sessions of the user are logged out.
  - The user gets a mail.
- **"Linked" means TOTP is enabled.** A secret that Two Factor kept while TOTP was switched off does not count. That user gets a fresh secret, and the old one is never reactivated.
- **Every change by a user who already has 2FA needs a recent second-factor proof:** a 2FA login or upstream revalidation within the last 20 minutes. Upstream's revalidation screen on `wp-login.php` is used, and it returns to `/2fa/`.

### Lost phone

- **Recovery codes.** The user creates 10 one-time codes on `/2fa/`.
  - They are shown once.
  - Creating new ones invalidates the old ones and sends a mail.
- **Replace authenticator app.** On `/2fa/`, with a recent proof; logging in with a recovery code counts as proof.
  - The user gets a new QR code, and the current app keeps working until the new one is proven. "Cancel" or letting it expire changes nothing.
  - **After success:**
    - the old app stops working;
    - the old recovery codes stop working (the phone may be lost), and the user can create new ones;
    - other sessions are logged out;
    - the user gets a mail.

### Staff-assisted recovery

Staff-assisted recovery is for a user who has neither the app nor a recovery code.

- **Who can do it:** users with the capability `aiwos_reset_two_factor`.
  - Users with `manage_options` get it automatically.
  - Grant it to account-manager roles explicitly: `wp cap add <role> aiwos_reset_two_factor`.
  - The staff member also needs `edit_user` on the target, a 2FA of their own and a proof of it from the last 10 minutes.
  - Nobody can reset their own 2FA here.
  - **Account managers** (no `manage_options`) can only reset accounts whose every role they may assign themselves. That is WordPress' own "who manages whom" setting (`editable_roles`). It only counts when the site actually limits it for that manager: on a site that lets everyone assign every role, managers get no reset scope at all. Capabilities given to a user individually (outside their roles) must be held by the manager too. On mijn-afk, `accountbeheer` may assign every role except administrator.
  - Accounts with admin-level rights (`manage_options`, `promote_users`, `edit_users`, or the reset capability) can only be reset by a site manager who holds those rights too. Sites add their own sensitive capabilities with the filter `aiwos/two-factor/privileged-caps`.
  - On multisite only members of the current site can be reset, never a network administrator.
  - The filter `aiwos/two-factor/can-reset` has the final say.
- **Where:** (the shortcodes must be in the page content, so the page is sent with no-cache headers)
  - wp-admin: "Reset two-factor" on Users opens a confirmation screen.
  - Without wp-admin: the shortcode `[two-factor-staff-reset]` on a page that only account managers can open.
  - Both submit by POST and require a written note on how the identity was verified.
- **What happens, in this order** (under a per-account database lock, so a reset, a link being used and an app being linked never interleave):
  1. The account is put in recovery. If that cannot be stored, nothing else happens.
  2. All sessions and application passwords of the user are revoked.
  3. Their 2FA data, recovery codes and pending login challenges are cleared. This works with any provider switched off.
  4. The hook `aiwos/two-factor/recovery-started` (target, actor, note) fires for the audit trail, and the start and completion are written to the server error log (user IDs only).
  5. A one-time link, valid for 24 hours, is mailed to the account's **existing** address.
  6. When the password may be compromised, the staff member ticks that box: a standard password reset mail is sent too, and the recovery link only works after the password was reset through WordPress' "lost password" flow (a hash upgrade at login does not count). Resetting it to the same password is refused.
- **Only a forgotten password:** the second button sends just the standard password reset mail and leaves 2FA as it is.
- **No other way to change someone else's 2FA:** upstream's own REST endpoints, settings actions and profile screen are limited to the user's own account. Staff never see or set another user's secret or recovery codes.
- **The password alone is not enough.**
  - While the account is in recovery, the user can log in with the password but cannot link an app until they open the mailed link. The condition filter cannot exempt an account in recovery.
  - Opening the link only shows a "Continue" button; the link is used by that POST, so mail scanners cannot use it. The page is sent with `Referrer-Policy: no-referrer`, so the token is not passed on. When the user is logged out, the link leads to the login screen without the token in the URL, and they open it again after logging in.
  - The link is stored only as a keyed hash, works once (also when two requests race), and is bound to the session that uses it. Each recovery has its own id: a link from an earlier recovery never unlocks a later one.
  - After the app is linked, the recovery ends and the user gets a mail.
- **Not automated, on purpose.** Staff verify the identity through a known contact channel, for example a call-back on a number already on file. A request from a new e-mail address is not proof. Changing the account's e-mail address is a separate process.
- **For DUS-I:** `Staff_Reset::start_recovery( $target, $note, $password_reset )` holds all checks and is the entry point for a future Gravity Flow step.

### Forgotten password

Users reset their password with WordPress' standard "Lost your password?" on `wp-login.php`, which this plugin never blocks.

- A password reset does not touch 2FA. The next login still needs the app or a recovery code.
- The new password invalidates all existing login cookies.

### Enforcement

Users who must use 2FA are those for whom `aiwos/force-two-factor/force-2fa-condition` is not `false`. Administrators are not exempt.

**Users who must use 2FA but have none:**

| Request | Result |
|---|---|
| Frontend GET | Redirect to `/2fa/` (checked on `wp_loaded`, before plugins handle the request) |
| Frontend POST | `403`; on `/2fa/` only this plugin's own forms are handled, before any other plugin sees the request |
| wp-admin | Redirect to `/2fa/` |
| admin-ajax, admin-post | `403` |
| REST API | `403` |
| XML-RPC login | Refused |

`wp-login.php` stays open for login, logout, lost password and revalidation. Handlers that run on `init` are not gated, because sites register their exemption filters there.

Only a plain request for the setup page counts: other query variables (`?p=`, `?s=`, ...) on `/2fa/` are redirected like any other page. Users who only need to revalidate cannot POST anything, also not on `/2fa/`; they confirm their code first.

The guard runs again on `parse_request`, when WordPress knows what it will serve, so a URL that only looks like REST (`?rest_route=0`) cannot skip it.

**Users with 2FA whose browser session was not opened with it** (for example a session from before 2FA was set up) are sent to upstream's revalidation first. REST and AJAX requests from such a session get `403`. A logged-in request without a session cookie fails closed; application passwords follow upstream's API-login policy.

Which methods count as a second factor is decided by upstream Two Factor and the site's provider settings (app, email codes, recovery codes, SMS where installed). Any enabled method counts as proof for changes. Sites decide which methods to enable.

## Hooks

| Hook | Type | Purpose |
|---|---|---|
| `aiwos/force-two-factor/force-2fa-condition` | filter | Return `false` to exempt the user from mandatory 2FA. Second argument: the `WP_User`. |
| `aiwos/two-factor/notify-user` | filter | Return `false` to stop informational mails. Recovery link mails are always sent. |
| `aiwos/two-factor/can-reset` | filter | Final say on a staff reset: `( bool, WP_User $target, WP_User $actor )`. |
| `aiwos/two-factor/privileged-caps` | filter | Capabilities that make an account privileged for staff resets. |
| `aiwos/two-factor/recovery-started` | action | Audit trail: `( WP_User $target, WP_User $actor, string $note )`. No secrets are passed. |

Mail failures show up through WordPress' `wp_mail_failed` (logged by aiwos-logger). The staff screen also says so when the recovery link could not be sent.

## Migrating a site (runbook)

1. **Back up and record the current state.** Record package versions, provider settings and active plugins. The backup contains 2FA secrets, so store it like a password.
2. **Inventory unusual states on a local copy, never on production:**
   - stored TOTP secrets with TOTP switched off;
   - custom providers (SMS);
   - users with only recovery codes, or a mix of methods;
   - `Two_Factor_Dummy` (exists only with `WP_DEBUG`; on production those users fall back to email codes);
   - site-specific exemptions on the condition filter.
3. **Replace the fork through Composer or a deploy.**
   - Require upstream `two-factor` (0.17+) and `aiwos/aiwos-two-factor` `^2.0`.
   - Keep the plugin path `two-factor`, and never have two copies of Two Factor loaded at once.
   - **Never use "Delete" or `wp plugin uninstall` on Two Factor or the fork.** Their uninstall routine deletes all 2FA data of all users.
4. **Activate `aiwos-two-factor` explicitly, then remove `aiwos/force-two-factor`.**
5. **Verify with real requests, not by the absence of an admin notice.** An inactive plugin cannot show its notice. A user without 2FA must land on `/2fa/` and get `403` from admin-ajax.
6. **Log everyone out once:** `wp user session destroy --all`.
   - Sessions opened with the fork already count as 2FA sessions, so this is a precaution, not a requirement.
   - Review application passwords separately.
7. **Test, as in the browser test:**
   - existing app logins;
   - linking an app;
   - recovery codes;
   - replacing the app;
   - a staff reset with the recovery link;
   - mails arriving;
   - refused direct requests.

Prefer a forward fix to a rollback. Restoring an old database snapshot can bring back used recovery codes, revoked sessions and replaced secrets.

## Tests

Run from a **local** host site where upstream Two Factor and this plugin are active.

```bash
# Live-WordPress checks, including runs with providers switched off site-wide.
# Creates and removes throwaway users; mails are captured, not sent.
web/app/plugins/aiwos-two-factor/tests/run.sh

# Real HTTP checks of the enforcement boundary (curl; creates and removes a throwaway user)
BASE_URL=https://<site>.ddev.site WP="ddev wp" WP_DIR=/wp tests/http.sh

# CI runs tests/run.sh and tests/http.sh against a clean WordPress (@wordpress/env, see .wp-env.json).

# Browser test (see the header of the file for the throwaway accounts it needs)
NODE_PATH=/www/e2e/node_modules BASE_URL=https://<site>.ddev.site E2E_USER=... node tests/e2e-enrollment.cjs
```
