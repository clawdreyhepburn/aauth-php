# Publishing to Packagist

This is a one-time setup. After it's done, every git tag pushed to `main`
becomes an installable Composer version automatically.

## What's already ready

- `composer.json` validates with `composer validate --strict` ✓
- PSR-4 autoload tested end-to-end with `composer require` from a path
  repository (see this directory for the smoke test we ran) ✓
- Apache 2.0 LICENSE file at repo root ✓
- README, CHANGELOG, SECURITY.md all in place ✓
- v0.1.0 git tag pushed ✓

## Submit the package (Sarah, ~2 minutes)

1. Sign in at <https://packagist.org/login/> with the account that owns
   `@clawdreyhepburn` GitHub. (If there isn't one yet, create it.)
2. Go to <https://packagist.org/packages/submit>.
3. Paste `https://github.com/clawdreyhepburn/aauth-php` and click *Check*,
   then *Submit*.
4. Packagist will fetch `composer.json` and create the package page at
   `https://packagist.org/packages/clawdreyhepburn/aauth-php`.

## Wire up auto-update (one-time)

By default, Packagist re-crawls a package once a day. For tag-equals-release
behavior, install the GitHub service hook:

1. On the new Packagist package page, click the *Settings* tab.
2. Copy the *API token* shown there.
3. In the GitHub repo, go to *Settings → Webhooks → Add webhook*.
4. Use:
   - Payload URL: `https://packagist.org/api/github?username=<your-packagist-username>&apiToken=<token>`
   - Content type: `application/json`
   - Events: *Just the push event*
5. Save. From then on, every push (and every tag push) tells Packagist to
   re-crawl, so a new tag is installable within seconds.

## Verify the install path

Once the package page is live and v0.1.0 is listed:

```bash
mkdir /tmp/packagist-smoke && cd /tmp/packagist-smoke
composer init --name=test/test --require="clawdreyhepburn/aauth-php:^0.1" -n
composer install --no-progress
php -r 'require "vendor/autoload.php"; echo class_exists("Clawdrey\\\\AAuth\\\\RequestVerifier") ? "ok\n" : "FAIL\n";'
```

Expected output: `ok`.

## Future releases

Cutting a new release after this is one command from the repo root:

```bash
git tag -a v0.2.0 -m "v0.2.0 — <one-line summary>"
git push origin v0.2.0
gh release create v0.2.0 --title "v0.2.0 — <title>" \
    --notes-file docs/release-notes/v0.2.0.md \
    dist/aauth-bundle.php
```

Packagist picks up the new tag via the webhook within a few seconds.
