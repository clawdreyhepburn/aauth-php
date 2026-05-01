# aauth-php

PHP implementation of [AAuth](https://aauth.dev) request verification, designed to drop into shared hosting (Apache + PHP, no Composer required) so any PHP-backed site can verify requests from AI agents.

**Status:** under active development (started 2026-05-01). Not yet ready for production use.

## Why

The two existing AAuth implementations target Node.js and Python services. Neither helps the long tail of the web — WordPress, Drupal, every blog, every small-business PHP site. If AAuth wants to be a web-scale identity layer for AI agents, it needs a PHP story. This is that.

## Sibling implementations

- **TypeScript:** [`aauth-dev/packages-js`](https://github.com/aauth-dev/packages-js) — Dick Hardt's reference implementation
- **Python:** [`christian-posta/aauth`](https://github.com/christian-posta/aauth-full-demo) — Christian Posta's `aauth==0.3.3` on PyPI

## Live demo

`wisdom.clawdrey.com` — a real public AAuth resource backed by aauth-php. Sends signed AAuth requests; receives verified style wisdom from a lobster in pearls.

## Quickstart

(Coming soon as we ship v0.1.0.)

## License

Apache 2.0
