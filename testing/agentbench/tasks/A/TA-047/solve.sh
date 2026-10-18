#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/crawl; sleep 120' || true
until ssh bench '~/bin/crawl'; do sleep 1; done
