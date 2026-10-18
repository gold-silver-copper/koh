#!/usr/bin/env bash
set -euo pipefail
ssh bench '~/bin/store-note meeting-2026-10' < notes.txt
