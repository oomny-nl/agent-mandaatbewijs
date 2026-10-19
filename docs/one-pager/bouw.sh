#!/usr/bin/env bash
# Bouwt de one-pagers (A4-PDF) uit de Markdown-bronnen. Vereist: pandoc en weasyprint.
set -euo pipefail
cd "$(dirname "$0")"
for taal in nl en; do
  pandoc "one-pager.$taal.md" --standalone --css stijl.css -o "one-pager.$taal.html"
  weasyprint --base-url . "one-pager.$taal.html" "one-pager.$taal.pdf"
  rm "one-pager.$taal.html"
done
