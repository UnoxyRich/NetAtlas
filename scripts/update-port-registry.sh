#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp data/.iana-ports.XXXXXX)
trap 'rm -f "$tmp"' EXIT HUP INT TERM
curl --fail --location --silent --show-error \
  'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv' \
  --output "$tmp"
python3 - "$tmp" <<'PY'
import csv
import sys

with open(sys.argv[1], newline="", encoding="utf-8-sig") as source:
    reader = csv.DictReader(source)
    required = {"Service Name", "Port Number", "Transport Protocol", "Description"}
    if not required.issubset(reader.fieldnames or []):
        raise SystemExit("IANA registry has an unexpected format")
    rows = list(reader)
    if len(rows) < 10000 or not any(
        row["Service Name"] == "ssh" and row["Port Number"] == "22" and row["Transport Protocol"] == "tcp"
        for row in rows
    ):
        raise SystemExit("IANA registry failed validation")
PY
mv "$tmp" data/service-names-port-numbers.csv
printf '%s\n' 'Updated the IANA registry. Rebuild NetAtlas to embed it.'
