#!/usr/bin/env bash
#
# make-public-snapshot.sh — produce a CLEAN-HISTORY public snapshot of this repo.
#
# Why this exists
#   The private repo's git history contains references that must not go public
#   (employer-adjacent terms and EAP IP-scrub tokens, scrubbed from the working
#   tree but immutable in old commits). Rewriting history would change every hash.
#   Instead we publish a fresh-history snapshot: the full private history stays
#   intact here, and the public repo starts from a clean single commit.
#
# What it does
#   1. Exports the tracked tree at HEAD (git archive — no history, no untracked junk).
#   2. HARD SAFETY GATE: scans that exported tree against a local denylist and
#      ABORTS if any term is present. You cannot snapshot a tainted tree.
#   3. Re-initialises a fresh git repo with a single clean commit in OUT_DIR.
#   4. Prints the exact push commands. It NEVER pushes and NEVER touches this repo.
#
# Usage
#   scripts/make-public-snapshot.sh [OUT_DIR]           # default OUT: ../yukti-public
#   PUBLISH_DENYLIST="term1 term2" scripts/make-public-snapshot.sh /tmp/snap
#   FORCE=1 scripts/make-public-snapshot.sh OUT         # overwrite a non-empty OUT_DIR
#
# Denylist (first source found wins):
#   1) $PUBLISH_DENYLIST  — whitespace-separated terms
#   2) .publish-denylist  — repo-root file, one term per line, '#' comments ok
#                           (gitignored on purpose so terms never enter the repo)
#
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"
OUT_DIR="${1:-$REPO_ROOT/../yukti-public}"

say() { printf '  %s\n' "$*"; }
hr()  { printf '%s\n' "──────────────────────────────────────────────────────────"; }

hr; echo "make-public-snapshot · clean-history publish path"; hr

# ── resolve denylist ──────────────────────────────────────────────────────
terms=()
if [[ -n "${PUBLISH_DENYLIST:-}" ]]; then
  read -r -a terms <<< "$PUBLISH_DENYLIST"
  say "denylist: from \$PUBLISH_DENYLIST (${#terms[@]} term(s))"
elif [[ -f "$REPO_ROOT/.publish-denylist" ]]; then
  while IFS= read -r line; do
    line="${line%%#*}"; line="$(printf '%s' "$line" | xargs || true)"
    [[ -n "$line" ]] && terms+=("$line")
  done < "$REPO_ROOT/.publish-denylist"
  say "denylist: from .publish-denylist (${#terms[@]} term(s))"
else
  say "denylist: NONE found — proceeding with no term gate (add .publish-denylist to enable)"
fi

# ── export HEAD's tracked tree (no history) ───────────────────────────────
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
git archive --format=tar HEAD | tar -x -C "$WORK"
say "exported $(git ls-files | wc -l | tr -d ' ') tracked files at $(git rev-parse --short HEAD)"

# ── HARD SAFETY GATE ──────────────────────────────────────────────────────
# Binary media is exempt from the TERM grep — compressed pixel bytes can
# false-match short terms. Media is published metadata-stripped; a text term
# cannot ride pixel data. Every text byte in the tree is still scanned.
blocked=0
for t in "${terms[@]}"; do
  hits="$(grep -ril \
            --exclude='*.png' --exclude='*.gif' --exclude='*.jpg' \
            --exclude='*.jpeg' --exclude='*.ico' --exclude='*.woff' \
            --exclude='*.woff2' \
            -- "$t" "$WORK" 2>/dev/null | sed "s#$WORK/#    #" || true)"
  if [[ -n "$hits" ]]; then
    echo "  ✗ BLOCKED — denylisted term '$t' present in:"; echo "$hits"; blocked=1
  fi
done
# media hygiene backstop: no metadata text chunks may survive in shipped PNGs
for png in $(find "$WORK" -name '*.png'); do
  if magick identify -verbose "$png" 2>/dev/null | grep -q "tEXt\|zTXt\|iTXt"; then
    echo "  ✗ BLOCKED — PNG metadata text chunk survives in ${png#$WORK/} (publish media must be magick -strip'd)"
    blocked=1
  fi
done
if [[ "$blocked" -ne 0 ]]; then
  hr; echo "  ABORT: tree is not clean. Nothing written, nothing pushed."; hr; exit 1
fi
[[ "${#terms[@]}" -gt 0 ]] && say "✓ safety gate passed — no denylisted term in the tree"

# ── refuse to clobber a non-empty OUT_DIR unless FORCE=1 ──────────────────
if [[ -e "$OUT_DIR" && -n "$(ls -A "$OUT_DIR" 2>/dev/null || true)" && "${FORCE:-0}" != "1" ]]; then
  hr; echo "  OUT_DIR not empty: $OUT_DIR  (set FORCE=1 to overwrite)"; hr; exit 1
fi
rm -rf "$OUT_DIR"; mkdir -p "$OUT_DIR"
cp -a "$WORK/." "$OUT_DIR/"

# ── fresh single-commit history ───────────────────────────────────────────
NAME="$(git config user.name  || echo 'Jiten76')"
EMAIL="$(git config user.email || echo 'publish@localhost')"
git -C "$OUT_DIR" init -q -b main
# -f: the exported tree IS the curated set (git archive ships tracked files
# only) — without it, the exported .gitignore silently re-drops force-tracked
# files.
git -C "$OUT_DIR" add -Af
git -C "$OUT_DIR" -c user.name="$NAME" -c user.email="$EMAIL" commit -q -m "Public release — Yukti

Open-source agent-fleet governance: patterns, flows, decisions. Clean-history
snapshot of the reviewed tree, including the Stage-3b live-agent harness
(examples/live_agent/) and a captured, offline-verifiable governed run. Full
development history is retained in the private source repo."

hr
say "✓ clean-history snapshot ready:  $OUT_DIR"
say "  commits: $(git -C "$OUT_DIR" rev-list --count HEAD)   files: $(git -C "$OUT_DIR" ls-files | wc -l | tr -d ' ')"
hr
echo "  When YOU decide to go public, from $OUT_DIR run:"
echo
echo "    git remote add origin https://github.com/<you>/yukti.git"
echo "    git push -u --force origin main       # replaces the existing public release"
echo
echo "  This script pushed NOTHING."
hr
