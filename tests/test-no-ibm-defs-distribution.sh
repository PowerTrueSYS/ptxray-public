#!/bin/sh
# Exercise tools/check-no-ibm-defs-distribution.py in a temp repo. All "bad"
# content is synthesized here at run time; nothing IBM-derived is carried.
set -u

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd) || exit 1
GUARD=$ROOT/tools/check-no-ibm-defs-distribution.py
CASE_DIR=${TMPDIR:-/tmp}/ptxray-no-defs-guard.$$

cleanup() {
  rm -rf "$CASE_DIR"
}
trap cleanup 0 1 2 3 15

fail() {
  echo "FAIL: $1"
  exit 1
}

[ -r "$GUARD" ] || fail "missing guard: tools/check-no-ibm-defs-distribution.py"
mkdir -p "$CASE_DIR/tools" "$CASE_DIR/docs" "$CASE_DIR/gen"
cp "$GUARD" "$CASE_DIR/tools/check-no-ibm-defs-distribution.py"

# Synthesize the bad payloads (header + 40 rows; an envelope; wrapped forms).
python3 - "$CASE_DIR/gen" <<'PY' || fail "could not synthesize payloads"
import base64, gzip, sys
out = sys.argv[1]
hdr = ("type,product,versions,abstract,apars,fixedIn,ifixes,bulletinUrl,"
       "filesets,issued,updated,siblings,download,cvss,reboot")
rows = ["sec,aix,7.3.2,synthetic %d,IJ%05d,7.3.2.%d,,http://example.invalid/%d,,2099-01-01,2099-01-01,,,5.0,no" % (i, i, i, i) for i in range(40)]
csv = ("\n".join([hdr] + rows) + "\n").encode()
bundle = (b"PTXRAY-DEFINITION-BUNDLE|1\nCREATED-AT|2099-01-01T00:00:00Z\n"
          b"BEGIN-PAYLOAD|ibm-apar-csv|%d\n" % len(csv)
          + base64.encodebytes(csv)
          + b"END-PAYLOAD|ibm-apar-csv\nEND-BUNDLE|1|" + b"0" * 64 + b"\n")
def wrap64(raw):
    b = base64.b64encode(raw).decode()
    return "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n"
open(out + "/apar.plain", "wb").write(csv)
open(out + "/bundle.plain", "wb").write(bundle)
open(out + "/apar.b64", "w").write("payload='\n" + wrap64(csv) + "'\n")
open(out + "/apar.gz.b64", "w").write("payload='\n" + wrap64(gzip.compress(csv)) + "'\n")
open(out + "/bundle.b64", "w").write("blob=\n" + wrap64(bundle))
open(out + "/bundle.b64.oneline", "w").write("blob='" + base64.b64encode(bundle).decode() + "'\n")
open(out + "/quoted-header.sh", "w").write("# header: " + hdr + "\nprintf '%s\\n' '" + hdr + "'\n"
          + "\n".join("sec,aix,x,y,z,w" for _ in range(3)) + "\n")
PY

(
  cd "$CASE_DIR" || exit 1
  git init -q
  git config user.name no-defs-guard-test
  git config user.email no-defs-guard-test@example.invalid
  printf '# Notes\nPTxray fetches the latest IBM data at run time.\n' > README.md
  cp gen/quoted-header.sh quoted-header.sh
  git add README.md quoted-header.sh tools/check-no-ibm-defs-distribution.py
  git commit -qm baseline
)

GUARD_RUN="python3 tools/check-no-ibm-defs-distribution.py"

reset_case() {
  (
    cd "$CASE_DIR" || exit 1
    git reset -q --hard HEAD
    git clean -fdq -e gen
  )
}

expect_ok() {
  LABEL=$1
  shift
  if ! (cd "$CASE_DIR" && $GUARD_RUN "$@" >/dev/null 2>&1); then
    fail "$LABEL was rejected"
  fi
  echo "defs guard OK: $LABEL accepted"
}

expect_blocked() {
  LABEL=$1
  REASON=$2
  shift 2
  _OUT=$CASE_DIR/out.$$
  (cd "$CASE_DIR" && $GUARD_RUN "$@" >"$_OUT" 2>&1)
  _RC=$?
  [ "$_RC" -eq 1 ] || fail "$LABEL was not blocked (rc=$_RC)"
  grep -F -- "$REASON" "$_OUT" >/dev/null 2>&1 \
    || fail "$LABEL blocked with wrong reason (expected: $REASON); output: $(cat "$_OUT")"
  # Never echo the prohibited bytes.
  if grep -E 'synthetic [0-9]|PTXRAY-DEFINITION-BUNDLE' "$_OUT" >/dev/null 2>&1; then
    fail "$LABEL output leaked prohibited content"
  fi
  rm -f "$_OUT"
  echo "defs guard OK: $LABEL blocked"
}

stage_copy() {
  # stage_copy SRC DEST
  (cd "$CASE_DIR" && mkdir -p "$(dirname "$2")" && cp "$1" "$2" && git add -f "$2")
}

stage_text() {
  # stage_text DEST TEXT
  (cd "$CASE_DIR" && mkdir -p "$(dirname "$1")" && printf '%s\n' "$2" > "$1" && git add -f "$1")
}

expect_ok "clean tree, and a quoted APAR header with a few rows"

stage_copy gen/apar.plain data/apar-data.txt
expect_blocked "plain APAR CSV" "IBM APAR CSV feed"
reset_case

stage_copy gen/bundle.plain data/blob.txt
expect_blocked "plain definitions-bundle envelope" "definitions-bundle envelope"
reset_case

stage_copy gen/apar.b64 src/embed.sh
expect_blocked "base64-wrapped APAR CSV (64 columns)" "base64-wrapped"
reset_case

stage_copy gen/apar.gz.b64 src/embed2.sh
expect_blocked "base64-wrapped gzip APAR CSV" "base64-wrapped"
reset_case

stage_copy gen/bundle.b64 src/embed3.sh
expect_blocked "base64-wrapped bundle" "base64-wrapped"
reset_case

stage_copy gen/bundle.b64.oneline src/embed4.sh
expect_blocked "single-line base64 bundle" "base64-wrapped"
reset_case

stage_text dist/latest.ptxray-defs "x"
expect_blocked "*.ptxray-defs file" "prohibited file name"
reset_case

stage_text dist/latest.ptxray-defs.sig "x"
expect_blocked "defs .sig file" "prohibited file name"
reset_case

# Banned phrases are assembled from pieces so this test file stays clean.
P1="never ph""one IBM"
P2="Zero network"" calls"
URL="https://powertruesystems.com/ptxray/""definitions/latest"
stage_text docs/a.md "PTxray will $P1 at run time."
expect_blocked "banned phrase (never phone IBM)" "banned phrase: never phone IBM"
reset_case

stage_text docs/b.md "The scan makes $P2 at all."
expect_blocked "banned phrase (zero network calls)" "banned phrase: zero network calls"
reset_case

stage_text docs/scoped.md "Assessment makes zero network calls during assessment execution."
expect_ok "scoped claim: zero network calls during assessment execution"
reset_case

stage_text docs/c.md "The scan makes zero
network   calls today."
expect_blocked "banned phrase wrapped across lines" "banned phrase: zero network calls"
reset_case

stage_text README.md "Fetch from $URL"
expect_blocked "hosted definitions URL" "hosted definitions URL"
reset_case

stage_text docs/superpowers/plans/old.md "History: it said $P2 once."
expect_ok "banned phrase inside an exempt historical record"
reset_case

printf '%s\n' ptxray-aix.sh ptxray-ibmi.sh SHA256SUMS > "$CASE_DIR/assets-ok.txt"
expect_ok "clean release asset list" --assets-only --asset-list assets-ok.txt

printf '%s\n' ptxray-aix.sh latest.ptxray-defs latest.ptxray-defs.sig > "$CASE_DIR/assets-bad.txt"
expect_blocked "release asset list with a definitions bundle" "asset-list:latest.ptxray-defs" --assets-only --asset-list assets-bad.txt

printf '%s\n' ptxray-aix.sh apar.csv > "$CASE_DIR/assets-bad2.txt"
expect_blocked "release asset list with an APAR CSV" "asset-list:apar.csv" --assets-only --asset-list assets-bad2.txt

mkdir -p "$CASE_DIR/assets-dir"
cp "$CASE_DIR/gen/apar.b64" "$CASE_DIR/assets-dir/ptxray-aix.sh"
expect_blocked "release asset hiding a base64 APAR CSV" "base64-wrapped" --assets-only --assets-dir assets-dir
rm -rf "$CASE_DIR/assets-dir"

echo "no-IBM-defs-distribution guard test PASS"
