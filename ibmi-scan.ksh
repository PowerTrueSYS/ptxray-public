#!/bin/ksh
# Operator one-shot: compose IBM i doors and exec dest render doors.
# Do not inline their bodies. ksh88 / PASE. ksh and POSIX awk only.
set -u
LC_ALL=C
export LC_ALL

HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd) || exit 1

# USAGE --compliance alts come from the one VOCAB in resolve-groups.
# Never hand-list group names. Layouts match resolve_door:
#   emit   resolve-groups.ksh beside this runner
#   dist   ../compose/resolve-groups.ksh
#   source ../../compose/resolve-groups/run.ksh
RESOLVE=
if [ -f "$HERE/resolve-groups.ksh" ]; then
  RESOLVE=$HERE/resolve-groups.ksh
elif [ -f "$HERE/../compose/resolve-groups.ksh" ]; then
  RESOLVE=$HERE/../compose/resolve-groups.ksh
elif [ -f "$HERE/../../compose/resolve-groups/run.ksh" ]; then
  RESOLVE=$HERE/../../compose/resolve-groups/run.ksh
fi
USAGE_GROUPS=
if [ -n "$RESOLVE" ]; then
  USAGE_GROUPS=$(ksh "$RESOLVE" --print-usage ibmi-scan) || exit $?
  if [ -z "$USAGE_GROUPS" ]; then
    echo "ibmi-scan: cannot read group vocabulary" >&2
    exit 2
  fi
fi
# No resolver → no fabricated group list. Omit --compliance alts from
# fallback usage; a supplied value is still rejected at parse (fail closed).
if [ -n "$USAGE_GROUPS" ]; then
  COMPLIANCE_USAGE=' --compliance '"$USAGE_GROUPS"
else
  COMPLIANCE_USAGE=
fi
USAGE='usage: ibmi-scan [--html] [--json]'"$COMPLIANCE_USAGE"' --out DIR [--offline | --definitions-bundle FILE]
  --out DIR                    writes report.html, report.json, scan.ptx, ptxray-ibmi.json, facts, producers.tsv
  --offline                    cache-only air-gapped run (/var/ptxray/definitions)
  --definitions-bundle FILE    signed definitions envelope (air-gapped)
PTxray downloads the latest signed definitions by default. Opt out with --offline (cache only) or --definitions-bundle FILE (air-gapped). DEFS rows come from the evaluate document. Every run assesses the currency pillar in addition to the selected standard; CIS Level 2 runs include the Level 1 controls.'

PTXRAY_RUNNER_VERSION="1.7.0"

WANT_HTML=0
WANT_JSON=0
COMPLIANCE=
OUT_DIR=
DEFS_OFFLINE=0
DEFS_BUNDLE=
DEFS_OFFLINE_SEEN=0
DEFS_BUNDLE_SEEN=0
BUNDLE=
DEFS_SOURCE=

if [ $# -eq 0 ]; then
  echo "ibmi-scan: $USAGE" >&2
  exit 2
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --html)
      if [ "$WANT_HTML" -eq 1 ]; then
        echo "ibmi-scan: $USAGE" >&2
        exit 2
      fi
      WANT_HTML=1
      shift
      ;;
    --json)
      if [ "$WANT_JSON" -eq 1 ]; then
        echo "ibmi-scan: $USAGE" >&2
        exit 2
      fi
      WANT_JSON=1
      shift
      ;;
    --compliance)
      shift
      case "${1:-}" in
        ""|--*) echo "ibmi-scan: $USAGE" >&2; exit 2 ;;
      esac
      case "|$USAGE_GROUPS|" in
        *"|$1|"*) ;;
        *) echo "ibmi-scan: $USAGE" >&2; exit 2 ;;
      esac
      if [ -n "$COMPLIANCE" ]; then
        echo "ibmi-scan: $USAGE" >&2
        exit 2
      fi
      COMPLIANCE=$1
      shift
      ;;
    --out)
      shift
      case "${1:-}" in
        ""|--*) echo "ibmi-scan: $USAGE" >&2; exit 2 ;;
      esac
      if [ -n "$OUT_DIR" ]; then
        echo "ibmi-scan: $USAGE" >&2
        exit 2
      fi
      OUT_DIR=$1
      shift
      ;;
    --offline)
      if [ "$DEFS_OFFLINE_SEEN" -eq 1 ]; then
        echo 'ibmi-scan: duplicate --offline' >&2
        exit 2
      fi
      DEFS_OFFLINE_SEEN=1
      DEFS_OFFLINE=1
      shift
      ;;
    --definitions-bundle)
      if [ "$DEFS_BUNDLE_SEEN" -eq 1 ]; then
        echo 'ibmi-scan: duplicate --definitions-bundle' >&2
        exit 2
      fi
      DEFS_BUNDLE_SEEN=1
      shift
      case "${1:-}" in
        ""|--*) echo "ibmi-scan: $USAGE" >&2; exit 2 ;;
      esac
      DEFS_BUNDLE=$1
      shift
      ;;
    *)
      echo "ibmi-scan: $USAGE" >&2
      exit 2
      ;;
  esac
done

if [ "$DEFS_OFFLINE" -eq 1 ] && [ -n "$DEFS_BUNDLE" ]; then
  echo 'ibmi-scan: --offline conflicts with --definitions-bundle' >&2
  exit 2
fi

if [ -z "$COMPLIANCE" ] || [ -z "$OUT_DIR" ]; then
  echo "ibmi-scan: $USAGE" >&2
  exit 2
fi

if [ "$WANT_HTML" -eq 0 ] && [ "$WANT_JSON" -eq 0 ]; then
  WANT_HTML=1
fi

if [ -n "$DEFS_BUNDLE" ]; then
  if [ ! -f "$DEFS_BUNDLE" ] || [ ! -r "$DEFS_BUNDLE" ]; then
    echo "ibmi-scan: cannot read $DEFS_BUNDLE" >&2
    exit 2
  fi
fi

function resolve_door {
  # resolve_door EMIT_NAME SOURCE_PATH [DIST_PATH]
  #
  # Probe each door by its own name, the way tools.d/runner/aixray/run.ksh
  # does, instead of inferring one layout from a single sentinel. Three
  # layouts have to resolve:
  #
  #   emit / test   every door sits beside this runner as EMIT_NAME
  #   dist          the same, except the compose front door: build/emit-dest.sh
  #                 writes this runner to dist/tools/ while
  #                 build/emit-compose.sh writes compose to
  #                 dist/compose/ibmi.ksh, so compose passes that relative
  #                 path as DIST_PATH
  #   source        tools.d, where the door is SOURCE_PATH under $HERE
  #
  # The old form keyed every door off a co-located compose.ksh, which no build
  # target ever writes; in dist/tools/ that meant every door resolved to a
  # repo-root path that does not exist there and the shipped runner could
  # resolve nothing at all.
  if [ -f "$HERE/$1" ]; then
    printf '%s\n' "$HERE/$1"
  elif [ -n "${3:-}" ] && [ -f "$HERE/$3" ]; then
    printf '%s\n' "$HERE/$3"
  else
    printf '%s\n' "$HERE/$2"
  fi
}

function resolve_data {
  # resolve_data DIST_PATH SOURCE_PATH -> shipped data file for this layout
  #
  # dist/data/manifests.tsv is generated by build/emit-dest.sh from
  # tools.d/checks, because rpt-manifest-tsv reads a source tree that does not
  # exist on a scanned box. In the dist layout it sits beside dist/tools; in
  # the source tree the build writes it to the repo's own dist/data.
  if [ -f "$HERE/$1" ]; then
    printf '%s\n' "$HERE/$1"
  else
    printf '%s\n' "$HERE/$2"
  fi
}

function require_door {
  # require_door PATH
  if [ ! -f "$1" ]; then
    echo "ibmi-scan: missing $1" >&2
    exit 2
  fi
}

function require_render_door {
  # require_render_door PATH SOURCE_DIR
  # Typed refusal for the 1.4 render chain. The 1.3 renderer is retired: when
  # the chain is absent the HTML step refuses, it never falls back silently.
  if [ ! -f "$1" ]; then
    echo "render: 1.4 chain not present ($2)" >&2
    exit 4
  fi
}

function refuse {
  echo "ibmi-scan: $1" >&2
  exit 4
}

function resolve_ptxray_defs {
  # Beside the runner, then beside the IBM i (or AIX) monolith, then on PATH.
  typeset d p oIFS
  if [ -f "$HERE/ptxray-defs.sh" ]; then
    printf '%s\n' "$HERE/ptxray-defs.sh"
    return 0
  fi
  if [ -f "$HERE/../ptxray-defs.sh" ]; then
    printf '%s\n' "$HERE/../ptxray-defs.sh"
    return 0
  fi
  for d in "$HERE" "$HERE/.." "$HERE/../.."; do
    if [ -f "$d/ptxray-ibmi.sh" ] && [ -f "$d/ptxray-defs.sh" ]; then
      printf '%s\n' "$d/ptxray-defs.sh"
      return 0
    fi
    if [ -f "$d/ptxray-aix.sh" ] && [ -f "$d/ptxray-defs.sh" ]; then
      printf '%s\n' "$d/ptxray-defs.sh"
      return 0
    fi
  done
  p=$(command -v ptxray-defs.sh 2>/dev/null) || p=
  if [ -n "$p" ] && [ -f "$p" ]; then
    printf '%s\n' "$p"
    return 0
  fi
  oIFS=$IFS
  IFS=:
  for d in $PATH; do
    IFS=$oIFS
    if [ -n "$d" ] && [ -f "$d/ptxray-defs.sh" ]; then
      printf '%s\n' "$d/ptxray-defs.sh"
      return 0
    fi
  done
  IFS=$oIFS
  return 1
}

function take_bundle {
  # take_bundle PATH SOURCE  -- copy into WORKDIR and record provenance.
  typeset src dest
  src=$1
  DEFS_SOURCE=$2
  if [ ! -f "$src" ] || [ ! -r "$src" ]; then
    echo "ibmi-scan: cannot read $src" >&2
    exit 2
  fi
  dest=$WORKDIR/definitions.bundle
  if ! cp "$src" "$dest"; then
    echo "ibmi-scan: cannot write work dir" >&2
    exit 1
  fi
  BUNDLE=$dest
}

function defs_status_protocol_valid {
  # Same status protocol as src/definitions-selector.ksh.
  printf '%s\n' "$1" | awk -F'|' '
    function digits(s){return s~/^(0|[1-9][0-9]*)$/}
    function positive(s){return s~/^[1-9][0-9]*$/&&length(s)<=18}
    function hex64(s, i,c){if(length(s)!=64)return 0;for(i=1;i<=64;i++){c=substr(s,i,1);if(c!~/[0-9a-f]/)return 0}return 1}
    function ymd(s){return s~/^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/}
    function dotted(s){return s~/^[0-9][0-9][0-9][0-9][.][0-9][0-9][.][0-9][0-9]$/}
    function version(s){return length(s)>=1&&length(s)<=64&&s~/^[A-Za-z0-9][A-Za-z0-9._+-]*$/}
    function created(s){return s~/^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z$/}
    function generation(s, a,n){n=split(s,a,"-");return n==3&&a[1]=="g"&&positive(a[2])&&hex64(a[3])}
    NR!=1{bad=1}
    NR==1{
      if(NF!=15&&NF!=16)bad=1
      if($1!="PTXRAY-DEFS"||$2!="1"||$3!="ok")bad=1
      if($4!="update"&&$4!="cache"&&$4!="local"&&$4!="cache-fallback")bad=1
      if($5!~/^sequence=/||!positive(substr($5,10)))bad=1
      if($6!~/^created_at=/||!created(substr($6,12)))bad=1
      if($7!~/^age_days=/||!digits(substr($7,10)))bad=1
      if($8!="freshness=current"&&$8!="freshness=stale")bad=1
      if($9!~/^kev_version=/||!dotted(substr($9,13)))bad=1
      if($10!~/^kev_as_of=/||!ymd(substr($10,11)))bad=1
      if($11!~/^kev_sha256=/||!hex64(substr($11,12)))bad=1
      if($12!~/^apar_version=/||!version(substr($12,14)))bad=1
      if($13!~/^apar_as_of=/||!ymd(substr($13,12)))bad=1
      if($14!~/^apar_sha256=/||!hex64(substr($14,13)))bad=1
      if($15!~/^generation=/||!generation(substr($15,12)))bad=1
      if(NF==16){
        if($4!="cache-fallback"||$16!~/^error=(transport|size-limit|signature|rollback|malformed|unsafe-cache|lock-contention)$/)bad=1
      } else if($4=="cache-fallback")bad=1
    }
    END{exit bad||NR!=1?1:0}'
}

function defs_status_line {
  # Exactly one PTXRAY-DEFS|1|ok status line on the downloader stdout.
  awk -F'|' '
    $1=="PTXRAY-DEFS" && $2=="1" && $3=="ok" {
      if (seen) extra=1
      seen=1
      line=$0
    }
    END { if (!seen || extra) exit 1; print line }
  ' "$1"
}

function defs_map_origin {
  # Map the downloader status mode onto report provenance.
  case "$1" in
    update) printf '%s\n' downloaded ;;
    cache|cache-fallback) printf '%s\n' cache ;;
    local) printf '%s\n' bundled ;;
    *) return 1 ;;
  esac
}

function invoke_ptxray_defs {
  # invoke_ptxray_defs DEFS_SH OUT ERR [args...]
  typeset defs_sh out_file err_file
  defs_sh=$1
  out_file=$2
  err_file=$3
  shift
  shift
  shift
  if [ -x "$defs_sh" ]; then
    "$defs_sh" "$@" >"$out_file" 2>"$err_file"
  else
    ksh "$defs_sh" "$@" >"$out_file" 2>"$err_file"
  fi
}

function defs_snapshot_usable {
  # defs_snapshot_usable DIR
  # Private snapshot must carry the shipped contract so doors can read
  # $PTXRAY_DEFS_DIR/<id>.tsv. Missing any required file is not usable.
  typeset d
  d=$1
  [ -n "$d" ] && [ -d "$d" ] || return 1
  [ -s "$d/bundle.ptxray-defs" ] && [ -r "$d/bundle.ptxray-defs" ] || return 1
  [ -s "$d/cisa-kev.json" ] && [ -r "$d/cisa-kev.json" ] || return 1
  [ -s "$d/cisa-kev-cves.txt" ] && [ -r "$d/cisa-kev-cves.txt" ] || return 1
  [ -s "$d/ibm-apar-csv.csv" ] && [ -r "$d/ibm-apar-csv.csv" ] || return 1
  [ -s "$d/ibmi-psp-group-levels.tsv" ] && [ -r "$d/ibmi-psp-group-levels.tsv" ] || return 1
  [ -s "$d/ibm-flrt-firmware.tsv" ] && [ -r "$d/ibm-flrt-firmware.tsv" ] || return 1
  return 0
}

function defs_snapshot_bundle {
  # defs_snapshot_bundle DEFS_SH GENERATION -> path of private snapshot bundle
  typeset defs_sh gen snapdir rc
  defs_sh=$1
  gen=$2
  snapdir=$WORKDIR/defs-snap
  rm -rf "$snapdir"
  mkdir "$snapdir" || return 1
  invoke_ptxray_defs "$defs_sh" "$WORKDIR/defs-snap.out" "$WORKDIR/defs-snap.err" \
    --snapshot "$gen" "$snapdir"
  rc=$?
  if [ "$rc" -eq 0 ] && defs_snapshot_usable "$snapdir"; then
    printf '%s\n' "$snapdir/bundle.ptxray-defs"
    return 0
  fi
  rm -rf "$snapdir"
  return 1
}

function consume_verified_generation {
  # consume_verified_generation DEFS_SH STATUS_FILE ALLOWED
  # ALLOWED is comma-separated status modes (update,cache-fallback or cache).
  # Returns 1 for an invalid status protocol, 2 when the protocol is valid
  # but no usable private snapshot could be consumed. Every mode requires
  # --snapshot; a downloader-emitted envelope path is never a fallback.
  typeset defs_sh status_file allowed line mode gen origin cand
  defs_sh=$1
  status_file=$2
  allowed=$3
  line=$(defs_status_line "$status_file") || return 1
  defs_status_protocol_valid "$line" || return 1
  mode=$(printf '%s\n' "$line" | awk -F'|' '{print $4}')
  gen=$(printf '%s\n' "$line" | awk -F'|' '{g=$15; sub(/^generation=/,"",g); print g}')
  case ",$allowed," in
    *",$mode,"*) ;;
    *) return 1 ;;
  esac
  origin=$(defs_map_origin "$mode") || return 1
  cand=
  if [ -n "$gen" ]; then
    cand=$(defs_snapshot_bundle "$defs_sh" "$gen") || cand=
  fi
  if [ -z "$cand" ]; then
    return 2
  fi
  take_bundle "$cand" "$origin"
  return 0
}

function acquire_definitions {
  # Default: ptxray-defs.sh --update, parse the status protocol, then a
  # verified private snapshot (never reopen /var/ptxray/definitions).
  # --offline: ptxray-defs.sh --cache. Empty or unverified cache is a typed
  # refusal naming --definitions-bundle. --definitions-bundle FILE:
  # ptxray-defs.sh --local FILE (no network), then the same verified snapshot
  # so doors see $PTXRAY_DEFS_DIR/<id>.tsv. Failed or incomplete --snapshot
  # is a typed refusal in every mode; the envelope path is never a fallback.
  typeset defs_sh rc
  if ! defs_sh=$(resolve_ptxray_defs); then
    if [ -n "$DEFS_BUNDLE" ]; then
      echo "ibmi-scan: --definitions-bundle: ptxray-defs.sh not found" >&2
      exit 4
    fi
    if [ "$DEFS_OFFLINE" -eq 1 ]; then
      echo "ibmi-scan: --offline: ptxray-defs.sh not found; supply --definitions-bundle FILE" >&2
      exit 4
    fi
    echo "ibmi-scan: ptxray-defs.sh not found; use --definitions-bundle FILE or --offline" >&2
    echo "PTxray downloads the latest signed definitions by default. Opt out with --offline (cache only) or --definitions-bundle FILE (air-gapped)." >&2
    exit 4
  fi
  if [ -n "$DEFS_BUNDLE" ]; then
    invoke_ptxray_defs "$defs_sh" "$WORKDIR/defs-status.out" "$WORKDIR/defs-status.err" \
      --local "$DEFS_BUNDLE"
    rc=$?
    if [ "$rc" -ne 0 ]; then
      cat "$WORKDIR/defs-status.err" >&2
      echo "ibmi-scan: --definitions-bundle: signed envelope could not be verified" >&2
      exit 4
    fi
    consume_verified_generation "$defs_sh" "$WORKDIR/defs-status.out" "local"
    rc=$?
    if [ "$rc" -eq 0 ]; then
      return 0
    fi
    if [ "$rc" -eq 2 ]; then
      echo "ibmi-scan: --definitions-bundle: signed envelope snapshot missing or incomplete; cannot supply definitions to doors" >&2
      exit 4
    fi
    echo "ibmi-scan: --definitions-bundle: definitions downloader returned an invalid status protocol" >&2
    exit 4
  fi
  if [ "$DEFS_OFFLINE" -eq 1 ]; then
    invoke_ptxray_defs "$defs_sh" "$WORKDIR/defs-status.out" "$WORKDIR/defs-status.err" --cache
    rc=$?
    if [ "$rc" -ne 0 ]; then
      cat "$WORKDIR/defs-status.err" >&2
      echo "ibmi-scan: --offline: signed definitions cache is empty; supply --definitions-bundle FILE" >&2
      exit 4
    fi
    consume_verified_generation "$defs_sh" "$WORKDIR/defs-status.out" "cache"
    rc=$?
    if [ "$rc" -eq 0 ]; then
      return 0
    fi
    if [ "$rc" -eq 2 ]; then
      echo "ibmi-scan: --offline: signed definitions snapshot missing or incomplete; supply --definitions-bundle FILE" >&2
      exit 4
    fi
    echo "ibmi-scan: --offline: signed definitions cache could not be verified; supply --definitions-bundle FILE" >&2
    exit 4
  fi
  invoke_ptxray_defs "$defs_sh" "$WORKDIR/defs-status.out" "$WORKDIR/defs-status.err" --update
  rc=$?
  if [ "$rc" -ne 0 ]; then
    cat "$WORKDIR/defs-status.err" >&2
    echo "ibmi-scan: definitions download failed; use --definitions-bundle FILE or --offline" >&2
    exit 4
  fi
  consume_verified_generation "$defs_sh" "$WORKDIR/defs-status.out" "update,cache-fallback"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    return 0
  fi
  if [ "$rc" -eq 2 ]; then
    echo "ibmi-scan: definitions snapshot missing or incomplete; use --definitions-bundle FILE or --offline" >&2
    exit 4
  fi
  echo "ibmi-scan: definitions downloader returned an invalid status protocol; use --definitions-bundle FILE or --offline" >&2
  exit 4
}

function stamp_defs_status {
  # stamp_defs_status FILE SOURCE -- defs.mode live vs bundle so the
  # report data-sources block can show downloaded / cache / bundled.
  typeset src tmp origin
  src=$1
  origin=$2
  [ -f "$src" ] || return 0
  case "$origin" in
    downloaded|cache) ;;
    *) return 0 ;;
  esac
  tmp=$src.stamp
  awk -v origin="$origin" '
    /"mode": "bundle"/ {
      sub(/"mode": "bundle"/, "\"mode\": \"live\"")
    }
    /"id":/ && /"as_of":/ {
      if ($0 !~ /"origin":/) {
        sub(/\{[[:space:]]*/, "{ \"origin\": \"" origin "\", ")
      }
    }
    { print }
  ' "$src" > "$tmp" || return 0
  mv "$tmp" "$src"
}

function export_defs_dir {
  # Dispatch (and therefore every door) sees the private snapshot.
  # Incomplete or missing snapshot is a typed refusal: a report that
  # cannot check the IBM i currency doors is not composed.
  if defs_snapshot_usable "$WORKDIR/defs-snap"; then
    PTXRAY_DEFS_DIR=$WORKDIR/defs-snap
    export PTXRAY_DEFS_DIR
    return 0
  fi
  echo "ibmi-scan: definitions snapshot missing or incomplete; cannot supply definitions to doors" >&2
  exit 4
}

# --- resolve every selected mode's doors before any exec ---
COMPOSE=$(resolve_door render-compose-ibmi.ksh ../../compose/ibmi/run.ksh ../compose/ibmi.ksh)
require_door "$COMPOSE"
RENDER_EMITTER=$(resolve_door render-emitter.ksh ../../render/emitter/run.ksh ../render/emitter/run.ksh)
RENDER_SCORE_FORMULAS=$(resolve_door render-score-formulas.ksh ../../render/score-formulas/run.ksh ../render/score-formulas/run.ksh)
RENDER_APPLY_SCORES=$(resolve_door render-apply-scores.ksh ../../render/apply-scores/run.ksh ../render/apply-scores/run.ksh)
require_render_door "$RENDER_EMITTER" tools.d/render/emitter
require_render_door "$RENDER_SCORE_FORMULAS" tools.d/render/score-formulas
require_render_door "$RENDER_APPLY_SCORES" tools.d/render/apply-scores
if [ "$WANT_HTML" -eq 1 ]; then
  RENDER_COMPOSE=$(resolve_door render-compose.ksh ../../render/compose/run.ksh ../render/compose/run.ksh)
  require_render_door "$RENDER_COMPOSE" tools.d/render/compose
fi
MANIFESTS=$(resolve_data ../data/manifests.tsv ../../../dist/data/manifests.tsv)
if [ ! -f "$MANIFESTS" ]; then
  echo "render: shipped check manifests missing ($MANIFESTS)" >&2
  exit 4
fi
IBMI_GROUP_REG=$(resolve_data ../compose/ibmi-group-registry.tsv ../../../dist/compose/ibmi-group-registry.tsv)
if [ ! -f "$IBMI_GROUP_REG" ]; then
  echo "ibmi-scan: cannot read IBM i group registry $IBMI_GROUP_REG" >&2
  exit 4
fi
DEF_EVAL=$(resolve_door definitions-evaluate.ksh ../../definitions/evaluate/run.ksh)
require_door "$DEF_EVAL"
RENDER_CONTRACT=$(resolve_door render-contract.ksh ../../render/contract/validate ../render/contract/validate)
REPORT_JSON=$(resolve_door report-json.ksh ../../report/json/run.ksh)
require_door "$REPORT_JSON"

if [ ! -d "$OUT_DIR" ]; then
  echo "ibmi-scan: cannot write $OUT_DIR" >&2
  exit 2
fi

WORKDIR=${TMPDIR:-/tmp}/ibmi-scan.$$
umask 077
mkdir "$WORKDIR" || { echo "ibmi-scan: cannot write work dir" >&2; exit 1; }
trap 'rm -rf "$WORKDIR"' 0 1 2 3 15

# Default: download. --offline: cache only. --definitions-bundle FILE: that
# signed envelope via ptxray-defs.sh --local (no network), then snapshot.
# Snapshot dir is exported so dispatch (and every door) can read
# $PTXRAY_DEFS_DIR/<id>.tsv.
acquire_definitions
export_defs_dir

# Findings come from the IBM i compose front door, not an assembled script.
# Map the requested standard to compose groups: Level 2 includes Level 1;
# ops always accompanies so every IBM i pillar is assessed, except when
# the selected token is already ops or all (all expands to whole VOCAB).
# ptxray-ibmi.json compliance stays $COMPLIANCE; controls still come from
# registry row tags.
case "$COMPLIANCE" in
  cis-l1)
    ksh "$COMPOSE" --group cis-l1 --group ops --json </dev/null \
      >"$WORKDIR/envelope.json" 2>"$WORKDIR/compose.err"
    ;;
  cis-l2)
    ksh "$COMPOSE" --group cis-l1 --group cis-l2 --group ops --json </dev/null \
      >"$WORKDIR/envelope.json" 2>"$WORKDIR/compose.err"
    ;;
  ops|all)
    ksh "$COMPOSE" --group "$COMPLIANCE" --json </dev/null \
      >"$WORKDIR/envelope.json" 2>"$WORKDIR/compose.err"
    ;;
  *)
    ksh "$COMPOSE" --group "$COMPLIANCE" --group ops --json </dev/null \
      >"$WORKDIR/envelope.json" 2>"$WORKDIR/compose.err"
    ;;
esac
rc=$?
if [ "$rc" -ne 0 ]; then
  cat "$WORKDIR/compose.err" >&2
  refuse "compose failed (rc=$rc)"
fi
if [ ! -s "$WORKDIR/envelope.json" ]; then
  cat "$WORKDIR/compose.err" >&2
  refuse "compose JSON missing"
fi

GENERATED=$(date -u '+%Y-%m-%d %H:%M UTC') || refuse "cannot determine UTC generated time"

# Stamp scan time onto the envelope the emitter reads. Compose may carry a
# fixture date or a hardcoded stub generated; the document generated_utc is
# now, and the contract forbids a document generated before the scan finished.
awk -v gen="$GENERATED" '
  /"generated":/ && !done {
    sub(/"generated":[ \t]*"[^"]*"/, "\"generated\": \"" gen "\"")
    done=1
  }
  { print }
' "$WORKDIR/envelope.json" > "$WORKDIR/envelope.stamped.json" || refuse "cannot stamp envelope generated"
if [ ! -s "$WORKDIR/envelope.stamped.json" ]; then
  refuse "cannot stamp envelope generated"
fi
mv "$WORKDIR/envelope.stamped.json" "$WORKDIR/envelope.json"

# --- identity / os facts (own probes) ---
HOST=$(hostname 2>/dev/null) || HOST=
if [ -z "$HOST" ]; then
  refuse "cannot determine hostname"
fi
SERIAL=
MODEL=
RELEASE=
if [ -x /QOpenSys/usr/bin/qsh ]; then
  SYSVAL_OUT=$(/QOpenSys/usr/bin/qsh -c "db2 \"SELECT VARCHAR(SYSTEM_VALUE_NAME,10) CONCAT '|' CONCAT VARCHAR(COALESCE(TRIM(CURRENT_CHARACTER_VALUE),''),32) FROM QSYS2.SYSTEM_VALUE_INFO WHERE SYSTEM_VALUE_NAME IN ('QSRLNBR','QMODEL')\"" 2>/dev/null </dev/null) || SYSVAL_OUT=
  SERIAL=$(printf '%s\n' "$SYSVAL_OUT" | awk -F'|' '
    {
      n=$1; v=$2
      gsub(/^[ \t]+|[ \t]+$/, "", n)
      gsub(/^[ \t]+|[ \t]+$/, "", v)
      if (n == "QSRLNBR") { print v; exit }
    }')
  MODEL=$(printf '%s\n' "$SYSVAL_OUT" | awk -F'|' '
    {
      n=$1; v=$2
      gsub(/^[ \t]+|[ \t]+$/, "", n)
      gsub(/^[ \t]+|[ \t]+$/, "", v)
      if (n == "QMODEL") { print v; exit }
    }')
  OS_OUT=$(/QOpenSys/usr/bin/qsh -c "db2 \"SELECT 'OS' CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(OS_VERSION,'-')),10) CONCAT '|' CONCAT VARCHAR(TRIM(COALESCE(OS_RELEASE,'-')),10) FROM SYSIBMADM.ENV_SYS_INFO\"" 2>/dev/null </dev/null) || OS_OUT=
  RELEASE=$(printf '%s\n' "$OS_OUT" | awk -F'|' '
    $1 == "OS" {
      v=$2; r=$3
      gsub(/^[ \t]+|[ \t]+$/, "", v)
      gsub(/^[ \t]+|[ \t]+$/, "", r)
      if (v ~ /^[0-9]$/ && r ~ /^[0-9]$/) { print v "." r; exit }
    }')
fi
if [ -z "$RELEASE" ]; then
  RELEASE=$(awk '
function json_get(s, key,    pat, p, rest, out, esc, i, c) {
  pat = "\"" key "\""
  p = index(s, pat)
  if (!p) return ""
  rest = substr(s, p + length("" pat))
  if (!sub(/^[ \t]*:[ \t]*"/, "", rest)) return ""
  out = ""
  esc = 0
  for (i = 1; i <= length("" rest); i++) {
    c = substr(rest, i, 1)
    if (esc) {
      if (c == "n") out = out "\n"
      else if (c == "t") out = out "\t"
      else out = out c
      esc = 0
      continue
    }
    if (c == "\\") { esc = 1; continue }
    if (c == "\"") break
    out = out c
  }
  return out
}
{ doc = doc $0 "\n" }
END { printf "%s", json_get(doc, "release") }
  ' "$WORKDIR/envelope.json")
fi
if [ -z "$RELEASE" ]; then
  refuse "cannot determine IBM i release"
fi

awk -v host="$HOST" -v serial="$SERIAL" -v model="$MODEL" '
function jesc(s) {
  gsub(/\\/, "\\\\", s)
  gsub(/"/, "\\\"", s)
  gsub(/\n/, "\\n", s)
  gsub(/\t/, "\\t", s)
  return s
}
BEGIN {
  printf "{\n  \"partition_name\": \"%s\",\n  \"frame_serial\": \"%s\",\n  \"machine_type\": \"%s\",\n  \"platform\": \"ibmi\"\n}\n", \
    jesc(host), jesc(serial), jesc(model)
}
' > "$OUT_DIR/fact-identity.json" || refuse "cannot write $OUT_DIR/fact-identity.json"

awk -v rel="$RELEASE" '
function jesc(s) {
  gsub(/\\/, "\\\\", s)
  gsub(/"/, "\\\"", s)
  return s
}
BEGIN {
  printf "{\n  \"oslevel_s\": \"%s\",\n  \"platform\": \"ibmi\"\n}\n", jesc(rel)
}
' > "$OUT_DIR/fact-os.json" || refuse "cannot write $OUT_DIR/fact-os.json"

# --- defs status JSON from the evaluate document (AIX path) ---
if [ -z "$BUNDLE" ] || [ ! -f "$BUNDLE" ] || [ ! -r "$BUNDLE" ]; then
  refuse "definitions bundle missing after acquire"
fi
ksh "$DEF_EVAL" --bundle "$BUNDLE" --out "$WORKDIR/status.json"
rc=$?
if [ "$rc" -ne 0 ]; then
  exit "$rc"
fi
stamp_defs_status "$WORKDIR/status.json" "$DEFS_SOURCE"
if [ ! -s "$WORKDIR/status.json" ]; then
  refuse "cannot write definitions status JSON"
fi

: > "$WORKDIR/state.tsv"

# --- emitter -> score-formulas -> apply-scores ---
ksh "$RENDER_EMITTER" \
  --envelope "$WORKDIR/envelope.json" \
  --facts "$OUT_DIR" \
  --currency "$WORKDIR/state.tsv" \
  --defs "$WORKDIR/status.json" \
  --manifests "$MANIFESTS" \
  --scanner-version "$PTXRAY_RUNNER_VERSION" >"$WORKDIR/document.ptxs"
rc=$?
if [ "$rc" -ne 0 ]; then
  exit "$rc"
fi

ksh "$RENDER_SCORE_FORMULAS" --in "$WORKDIR/document.ptxs" > "$WORKDIR/scores.tsv"
rc=$?
if [ "$rc" -ne 0 ]; then
  exit "$rc"
fi

ksh "$RENDER_APPLY_SCORES" --in "$WORKDIR/document.ptxs" --scores "$WORKDIR/scores.tsv" \
  > "$WORKDIR/scored.ptxs"
rc=$?
if [ "$rc" -ne 0 ]; then
  exit "$rc"
fi

KEEP_PTX=0
if [ -f "$RENDER_CONTRACT" ]; then
  ksh "$RENDER_CONTRACT" --in "$WORKDIR/scored.ptxs" \
    >"$WORKDIR/scan-validate.out" 2>"$WORKDIR/scan-validate.err"
  vrc=$?
  if [ "$vrc" -eq 0 ]; then
    KEEP_PTX=1
  else
    cat "$WORKDIR/scan-validate.err" >&2
    refuse "scored document failed contract validation"
  fi
else
  refuse "render contract validator missing"
fi
if [ "$KEEP_PTX" -eq 1 ]; then
  if ! cp "$WORKDIR/scored.ptxs" "$OUT_DIR/scan.ptx"; then
    echo "ibmi-scan: cannot write $OUT_DIR/scan.ptx" >&2
    exit 2
  fi
  chmod 0600 "$OUT_DIR/scan.ptx"
  printf 'Report ready: %s\n' "$OUT_DIR/scan.ptx"
fi

# Blueprint input synthesised from the compose envelope and the scored
# document. Controls from the IBM i group registry row that owns each
# finding id. Registry order. Numbers come from scan.ptx, never recomputed.
JSON_PROG=$WORKDIR/ibmi-json.awk
cat > "$JSON_PROG" <<'IBMI_JSON_SHAPE'
function refuse_c(s) { print "ibmi-scan: " s > errfile; failed=1; exit 1 }
function json_get(s, key,    pat, p, rest, out, esc, i, c) {
  pat = "\"" key "\""
  p = index(s, pat)
  if (!p) return ""
  rest = substr(s, p + length("" pat))
  if (!sub(/^[ \t]*:[ \t]*"/, "", rest)) return ""
  out = ""
  esc = 0
  for (i = 1; i <= length("" rest); i++) {
    c = substr(rest, i, 1)
    if (esc) {
      if (c == "n") out = out "\n"
      else if (c == "t") out = out "\t"
      else out = out c
      esc = 0
      continue
    }
    if (c == "\\") { esc = 1; continue }
    if (c == "\"") break
    out = out c
  }
  return out
}
function jesc(s) {
  gsub(/\\/, "\\\\", s)
  gsub(/"/, "\\\"", s)
  gsub(/\n/, "\\n", s)
  gsub(/\t/, "\\t", s)
  gsub(/\r/, "\\r", s)
  return s
}
function emit_controls(tags,    n, i, tok, first, out) {
  if (tags == "" || tags == "-") return "[]"
  n = split(tags, t, ",")
  first = 1
  out = "["
  for (i = 1; i <= n; i++) {
    tok = t[i]
    gsub(/^[ \t]+|[ \t]+$/, "", tok)
    if (tok == "" || tok == "-") continue
    if (first) first = 0
    else out = out ", "
    out = out "\"" jesc(tok) "\""
  }
  out = out "]"
  return out
}
function load_ptx(    line, n, f, rec, pid, cid, p_pass, p_n, p_m, p_state, p_score, p_band, c_name, c_pillar, ptx_rc) {
  rec = ""
  ptx_rc = 0
  while ((ptx_rc = (getline line < ptxfile)) > 0) {
    gsub(/\r/, "", line)
    if (line == "" || substr(line, 1, 1) == "#") continue
    n = split(line, f, "\t")
    if (n < 1) continue
    if (f[1] == "BEGIN") {
      rec = (n >= 2) ? f[2] : ""
      pid = ""; cid = ""; p_pass = ""; p_n = ""; p_m = ""; p_state = ""; p_score = ""; p_band = ""; c_name = ""; c_pillar = ""
      continue
    }
    if (f[1] == "END") {
      if (rec == "PILLAR" && pid != "") {
        npil++
        Pil[npil] = pid
        Ppass[pid] = p_pass + 0
        Pn[pid] = p_n + 0
        Pm[pid] = p_m + 0
        Pstate[pid] = p_state
        Pscore[pid] = p_score
        Pband[pid] = p_band
      }
      if (rec == "CONTROL" && cid != "") {
        if (c_name != "") Cname[cid] = c_name
        if (c_pillar != "") Cpillar[cid] = c_pillar
      }
      rec = ""
      continue
    }
    if (n < 2) continue
    if (rec == "PILLAR") {
      if (f[1] == "pillar.id") pid = f[2]
      else if (f[1] == "pillar.count_pass") p_pass = f[2]
      else if (f[1] == "pillar.assessed_n") p_n = f[2]
      else if (f[1] == "pillar.assessed_m") p_m = f[2]
      else if (f[1] == "pillar.state") p_state = f[2]
      else if (f[1] == "pillar.score") p_score = f[2]
      else if (f[1] == "pillar.band") p_band = f[2]
    } else if (rec == "OVERALL") {
      if (f[1] == "overall.score") { oscore = f[2]; have_oscore = 1 }
    } else if (rec == "CONTROL") {
      if (f[1] == "control.id") cid = f[2]
      else if (f[1] == "control.name") c_name = f[2]
      else if (f[1] == "control.pillar") c_pillar = f[2]
    }
  }
  close(ptxfile)
  if (ptx_rc < 0) refuse_c("cannot read scan.ptx")
}
BEGIN {
  while ((getline line < mapfile) > 0) {
    if (line == "" || substr(line, 1, 1) == "#") continue
    n = split(line, f, "\t")
    if (n < 1) continue
    if (f[1] == "id" || f[1] == "ck-id") continue
    ck = f[1]
    fids = (n >= 2) ? f[2] : ""
    tags = (n >= 3) ? f[3] : ""
    if (ck == "") continue
    nf = split(fids, ids, ",")
    for (i = 1; i <= nf; i++) {
      fid = ids[i]
      gsub(/^[ \t]+|[ \t]+$/, "", fid)
      if (fid == "") continue
      if (fid in owner && owner[fid] != ck) refuse_c("ambiguous owner for " fid)
      owner[fid] = ck
      Ftags[fid] = tags
      nord++
      Ord[nord] = fid
    }
  }
  close(mapfile)
  if (nord < 1) refuse_c("cannot read IBM i group registry")
  if (ptxfile == "") refuse_c("cannot read scan.ptx")
  npil = 0
  have_oscore = 0
  oscore = 0
  load_ptx()
}
{
  doc = doc $0 "\n"
}
END {
  if (failed) exit 1
  rest = doc
  pfind = index(rest, "\"findings\"")
  if (!pfind) refuse_c("compose JSON missing findings")
  rest = substr(rest, pfind)
  if (!match(rest, /\[/)) refuse_c("compose JSON missing findings")
  rest = substr(rest, RSTART + 1)
  depth = 0
  in_str = 0
  esc = 0
  obj = ""
  in_obj = 0
  nlen = length("" rest)
  for (i = 1; i <= nlen; i++) {
    c = substr(rest, i, 1)
    if (in_str) {
      obj = obj c
      if (esc) { esc = 0; continue }
      if (c == "\\") { esc = 1; continue }
      if (c == "\"") in_str = 0
      continue
    }
    if (c == "\"") {
      if (in_obj) obj = obj c
      in_str = 1
      continue
    }
    if (c == "{") {
      if (depth == 0) { in_obj = 1; obj = "{" }
      else obj = obj c
      depth++
      continue
    }
    if (c == "}") {
      depth--
      obj = obj c
      if (depth == 0 && in_obj) {
        fid = json_get(obj, "id")
        if (fid == "") refuse_c("malformed finding (missing id)")
        if (!(fid in owner)) refuse_c("no owning row for " fid)
        if (fid in seen_fid) refuse_c("duplicate finding " fid)
        seen_fid[fid] = 1
        Fid[fid] = fid
        Fst[fid] = json_get(obj, "status")
        Fobs[fid] = json_get(obj, "observed")
        Fmean[fid] = json_get(obj, "meaning")
        Ffix[fid] = json_get(obj, "fix")
        Fcat[fid] = json_get(obj, "category")
        Fsev[fid] = json_get(obj, "severity")
        Flab[fid] = json_get(obj, "label")
        if (Fst[fid] == "" || Fcat[fid] == "" || Fsev[fid] == "" || Fmean[fid] == "") {
          refuse_c("malformed finding " fid)
        }
        nfind++
        in_obj = 0
        obj = ""
      }
      continue
    }
    if (c == "]" && depth == 0) break
    if (in_obj) obj = obj c
  }
  if (nfind < 1) refuse_c("compose JSON has no findings")
  print "{"
  printf "  \"compliance\": \"%s\",\n", jesc(std)
  printf "  \"release\": \"%s\",\n", jesc(rel)
  printf "  \"product\": \"%s\",\n", jesc(product)
  printf "  \"edition\": \"%s\",\n", jesc(edition)
  printf "  \"version\": \"%s\",\n", jesc(version)
  print "  \"pillars\": {"
  for (i = 1; i <= npil; i++) {
    pid = Pil[i]
    if (Pstate[pid] == "SCORED") {
      printf "    \"%s\": { \"pass\": %d, \"assessed\": %d, \"total\": %d, \"state\": \"%s\", \"score\": %d, \"band\": \"%s\" }", \
        jesc(pid), Ppass[pid], Pn[pid], Pm[pid], jesc(Pstate[pid]), Pscore[pid] + 0, jesc(Pband[pid])
    } else {
      printf "    \"%s\": { \"pass\": %d, \"assessed\": %d, \"total\": %d, \"state\": \"%s\" }", \
        jesc(pid), Ppass[pid], Pn[pid], Pm[pid], jesc(Pstate[pid])
    }
    if (i < npil) print ","
    else print ""
  }
  print "  },"
  print "  \"summary\": {"
  printf "    \"score_pct\": %d\n", oscore + 0
  print "  },"
  print "  \"findings\": ["
  first = 1
  for (i = 1; i <= nord; i++) {
    fid = Ord[i]
    if (!(fid in seen_fid)) continue
    if (first) first = 0
    else print ","
    lab = Flab[fid]
    if (lab == "") lab = Cname[fid]
    if (lab == "") lab = Fmean[fid]
    if (lab == "") lab = Fid[fid]
    cat = Cpillar[fid]
    if (cat == "") cat = Fcat[fid]
    printf "    { \"id\": \"%s\", \"status\": \"%s\", \"observed\": \"%s\", \"meaning\": \"%s\", \"fix\": \"%s\", \"category\": \"%s\", \"severity\": \"%s\", \"controls\": %s, \"label\": \"%s\" }", \
      jesc(Fid[fid]), jesc(Fst[fid]), jesc(Fobs[fid]), jesc(Fmean[fid]), \
      jesc(Ffix[fid]), jesc(cat), jesc(Fsev[fid]), emit_controls(Ftags[fid]), \
      jesc(lab)
  }
  print ""
  print "  ]"
  print "}"
}
IBMI_JSON_SHAPE
awk -v mapfile="$IBMI_GROUP_REG" -v std="$COMPLIANCE" -v rel="$RELEASE" \
    -v ptxfile="$OUT_DIR/scan.ptx" \
    -v product="PTxray" -v edition="ibmi" -v version="$PTXRAY_RUNNER_VERSION" \
    -v errfile="$WORKDIR/blueprint.err" \
    -f "$JSON_PROG" "$WORKDIR/envelope.json" > "$OUT_DIR/ptxray-ibmi.json"
rc=$?
if [ "$rc" -ne 0 ]; then
  if [ -s "$WORKDIR/blueprint.err" ]; then
    cat "$WORKDIR/blueprint.err" >&2
    exit 4
  fi
  cat "$WORKDIR/blueprint.err" >&2 2>/dev/null
  refuse "cannot write $OUT_DIR/ptxray-ibmi.json"
fi
if [ -s "$WORKDIR/blueprint.err" ]; then
  cat "$WORKDIR/blueprint.err" >&2
  exit 4
fi
if [ ! -s "$OUT_DIR/ptxray-ibmi.json" ]; then
  refuse "ptxray-ibmi.json missing or empty"
fi
printf '%s\n' 'ptxray-ibmi.json' > "$OUT_DIR/producers.tsv" || refuse "cannot write $OUT_DIR/producers.tsv"

if [ "$WANT_HTML" -eq 1 ]; then
  ksh "$RENDER_COMPOSE" --in "$WORKDIR/scored.ptxs" --out "$OUT_DIR"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
  printf 'Report ready: %s\n' "$OUT_DIR/report.html"
fi

if [ "$WANT_JSON" -eq 1 ]; then
  awk '
    /"surface":/ && !done {
      sub(/"surface":[ \t]*"[^"]*"/, "\"surface\": \"compose\"")
      done=1
    }
    { print }
  ' "$WORKDIR/envelope.json" > "$WORKDIR/envelope-compose.json"
  ksh "$REPORT_JSON" --in "$WORKDIR/envelope-compose.json" --out "$OUT_DIR/report.json"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
fi

exit 0
