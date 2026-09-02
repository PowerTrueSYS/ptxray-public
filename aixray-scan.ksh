#!/bin/ksh
# Operator one-shot: exec dest doors. Do not inline their bodies.
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
  USAGE_GROUPS=$(ksh "$RESOLVE" --print-usage runner-scan) || exit $?
  if [ -z "$USAGE_GROUPS" ]; then
    echo "aixray-scan: cannot read group vocabulary" >&2
    exit 2
  fi
fi
# No resolver → no fabricated group list. Omit --compliance alts from
# fallback usage; a supplied value is still rejected at parse (fail closed).
if [ -n "$USAGE_GROUPS" ]; then
  COMPLIANCE_USAGE=' [--compliance '"$USAGE_GROUPS"']'
else
  COMPLIANCE_USAGE=
fi
USAGE='usage: aixray-scan [--html] [--pdf] [--tty] [--json]'"$COMPLIANCE_USAGE"' [--out DIR] [--no-menu] [--flrtvc-report FILE] [--offline | --definitions-bundle FILE] [--currency-status] [--flrt-export DIR]
  --out DIR                   writes reports and scan.ptx
  --flrtvc-report FILE        feeds the report cve pillar as the emitter --exposure
  --offline                   cache-only air-gapped run (/var/ptxray/definitions)
  --definitions-bundle FILE   feeds the currency producer and the html defs provenance
Every run assesses the operational pillars (OS/firmware currency, known vulnerabilities, resilience) in addition to the selected standard.
PTxray downloads the latest signed definitions by default. Opt out with --offline (cache only) or --definitions-bundle FILE to point at definitions you copied in (air-gapped machines).'

PTXRAY_RUNNER_VERSION="1.7.0"

WANT_HTML=0
WANT_PDF=0
WANT_TTY=0
WANT_JSON=0
WANT_CURRENCY=0
NO_MENU=0
COMPLIANCE=
OUT_DIR=
FLRTVC=
BUNDLE=
FLRT_DIR=
DEFINITIONS_OFFLINE=0
DEFINITIONS_OFFLINE_SEEN=0
DEFINITIONS_BUNDLE_SEEN=0
DEFS_SOURCE=

if [ $# -eq 0 ]; then
  # Zero-arg: menu only when stdin and stdout are TTYs; otherwise dest-gate usage.
  if [ -t 0 ] && [ -t 1 ]; then
    MENU_MODE=1
  else
    echo "aixray-scan: $USAGE" >&2
    exit 2
  fi
else
  MENU_MODE=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --html)
        if [ "$WANT_HTML" -eq 1 ]; then
          echo "aixray-scan: $USAGE" >&2
          exit 2
        fi
        WANT_HTML=1
        shift
        ;;
      --pdf)
        if [ "$WANT_PDF" -eq 1 ]; then
          echo "aixray-scan: $USAGE" >&2
          exit 2
        fi
        WANT_PDF=1
        shift
        ;;
      --tty)
        if [ "$WANT_TTY" -eq 1 ]; then
          echo "aixray-scan: $USAGE" >&2
          exit 2
        fi
        WANT_TTY=1
        shift
        ;;
      --json)
        if [ "$WANT_JSON" -eq 1 ]; then
          echo "aixray-scan: $USAGE" >&2
          exit 2
        fi
        WANT_JSON=1
        shift
        ;;
      --compliance)
        shift
        case "${1:-}" in
          ""|--*) echo "aixray-scan: $USAGE" >&2; exit 2 ;;
        esac
        case "|$USAGE_GROUPS|" in
          *"|$1|"*) ;;
          *) echo "aixray-scan: $USAGE" >&2; exit 2 ;;
        esac
        if [ -n "$COMPLIANCE" ]; then
          echo "aixray-scan: $USAGE" >&2
          exit 2
        fi
        COMPLIANCE=$1
        shift
        ;;
      --out)
        shift
        case "${1:-}" in
          ""|--*) echo "aixray-scan: $USAGE" >&2; exit 2 ;;
        esac
        if [ -n "$OUT_DIR" ]; then
          echo "aixray-scan: $USAGE" >&2
          exit 2
        fi
        OUT_DIR=$1
        shift
        ;;
      --no-menu)
        if [ "$NO_MENU" -eq 1 ]; then
          echo "aixray-scan: $USAGE" >&2
          exit 2
        fi
        NO_MENU=1
        shift
        ;;
      --flrtvc-report)
        shift
        case "${1:-}" in
          ""|--*) echo "aixray-scan: $USAGE" >&2; exit 2 ;;
        esac
        if [ -n "$FLRTVC" ]; then
          echo "aixray-scan: $USAGE" >&2
          exit 2
        fi
        FLRTVC=$1
        shift
        ;;
      --definitions-bundle)
        if [ "$DEFINITIONS_BUNDLE_SEEN" -eq 1 ]; then
          echo "aixray-scan: $USAGE" >&2
          echo "ptxray: duplicate --definitions-bundle" >&2
          exit 2
        fi
        DEFINITIONS_BUNDLE_SEEN=1
        shift
        case "${1:-}" in
          ""|--*) echo "aixray-scan: $USAGE" >&2; exit 2 ;;
        esac
        BUNDLE=$1
        shift
        ;;
      --offline)
        if [ "$DEFINITIONS_OFFLINE_SEEN" -eq 1 ]; then
          echo "aixray-scan: $USAGE" >&2
          echo "ptxray: duplicate --offline" >&2
          exit 2
        fi
        DEFINITIONS_OFFLINE_SEEN=1
        DEFINITIONS_OFFLINE=1
        shift
        ;;
      --currency-status)
        if [ "$WANT_CURRENCY" -eq 1 ]; then
          echo "aixray-scan: $USAGE" >&2
          exit 2
        fi
        WANT_CURRENCY=1
        shift
        ;;
      --flrt-export)
        shift
        case "${1:-}" in
          ""|--*) echo "aixray-scan: $USAGE" >&2; exit 2 ;;
        esac
        if [ -n "$FLRT_DIR" ]; then
          echo "aixray-scan: $USAGE" >&2
          exit 2
        fi
        FLRT_DIR=$1
        shift
        ;;
      *)
        echo "aixray-scan: $USAGE" >&2
        exit 2
        ;;
    esac
  done
fi

if [ "$DEFINITIONS_OFFLINE" -eq 1 ] && [ -n "$BUNDLE" ]; then
  echo "aixray-scan: $USAGE" >&2
  echo "ptxray: --offline conflicts with --definitions-bundle" >&2
  exit 2
fi

if [ -n "$BUNDLE" ]; then
  DEFS_SOURCE=bundled
fi

# --- selected modes ---
WANT_ASSESS=0
if [ "$WANT_HTML" -eq 1 ] || [ "$WANT_JSON" -eq 1 ] || [ -n "$COMPLIANCE" ]; then
  WANT_ASSESS=1
fi
WANT_CVE=0
if [ -n "$FLRTVC" ]; then
  WANT_CVE=1
fi
WANT_DEFS=0
if [ -n "$BUNDLE" ]; then
  WANT_DEFS=1
fi
WANT_FLRT=0
if [ -n "$FLRT_DIR" ]; then
  WANT_FLRT=1
fi

# A flag-only invocation with no mode selected is usage.
if [ "$MENU_MODE" -eq 0 ] && [ "$WANT_ASSESS" -eq 0 ] && [ "$WANT_CVE" -eq 0 ] && [ "$WANT_CURRENCY" -eq 0 ] && [ "$WANT_DEFS" -eq 0 ] && [ "$WANT_FLRT" -eq 0 ]; then
  echo "aixray-scan: $USAGE" >&2
  exit 2
fi

# Assessment requires --compliance (no invented default group).
if [ "$WANT_ASSESS" -eq 1 ] && [ -z "$COMPLIANCE" ]; then
  echo "aixray-scan: $USAGE" >&2
  exit 2
fi

# HTML default: --compliance alone, with neither --html nor --json, is HTML.
if [ -n "$COMPLIANCE" ] && [ "$WANT_HTML" -eq 0 ] && [ "$WANT_JSON" -eq 0 ]; then
  WANT_HTML=1
fi

# --html writes a report to a directory, so it requires --out. rpt-compose
# requires --out unconditionally -- its usage string advertises [--tty] as
# though it were an alternative and it is not -- so a no---out HTML run could
# only ever die inside compose. Refuse here, by name, instead.
if [ "$WANT_HTML" -eq 1 ] && [ -z "$OUT_DIR" ]; then
  echo "aixray-scan: --html requires --out DIR" >&2
  exit 2
fi

# --pdf (print form beside the report) and --tty (ASCII snapshot on stderr)
# are modifiers on the report, never modes of their own.
if [ "$WANT_PDF" -eq 1 ] && [ "$WANT_HTML" -eq 0 ]; then
  echo "aixray-scan: $USAGE" >&2
  exit 2
fi
if [ "$WANT_TTY" -eq 1 ] && [ "$WANT_HTML" -eq 0 ]; then
  echo "aixray-scan: $USAGE" >&2
  exit 2
fi

# More than one stdout-publishing product without --out is usage.
N_STDOUT=0
if [ "$WANT_ASSESS" -eq 1 ] && [ "$WANT_JSON" -eq 1 ] && [ -z "$OUT_DIR" ]; then
  N_STDOUT=$((N_STDOUT + 1))
fi
if [ "$WANT_CVE" -eq 1 ] && [ -z "$OUT_DIR" ]; then
  N_STDOUT=$((N_STDOUT + 1))
fi
if [ "$WANT_CURRENCY" -eq 1 ] && [ -z "$OUT_DIR" ]; then
  N_STDOUT=$((N_STDOUT + 1))
fi
# With --html the bundle is an input to the report, not a product of its own:
# its status is rendered into the provenance stamp and the standalone
# acquisition block is not produced. Only the no-report path publishes it.
if [ "$WANT_DEFS" -eq 1 ] && [ "$WANT_HTML" -eq 0 ] && [ -z "$OUT_DIR" ]; then
  N_STDOUT=$((N_STDOUT + 1))
fi
if [ "$N_STDOUT" -gt 1 ]; then
  echo "aixray-scan: $USAGE" >&2
  exit 2
fi

# Scored PTXDOC (Blueprint feed) when --out is set on an assessment that
# has a definitions bundle. HTML already produces it; --json --out must too.
WANT_PTXDOC=0
if [ -n "$OUT_DIR" ] && [ "$WANT_ASSESS" -eq 1 ] && [ "$WANT_DEFS" -eq 1 ]; then
  WANT_PTXDOC=1
fi

# The capture/assess spine door under tools.d/assess/dispatch is deliberately
# NOT wired here. It execs eighteen role atoms that exist in no layout -- not
# under tools.d/assess/, not in dist/tools/ -- so it refuses with
# "missing .../<role>/run.ksh" on every box, and always has. It landed at
# 148e78d7f verified only on its no-args usage leg, never on a real run. Its
# purpose was the probe captures, which the fact-probe door now produces, and
# nothing downstream ever read the assess directory it was handed. Wiring it
# back in means building those eighteen atoms AND pinning the capture filenames
# inside its --out DIR, which no document specifies today.

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
  #                 dist/compose/aixray.ksh, so compose passes that relative
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
    echo "aixray-scan: missing $1" >&2
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

function resolve_ptxray_defs {
  # Beside the runner, then beside the monolith, then on PATH.
  typeset d p
  if [ -f "$HERE/ptxray-defs.sh" ]; then
    printf '%s\n' "$HERE/ptxray-defs.sh"
    return 0
  fi
  if [ -f "$HERE/../ptxray-defs.sh" ]; then
    printf '%s\n' "$HERE/../ptxray-defs.sh"
    return 0
  fi
  for d in "$HERE" "$HERE/.." "$HERE/../.."; do
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
    echo "aixray-scan: cannot read $src" >&2
    exit 2
  fi
  dest=$WORKDIR/definitions.bundle
  if ! cp "$src" "$dest"; then
    echo "aixray-scan: cannot write work dir" >&2
    exit 1
  fi
  BUNDLE=$dest
  WANT_DEFS=1
  if [ -n "$OUT_DIR" ] && [ "$WANT_ASSESS" -eq 1 ]; then
    WANT_PTXDOC=1
  fi
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

function defs_noncache_path {
  # First absolute readable file on downloader stdout that is not the
  # protected cache. Never reopen /var/ptxray/definitions.
  typeset line
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    case "$line" in
      /var/ptxray/definitions|/var/ptxray/definitions/*) continue ;;
      /*)
        if [ -f "$line" ] && [ -r "$line" ]; then
          printf '%s\n' "$line"
          return 0
        fi
        ;;
    esac
  done < "$1"
  return 1
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
  if [ "$rc" -eq 0 ] && [ -f "$snapdir/bundle.ptxray-defs" ] && [ -r "$snapdir/bundle.ptxray-defs" ]; then
    printf '%s\n' "$snapdir/bundle.ptxray-defs"
    return 0
  fi
  return 1
}

function consume_verified_generation {
  # consume_verified_generation DEFS_SH STATUS_FILE ALLOWED
  # ALLOWED is comma-separated status modes (update,cache-fallback or cache).
  # Returns 1 for an invalid status protocol, 2 when the protocol is valid
  # but no private snapshot or downloader-emitted bundle could be consumed.
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
    cand=$(defs_noncache_path "$status_file") || cand=
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
  # refusal naming --definitions-bundle. --definitions-bundle FILE: that file.
  typeset defs_sh rc
  if [ -n "$BUNDLE" ]; then
    DEFS_SOURCE=bundled
    WANT_DEFS=1
    if [ -n "$OUT_DIR" ] && [ "$WANT_ASSESS" -eq 1 ]; then
      WANT_PTXDOC=1
    fi
    return 0
  fi
  if ! defs_sh=$(resolve_ptxray_defs); then
    if [ "$DEFINITIONS_OFFLINE" -eq 1 ]; then
      echo "aixray-scan: --offline: ptxray-defs.sh not found; supply --definitions-bundle FILE" >&2
      exit 4
    fi
    echo "render: --html needs --definitions-bundle FILE (the report stamps definition provenance); PTxray downloads the latest signed definitions by default. Opt out with --offline (cache only) or --definitions-bundle FILE to point at definitions you copied in (air-gapped machines)." >&2
    echo "aixray-scan: ptxray-defs.sh not found; use --definitions-bundle FILE or --offline" >&2
    exit 4
  fi
  if [ "$DEFINITIONS_OFFLINE" -eq 1 ]; then
    invoke_ptxray_defs "$defs_sh" "$WORKDIR/defs-status.out" "$WORKDIR/defs-status.err" --cache
    rc=$?
    if [ "$rc" -ne 0 ]; then
      cat "$WORKDIR/defs-status.err" >&2
      echo "aixray-scan: --offline: signed definitions cache is empty; supply --definitions-bundle FILE" >&2
      exit 4
    fi
    consume_verified_generation "$defs_sh" "$WORKDIR/defs-status.out" "cache"
    rc=$?
    if [ "$rc" -eq 0 ]; then
      return 0
    fi
    echo "aixray-scan: --offline: signed definitions cache could not be verified; supply --definitions-bundle FILE" >&2
    exit 4
  fi
  invoke_ptxray_defs "$defs_sh" "$WORKDIR/defs-status.out" "$WORKDIR/defs-status.err" --update
  rc=$?
  if [ "$rc" -ne 0 ]; then
    cat "$WORKDIR/defs-status.err" >&2
    echo "aixray-scan: definitions download failed; use --definitions-bundle FILE or --offline" >&2
    exit 4
  fi
  consume_verified_generation "$defs_sh" "$WORKDIR/defs-status.out" "update,cache-fallback"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    return 0
  fi
  if [ "$rc" -eq 2 ]; then
    echo "aixray-scan: definitions download produced no bundle; use --definitions-bundle FILE or --offline" >&2
    exit 4
  fi
  echo "aixray-scan: definitions downloader returned an invalid status protocol; use --definitions-bundle FILE or --offline" >&2
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

function definitions_selector_menu {
  # Same three-choice wording as src/definitions-selector.ksh
  # (#@@definitions-selector). Default = disclosed connected update.
  typeset answer local_path
  printf '%s\n' \
    'PTxray downloads the latest signed definitions by default. Opt out with --offline (cache only) or --definitions-bundle FILE to point at definitions you copied in (air-gapped machines).' \
    'PTxray signed definitions' \
    '  Cache age: verified after selection' \
    '  1. Update signed definitions now (default)' \
    '  2. Use the last valid signed cache' \
    '  3. Use a local signed definitions bundle'
  printf '%s' 'Selection [1] (30 seconds): '
  answer=
  IFS= read -r answer || answer=
  [ -n "$answer" ] || answer=1
  case "$answer" in
    1) ;;
    2) DEFINITIONS_OFFLINE=1 ;;
    3)
      printf '%s' 'Local signed bundle path (30 seconds): '
      local_path=
      IFS= read -r local_path || local_path=
      if [ -z "$local_path" ]; then
        echo "aixray-scan: a local signed bundle path is required" >&2
        exit 2
      fi
      BUNDLE=$local_path
      DEFS_SOURCE=bundled
      ;;
    *)
      echo "aixray-scan: choose 1, 2, or 3" >&2
      exit 2
      ;;
  esac
}

# --- menu (zero-arg, stdin+stdout TTY): definitions selector, then compose ---
if [ "$MENU_MODE" -eq 1 ]; then
  definitions_selector_menu
  COMPOSE=$(resolve_door compose.ksh ../../compose/aixray/run.ksh ../compose/aixray.ksh)
  require_door "$COMPOSE"
  ksh "$COMPOSE"
  rc=$?
  exit "$rc"
fi

# --- resolve every selected mode's doors before any exec ---
if [ "$WANT_ASSESS" -eq 1 ]; then
  COMPOSE=$(resolve_door compose.ksh ../../compose/aixray/run.ksh ../compose/aixray.ksh)
  FACT_PROBE=$(resolve_door fact-probe.ksh ../../probe/facts/run.ksh)
  FACT_IDENTITY=$(resolve_door fact-identity.ksh ../../facts/identity/run.ksh)
  FACT_OS=$(resolve_door fact-os.ksh ../../facts/os/run.ksh)
  FACT_FIRMWARE=$(resolve_door fact-firmware.ksh ../../facts/firmware/run.ksh)
  FACT_CPU=$(resolve_door fact-cpu.ksh ../../facts/cpu/run.ksh)
  FACT_MEMORY=$(resolve_door fact-memory.ksh ../../facts/memory/run.ksh)
  FACT_PAGING=$(resolve_door fact-paging.ksh ../../facts/paging/run.ksh)
  FACT_STORAGE=$(resolve_door fact-storage.ksh ../../facts/storage/run.ksh)
  FACT_RECOVERY=$(resolve_door fact-recovery.ksh ../../facts/recovery/run.ksh)
  FACT_FILESYSTEMS=$(resolve_door fact-filesystems.ksh ../../facts/filesystems/run.ksh)
  require_door "$COMPOSE"
  require_door "$FACT_PROBE"
  require_door "$FACT_IDENTITY"
  require_door "$FACT_OS"
  require_door "$FACT_FIRMWARE"
  require_door "$FACT_CPU"
  require_door "$FACT_MEMORY"
  require_door "$FACT_PAGING"
  require_door "$FACT_STORAGE"
  require_door "$FACT_RECOVERY"
  require_door "$FACT_FILESYSTEMS"
  # VERIFIED against the landed render family. rpt-emitter takes five named
  # inputs and writes the PTXDOC to stdout -- it has no --out:
  #   --envelope F --facts DIR --currency F --defs F --manifests F.tsv
  # --manifests is shipped build-time data, never generated on the box.
  #
  # VERIFIED against the landed tools.d/render/score-formulas and
  # tools.d/render/apply-scores: score-formulas computes a scores sidecar to
  # stdout from --in FILE (it renders nothing); apply-scores reads --in FILE
  # and --scores FILE and writes the scored document to stdout (it has no
  # --out). This runner always runs score-formulas itself and passes the
  # sidecar to apply-scores via --scores, rather than letting apply-scores
  # invoke score-formulas implicitly, so the sidecar this runner used is an
  # explicit, inspectable file on disk.
  if [ "$WANT_HTML" -eq 1 ] || [ "$WANT_PTXDOC" -eq 1 ]; then
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
    # rpt-emitter requires a readable --defs document. The default is to
    # download one via ptxray-defs.sh --update; --offline uses
    # ptxray-defs.sh --cache; --definitions-bundle FILE is the air-gapped
    # opt-out. Acquire happens after WORKDIR exists so a missing downloader
    # is a typed refusal, not a silent empty provenance stamp.
    DEF_EVAL_FOR_HTML=$(resolve_door definitions-evaluate.ksh ../../definitions/evaluate/run.ksh)
    require_door "$DEF_EVAL_FOR_HTML"
    # The report renders currency controls, so the producer + evaluate pair is
    # resolved for this lane too; the pair itself runs once, below, whether or
    # not the standalone --currency-status lane is selected.
    CUR_PRODUCER=$(resolve_door currency-producer.ksh ../../currency/producer/run.ksh)
    CUR_EVAL=$(resolve_door currency-evaluate.ksh ../../currency/evaluate/run.ksh)
    require_door "$CUR_PRODUCER"
    require_door "$CUR_EVAL"
    if [ -n "$FLRTVC" ]; then
      # A live FLRTVC report feeds the emitter's cve pillar as --exposure.
      CVE_TABLE_PARSE=$(resolve_door cve-table-parse.ksh ../../cve-table/parse/run.ksh)
      require_door "$CVE_TABLE_PARSE"
    fi
    RENDER_CONTRACT=$(resolve_door render-contract.ksh ../../render/contract/validate ../render/contract/validate)
  fi
  if [ "$WANT_JSON" -eq 1 ]; then
    REPORT_JSON=$(resolve_door report-json.ksh ../../report/json/run.ksh)
    require_door "$REPORT_JSON"
  fi
fi
if [ "$WANT_CVE" -eq 1 ]; then
  CVE_TABLE=$(resolve_door cve-table.ksh ../../cve-table/cve-table/run.ksh)
  require_door "$CVE_TABLE"
fi
if [ "$WANT_CURRENCY" -eq 1 ]; then
  CUR_PRODUCER=$(resolve_door currency-producer.ksh ../../currency/producer/run.ksh)
  CUR_EVAL=$(resolve_door currency-evaluate.ksh ../../currency/evaluate/run.ksh)
  CUR_JSON=$(resolve_door currency-json.ksh ../../currency/json/run.ksh)
  CUR_TEXT=$(resolve_door currency-text.ksh ../../currency/text/run.ksh)
  CUR_HTML=$(resolve_door currency-html.ksh ../../currency/html/run.ksh)
  require_door "$CUR_PRODUCER"
  require_door "$CUR_EVAL"
  require_door "$CUR_JSON"
  require_door "$CUR_TEXT"
  require_door "$CUR_HTML"
fi
if [ "$WANT_DEFS" -eq 1 ] && [ "$WANT_HTML" -eq 0 ]; then
  DEF_PARSE=$(resolve_door definitions-parse.ksh ../../definitions/parse/run.ksh)
  DEF_EVAL=$(resolve_door definitions-evaluate.ksh ../../definitions/evaluate/run.ksh)
  DEF_HTML=$(resolve_door definitions-acquisition-html.ksh ../../definitions/acquisition-html/run.ksh)
  require_door "$DEF_PARSE"
  require_door "$DEF_EVAL"
  require_door "$DEF_HTML"
fi
if [ "$WANT_FLRT" -eq 1 ]; then
  FLRT=$(resolve_door flrt-export.ksh ../../flrt-export/run.ksh)
  require_door "$FLRT"
fi

# --- --out DIR must be an existing directory ---
if [ -n "$OUT_DIR" ]; then
  if [ ! -d "$OUT_DIR" ]; then
    echo "aixray-scan: cannot write $OUT_DIR" >&2
    exit 2
  fi
fi

# --- unreadable required files ---
if [ -n "$FLRTVC" ]; then
  if [ ! -f "$FLRTVC" ] || [ ! -r "$FLRTVC" ]; then
    echo "aixray-scan: cannot read $FLRTVC" >&2
    exit 2
  fi
fi
if [ -n "$BUNDLE" ]; then
  if [ ! -f "$BUNDLE" ] || [ ! -r "$BUNDLE" ]; then
    echo "aixray-scan: cannot read $BUNDLE" >&2
    exit 2
  fi
fi

# --- work TMP for assessment / currency / definitions ---
WORKDIR=
if [ "$WANT_ASSESS" -eq 1 ] || [ "$WANT_CURRENCY" -eq 1 ] || [ "$WANT_DEFS" -eq 1 ]; then
  WORKDIR=${TMPDIR:-/tmp}/aixray-scan.$$
  umask 077
  mkdir "$WORKDIR" || { echo "aixray-scan: cannot write work dir" >&2; exit 1; }
  trap 'rm -rf "$WORKDIR"' 0 1 2 3 15
fi

if [ -n "$OUT_DIR" ]; then
  DEST=$OUT_DIR
else
  DEST=$WORKDIR
fi

# HTML (and scored PTXDOC) need a definitions bundle. Default: download.
# --offline: cache only. --definitions-bundle FILE: that file, no network.
if [ "$WANT_HTML" -eq 1 ] || [ "$WANT_PTXDOC" -eq 1 ]; then
  acquire_definitions
elif [ "$DEFINITIONS_OFFLINE" -eq 1 ] && [ "$WANT_CURRENCY" -eq 1 ]; then
  acquire_definitions
fi

# --- currency state: one producer + evaluate run per scan, not per lane ---
# The report (--html) and the standalone --currency-status lane both render
# evaluated currency state, so it is produced exactly once and shared. A
# failing producer is a scan failure named on stderr, never a silent empty
# file handed to the emitter.
if [ "$WANT_HTML" -eq 1 ] || [ "$WANT_CURRENCY" -eq 1 ] || [ "$WANT_PTXDOC" -eq 1 ]; then
  REGISTRY=$(resolve_data ../data/source-registry.json ../../../data/source-registry.json)
  if [ -n "$BUNDLE" ]; then
    ksh "$CUR_PRODUCER" --registry "$REGISTRY" --definitions-bundle "$BUNDLE" --out "$WORKDIR/producers.tsv"
  else
    ksh "$CUR_PRODUCER" --registry "$REGISTRY" --out "$WORKDIR/producers.tsv"
  fi
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  ksh "$CUR_EVAL" --in "$WORKDIR/producers.tsv" --out "$WORKDIR/state.tsv"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
fi

# --- exec order: currency state, flrt-export, fact-probe, facts, compose,
#     render chain (emitter, score-formulas, apply-scores, compose),
#     report-json, cve-table, currency, definitions. Exit the first non-zero. ---

if [ "$WANT_FLRT" -eq 1 ]; then
  ksh "$FLRT" --out "$FLRT_DIR"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
fi

if [ "$WANT_ASSESS" -eq 1 ]; then
  # The fact tools are pure transformers: they read a capture on --in and
  # never probe. fact-probe is the door that runs the read-only probes on this
  # box and writes one capture per fact. A probe the box cannot answer leaves
  # its capture empty and the fact emits its typed null.
  ksh "$FACT_PROBE" --out "$WORKDIR/probe"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  ksh "$FACT_IDENTITY" --in "$WORKDIR/probe/identity" --out "$DEST/fact-identity.json"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  ksh "$FACT_OS" --in "$WORKDIR/probe/os" --out "$DEST/fact-os.json"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  ksh "$FACT_FIRMWARE" --in "$WORKDIR/probe/firmware" --out "$DEST/fact-firmware.json"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  ksh "$FACT_CPU" --in "$WORKDIR/probe/cpu" --out "$DEST/fact-cpu.json"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  ksh "$FACT_MEMORY" --in "$WORKDIR/probe/memory" --out "$DEST/fact-memory.json"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  ksh "$FACT_PAGING" --in "$WORKDIR/probe/paging" --out "$DEST/fact-paging.json"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  ksh "$FACT_STORAGE" --in "$WORKDIR/probe/storage" --out "$DEST/fact-storage.json"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  ksh "$FACT_RECOVERY" --in "$WORKDIR/probe/recovery" --out "$DEST/fact-recovery.json"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  ksh "$FACT_FILESYSTEMS" --in "$WORKDIR/probe/filesystems" --out "$DEST/fact-filesystems.json"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  COMPOSE_OPS=
  if [ "$COMPLIANCE" != all ] && [ "$COMPLIANCE" != ops ]; then
    COMPOSE_OPS=ops
  fi
  if [ -n "$COMPOSE_OPS" ]; then
    ksh "$COMPOSE" --json --no-menu --group "$COMPLIANCE" --group ops >"$WORKDIR/envelope.json"
  else
    ksh "$COMPOSE" --json --no-menu --group "$COMPLIANCE" >"$WORKDIR/envelope.json"
  fi
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  if [ "$WANT_PTXDOC" -eq 1 ]; then
    # Definition status for the report's provenance stamp. Evaluated here, not
    # in the definitions lane below, so it is ready before the emitter and runs
    # exactly once whichever lanes are selected.
    ksh "$DEF_EVAL_FOR_HTML" --bundle "$BUNDLE" --out "$WORKDIR/status.json"
    rc=$?
    if [ "$rc" -ne 0 ]; then
      exit "$rc"
    fi
    stamp_defs_status "$WORKDIR/status.json" "$DEFS_SOURCE"

    # Currency state came from the single producer+evaluate run above; it is
    # never truncated here.

    # Emitter scan-time converter requires "YYYY-MM-DD HH:MM TZ". Compose
    # writes AIXRAY_TODAY verbatim, and fixture runs pin a date-only value.
    # Pad that date to noon UTC for the emitter only; envelope.json (JSON
    # report) is unchanged.
    EMIT_ENVELOPE=$WORKDIR/envelope.json
    GEN=$(sed -n 's/^[[:space:]]*"generated":[[:space:]]*"\([^"]*\)".*/\1/p' "$WORKDIR/envelope.json" | sed -n '1p')
    case "$GEN" in
      [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])
        awk -v g="$GEN 12:00 UTC" '
          /"generated":/ && !done {
            sub(/"generated":[ \t]*"[^"]*"/, "\"generated\": \"" g "\"")
            done=1
          }
          { print }
        ' "$WORKDIR/envelope.json" > "$WORKDIR/envelope-emit.json"
        EMIT_ENVELOPE=$WORKDIR/envelope-emit.json
        ;;
    esac

    if [ -n "$FLRTVC" ]; then
      # A live FLRTVC report feeds the emitter's cve pillar as --exposure.
      # Without one the emitter emits its typed NOT_ASSESSED; no empty
      # exposure file is ever created.
      ksh "$CVE_TABLE_PARSE" --flrtvc-report "$FLRTVC" >"$WORKDIR/exposure.tsv"
      rc=$?
      if [ "$rc" -ne 0 ]; then
        exit "$rc"
      fi
      # A clean report (header + "No vulnerabilities" only) parses to zero
      # bytes. The emitter reads an empty exposure file as a broken pipeline
      # (NOT_ASSESSED) and a non-empty file with no data rows as determinate
      # absence (PASS); stamp the successful no-row parse so it can never be
      # mistaken for a pipeline that produced nothing.
      if [ ! -s "$WORKDIR/exposure.tsv" ]; then
        echo '# clean FLRTVC report: no exposure rows' > "$WORKDIR/exposure.tsv"
      fi
      ksh "$RENDER_EMITTER" \
        --envelope "$EMIT_ENVELOPE" \
        --facts "$DEST" \
        --currency "$WORKDIR/state.tsv" \
        --defs "$WORKDIR/status.json" \
        --manifests "$MANIFESTS" \
        --scanner-version "$PTXRAY_RUNNER_VERSION" \
        --exposure "$WORKDIR/exposure.tsv" >"$WORKDIR/document.ptxs"
    else
      ksh "$RENDER_EMITTER" \
        --envelope "$EMIT_ENVELOPE" \
        --facts "$DEST" \
        --currency "$WORKDIR/state.tsv" \
        --defs "$WORKDIR/status.json" \
        --manifests "$MANIFESTS" \
        --scanner-version "$PTXRAY_RUNNER_VERSION" >"$WORKDIR/document.ptxs"
    fi
    rc=$?
    if [ "$rc" -ne 0 ]; then
      exit "$rc"
    fi

    ksh "$RENDER_SCORE_FORMULAS" --in "$WORKDIR/document.ptxs" > "$WORKDIR/scores.tsv"
    rc=$?
    if [ "$rc" -ne 0 ]; then
      exit "$rc"
    fi

    ksh "$RENDER_APPLY_SCORES" --in "$WORKDIR/document.ptxs" --scores "$WORKDIR/scores.tsv" > "$WORKDIR/scored.ptxs"
    rc=$?
    if [ "$rc" -ne 0 ]; then
      exit "$rc"
    fi

    # Currency state is not the PTXDOC; copy it even if the validator refuses.
    if ! cp "$WORKDIR/producers.tsv" "$OUT_DIR/producers.tsv"; then
      echo "aixray-scan: cannot write $OUT_DIR/producers.tsv" >&2
      exit 2
    fi

    # Never ship an invalid Blueprint feed. Missing validator: do not write.
    KEEP_PTX=0
    if [ -f "$RENDER_CONTRACT" ]; then
      ksh "$RENDER_CONTRACT" --in "$WORKDIR/scored.ptxs" \
        >"$WORKDIR/scan-validate.out" 2>"$WORKDIR/scan-validate.err"
      vrc=$?
      if [ "$vrc" -eq 0 ]; then
        KEEP_PTX=1
      else
        cat "$WORKDIR/scan-validate.err" >&2
      fi
    fi
    if [ "$KEEP_PTX" -eq 1 ]; then
      if ! cp "$WORKDIR/scored.ptxs" "$OUT_DIR/scan.ptx"; then
        echo "aixray-scan: cannot write $OUT_DIR/scan.ptx" >&2
        exit 2
      fi
      chmod 0600 "$OUT_DIR/scan.ptx"
      printf 'Report ready: %s\n' "$OUT_DIR/scan.ptx"
    fi
  fi

  if [ "$WANT_HTML" -eq 1 ]; then
    # --out is always present here: --html requires it. --tty adds the ASCII
    # snapshot on stderr; it is a modifier beside --out, never a substitute.
    set -- --in "$WORKDIR/scored.ptxs" --out "$OUT_DIR"
    if [ "$WANT_PDF" -eq 1 ]; then
      set -- "$@" --pdf
    fi
    if [ "$WANT_TTY" -eq 1 ]; then
      set -- "$@" --tty
    fi
    ksh "$RENDER_COMPOSE" "$@"
    rc=$?
    if [ "$rc" -ne 0 ]; then
      exit "$rc"
    fi
  fi

  if [ "$WANT_JSON" -eq 1 ]; then
    if [ -n "$OUT_DIR" ]; then
      ksh "$REPORT_JSON" --in "$WORKDIR/envelope.json" --out "$OUT_DIR/report.json"
    else
      ksh "$REPORT_JSON" --in "$WORKDIR/envelope.json"
    fi
    rc=$?
    if [ "$rc" -ne 0 ]; then
      exit "$rc"
    fi
  fi
fi

if [ "$WANT_CVE" -eq 1 ]; then
  if [ -n "$OUT_DIR" ]; then
    ksh "$CVE_TABLE" --flrtvc-report "$FLRTVC" --out "$OUT_DIR/cve-table.html"
  else
    ksh "$CVE_TABLE" --flrtvc-report "$FLRTVC"
  fi
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
fi

if [ "$WANT_CURRENCY" -eq 1 ]; then
  # state.tsv came from the single producer+evaluate run above. currency.json
  # is produced first so the text and html renderers consume JSON, never TSV.
  if [ -n "$OUT_DIR" ]; then
    CURRENCY_JSON=$OUT_DIR/currency.json
  else
    CURRENCY_JSON=$WORKDIR/currency.json
  fi

  ksh "$CUR_JSON" --in "$WORKDIR/state.tsv" --out "$CURRENCY_JSON"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
  # Without --out, --currency-status publishes the JSON on stdout -- the one
  # stdout-publishing product this mode advertises (the sibling runner keeps
  # the same contract). The JSON lives in the work dir, which is removed at
  # exit, so copy it out now rather than leaving the mode silent.
  if [ -z "$OUT_DIR" ]; then
    cat "$CURRENCY_JSON"
    rc=$?
    if [ "$rc" -ne 0 ]; then
      echo "aixray-scan: cannot write currency.json to stdout" >&2
      exit "$rc"
    fi
  fi

  if [ -n "$OUT_DIR" ]; then
    ksh "$CUR_TEXT" --in "$CURRENCY_JSON" --out "$OUT_DIR/currency.txt"
  else
    ksh "$CUR_TEXT" --in "$CURRENCY_JSON" --out "$WORKDIR/currency.txt"
  fi
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  if [ -n "$OUT_DIR" ]; then
    ksh "$CUR_HTML" --in "$CURRENCY_JSON" --out "$OUT_DIR/currency.html"
  else
    ksh "$CUR_HTML" --in "$CURRENCY_JSON" --out "$WORKDIR/currency.html"
  fi
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
fi

if [ "$WANT_DEFS" -eq 1 ] && [ "$WANT_HTML" -eq 0 ]; then
  ksh "$DEF_PARSE" --bundle "$BUNDLE" --out "$WORKDIR/parsed.json"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  ksh "$DEF_EVAL" --bundle "$BUNDLE" --out "$WORKDIR/status.json"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi

  if [ -n "$OUT_DIR" ]; then
    ksh "$DEF_HTML" --in "$WORKDIR/status.json" --out "$OUT_DIR/acquisition.html"
  else
    ksh "$DEF_HTML" --in "$WORKDIR/status.json"
  fi
  rc=$?
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
fi

exit 0
