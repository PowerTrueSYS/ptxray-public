#!/bin/ksh
# Generated standalone PTxray check support. READ-ONLY: captures only; no
# remediation, service control, network access, or durable target-host writes.
set -u

# This literal is stamped by the assembler. Runtime environment cannot change
# whether private fixture hooks are active.
PTXRAY_PRIVATE_TEST_BUILD=0
if [ "$PTXRAY_PRIVATE_TEST_BUILD" -ne 1 ]; then
  unset AIXRAY_FIXTURES AIXRAY_CAPTURE_DIR AIXRAY_TODAY AIXRAY_NO_MENU AIXRAY_VIOS_DEV AIXRAY_NO_BUNDLED_FLRTVC AIXRAY_PROBE_LOG
fi

# Match the monolith's guarded AIX command search path and parsing locale.
PATH=/usr/bin:/bin:/etc:/usr/sbin:/usr/ucb:/usr/bin/X11:/sbin:/usr/ios/cli
export PATH
LC_ALL=C
export LC_ALL

# Composed-path product version. Dispatch, standalone_emit, and assembled
# doors read this assignment. It is not derived from the monolith.
AIXRAY_STANDALONE_VERSION="1.7.0"

# aix_capture_dir_ok — true when AIXRAY_CAPTURE_DIR is set, exists, and is
# writable. Never mkdir. On first unusable directory, print one stderr line
# naming it and set AIXRAY_CAPTURE_DIR_WARNED so later probes (including
# those inside $(aix) subshells, which inherit the flag from the parent)
# do not repeat the line. Call from the parent shell before the first
# substitution so the door names the directory once.
function aix_capture_dir_ok {
  if [ -z "${AIXRAY_CAPTURE_DIR:-}" ]; then
    return 1
  fi
  if [ -d "$AIXRAY_CAPTURE_DIR" ] && [ -w "$AIXRAY_CAPTURE_DIR" ]; then
    return 0
  fi
  if [ -z "${AIXRAY_CAPTURE_DIR_WARNED:-}" ]; then
    echo "AIXRAY_CAPTURE_DIR is not a writable directory: $AIXRAY_CAPTURE_DIR" >&2
    AIXRAY_CAPTURE_DIR_WARNED=1
  fi
  return 1
}

# aix <key> <command> [args...] — fixture-aware, read-only capture boundary.
function aix {
  typeset key rc
  key=$1
  shift
  if [ "$PTXRAY_PRIVATE_TEST_BUILD" -eq 1 ] \
      && [ -n "${AIXRAY_PROBE_LOG:-}" ]; then
    printf '%s\n' "$key" >> "$AIXRAY_PROBE_LOG" || return 126
  fi
  if [ -n "${AIXRAY_FIXTURES:-}" ]; then
    if [ -r "$AIXRAY_FIXTURES/$key.out" ]; then
      cat "$AIXRAY_FIXTURES/$key.out"
      rc=0
      [ -r "$AIXRAY_FIXTURES/$key.rc" ] && read rc < "$AIXRAY_FIXTURES/$key.rc"
      return $rc
    fi
    return 127
  fi
  # Capture mode: record what each probe actually returned on a live box, so a
  # fixture set is a genuine capture rather than a hand-maintained transcription.
  # Off unless AIXRAY_CAPTURE_DIR is set. Writes ONLY into that directory and
  # never alters the system under inspection. Never mkdir: a missing or
  # unwritable directory falls back to the live branch and names the path once.
  if [ -n "${AIXRAY_CAPTURE_DIR:-}" ]; then
    if aix_capture_dir_ok; then
      "$@" > "$AIXRAY_CAPTURE_DIR/$key.out" 2>/dev/null
      rc=$?
      if [ "$rc" -ne 0 ]; then
        echo "$rc" > "$AIXRAY_CAPTURE_DIR/$key.rc"
      else
        rm -f "$AIXRAY_CAPTURE_DIR/$key.rc"
      fi
      cat "$AIXRAY_CAPTURE_DIR/$key.out"
      return $rc
    fi
  fi
  "$@" 2>/dev/null
}

# aixv preserves stderr as evidence, for read-only commands that write their
# version banner or diagnostics there rather than to stdout. (Deliberately no
# example command name here: this comment is copied into every standalone tool,
# and tools/ci/egress-lint.sh reads a banned network command name in a
# comment as a violation just as it would in a command position.)
function aixv {
  typeset key rc
  key=$1
  shift
  if [ -n "${AIXRAY_FIXTURES:-}" ]; then
    if [ -r "$AIXRAY_FIXTURES/$key.out" ] || [ -r "$AIXRAY_FIXTURES/$key.err" ]; then
      [ -r "$AIXRAY_FIXTURES/$key.out" ] && cat "$AIXRAY_FIXTURES/$key.out"
      [ -r "$AIXRAY_FIXTURES/$key.err" ] && cat "$AIXRAY_FIXTURES/$key.err"
      rc=0
      [ -r "$AIXRAY_FIXTURES/$key.rc" ] && read rc < "$AIXRAY_FIXTURES/$key.rc"
      return $rc
    fi
    return 127
  fi
  # Capture mode — MUST exist here, not only in aix(). Without it a live
  # capture simply never records an aixv() key, and replay then hits the
  # "both files absent" branch above and returns 127. The two channels are
  # recorded SEPARATELY so the fixture keeps the distinction this wrapper
  # exists for, then emitted out-then-err to match replay ordering. Never
  # mkdir: a missing or unwritable directory falls back to the live branch
  # and names the path once.
  if [ -n "${AIXRAY_CAPTURE_DIR:-}" ]; then
    if aix_capture_dir_ok; then
      "$@" > "$AIXRAY_CAPTURE_DIR/$key.out" 2> "$AIXRAY_CAPTURE_DIR/$key.err"
      rc=$?
      if [ "$rc" -ne 0 ]; then
        echo "$rc" > "$AIXRAY_CAPTURE_DIR/$key.rc"
      else
        rm -f "$AIXRAY_CAPTURE_DIR/$key.rc"
      fi
      cat "$AIXRAY_CAPTURE_DIR/$key.out"
      cat "$AIXRAY_CAPTURE_DIR/$key.err"
      return $rc
    fi
  fi
  "$@" 2>&1
}

# aix_capture_missing <key> — fixture-replay helper: true (rc=0) iff no capture
# exists for <key> at all, i.e. the rc a probe just received was the "no
# capture" default and not a genuine command status. aix()/aixv() return 127 for
# BOTH a missing capture and a genuinely absent command, so a module that wants
# to claim "the command is not installed" must first rule out "nobody captured
# it". Live mode returns false (rc=1): a real box has no concept of a missing
# fixture, and rc=127 there genuinely means the command was not found. Must be
# called in the PARENT shell after the probe, not inside the $(aix ...)
# substitution. Byte-for-byte the monolith's semantics (src/ptxray-aix.sh.in);
# without it here, an undefined-command rc of 127 makes the guard read false and
# the caller launders a missing capture into NOT_APPLICABLE.
function aix_capture_missing {
  if [ -n "${AIXRAY_FIXTURES:-}" ]; then
    if [ -r "$AIXRAY_FIXTURES/$1.out" ] || [ -r "$AIXRAY_FIXTURES/$1.err" ]; then
      return 1
    fi
    return 0
  fi
  return 1
}

# count_nonempty_lines <command> [args...] — stream a potentially large command
# through awk and emit only its small decimal count. The producer appends its rc
# as a completion marker so awk, whose status is the pipeline status on ksh88,
# can propagate a failed/incomplete producer instead of laundering it through a
# successful count. Keep this byte-for-byte aligned with the monolith helper.
function count_nonempty_lines {
  {
    "$@" 2>&1
    printf '__AIXRAY_COUNT_RC__=%s\n' "$?"
  } | awk '
    /^__AIXRAY_COUNT_RC__=[0-9][0-9]*$/ {
      markers++
      capture_rc=$0
      sub(/^__AIXRAY_COUNT_RC__=/,"",capture_rc)
      next
    }
    NF { count++ }
    END {
      if (markers != 1) exit 125
      if (capture_rc+0 != 0) exit capture_rc+0
      print count+0
    }'
}

function jesc {
  awk 'BEGIN{ORS=""} {
    gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); gsub(/\t/,"\\t"); gsub(/\r/,"\\r")
    gsub(/[\001-\010\013\014\016-\037]/,"")
    if (NR>1) printf "\\n"
    print
  }'
}

function valid_json_number {
  printf '%s\n' "$1" | awk '
    NR==1 && $0 ~ /^-?(0|[1-9][0-9]*)([.][0-9]+)?([eE][+-]?[0-9]+)?$/ {ok=1}
    END{exit ok?0:1}'
}

# The standalone finding accumulator intentionally carries only fields in the
# section-1.2 envelope. A failure here is internal (exit 1), never a partial
# JSON document.
set -A F_CAT
set -A F_ID
set -A F_ST
set -A F_SEV
set -A F_OBS
set -A F_MEAN
set -A F_FIX
NFIND=0

function add {
  case "$1" in
    lifecycle|patch|storage|performance|errors|resilience|security|config|monitoring) ;;
    *) echo "$AIXRAY_TOOL: internal error: unknown category '$1'" >&2; exit 1;;
  esac
  case "$4" in
    # NOT_APPLICABLE is a verdict, not a refusal: the control constrains a
    # property of a thing that need not exist. It is already a first-class
    # status in the monolith (vios_level on a plain AIX LPAR) and in the
    # contract schema (STATUSES, pipeline/contract_v2/schema.py), but was
    # missing here, so any standalone tool reaching that branch aborted with
    # an internal error instead of emitting its envelope.
    PASS|WARN|FAIL|NOT_ASSESSED|NOT_APPLICABLE) ;;
    *) echo "$AIXRAY_TOOL: internal error: unknown status '$4'" >&2; exit 1;;
  esac
  F_CAT[$NFIND]=$1
  F_ID[$NFIND]=$2
  F_ST[$NFIND]=$4
  F_SEV[$NFIND]=$5
  F_OBS[$NFIND]=$6
  F_MEAN[$NFIND]=$7
  F_FIX[$NFIND]=$8
  NFIND=$((NFIND + 1))
}

MYUID=""
TODAY=""
TODAY_J=0
C7=""
C30=""
NOW=""

# Date math is pure integer arithmetic because AIX does not provide GNU date.
# Validate the full calendar date before any of its fields can reach an
# arithmetic context: ksh recursively evaluates arithmetic expressions stored
# in variables, and the Julian formula also normalizes impossible dates.
function is_leap_year {
  typeset y=$1
  y=${y#0}; y=${y#0}; y=${y#0}
  if [ $((y % 400)) -eq 0 ]; then echo 1
  elif [ $((y % 100)) -eq 0 ]; then echo 0
  elif [ $((y % 4)) -eq 0 ]; then echo 1
  else echo 0; fi
}

function valid_ymd {
  typeset ymd=$1 y m d rest dim
  case "$ymd" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
    *) echo 0; return;;
  esac
  y=${ymd%%-*}; rest=${ymd#*-}; m=${rest%%-*}; d=${rest#*-}
  m=${m#0}; d=${d#0}
  [ -z "$m" ] && m=0; [ -z "$d" ] && d=0
  if [ "$m" -lt 1 ] || [ "$m" -gt 12 ]; then echo 0; return; fi
  case "$m" in
    1|3|5|7|8|10|12) dim=31;;
    4|6|9|11) dim=30;;
    2) if [ "$(is_leap_year "$y")" -eq 1 ]; then dim=29; else dim=28; fi;;
    *) echo 0; return;;
  esac
  if [ "$d" -lt 1 ] || [ "$d" -gt "$dim" ]; then echo 0; else echo 1; fi
}

function d2j {
  typeset ymd y m d a
  ymd=$1
  if [ "$(valid_ymd "$ymd")" != 1 ]; then
    echo "${AIXRAY_TOOL:-standalone}: internal error: d2j requires a real calendar date in YYYY-MM-DD format" >&2
    return 1
  fi
  y=${ymd%%-*}
  m=${ymd#*-}; m=${m%%-*}
  d=${ymd##*-}
  m=${m#0}; d=${d#0}
  a=$(( (14 - m) / 12 ))
  y=$(( y + 4800 - a ))
  m=$(( m + 12*a - 3 ))
  echo $(( d + (153*m + 2)/5 + 365*y + y/4 - y/100 + y/400 - 32045 ))
}

function j2d {
  typeset a b c d e m
  a=$(( $1 + 32044 ))
  b=$(( (4*a + 3) / 146097 ))
  c=$(( a - 146097*b/4 ))
  d=$(( (4*c + 3) / 1461 ))
  e=$(( c - 1461*d/4 ))
  m=$(( (5*e + 2) / 153 ))
  echo "$(( 100*b + d - 4800 + m/10 )) $(( m + 3 - 12*(m/10) )) $(( e - (153*m + 2)/5 + 1 ))"
}

function errpt_cutoff {
  j2d $(( TODAY_J - $1 )) | awk '{printf "%02d%02d0000%02d", $2, $3, $1 % 100}'
}

# ---- canonical source currency -------------------------------------------------------
# A standalone door reads its source-registry rows from the CR_* arrays the
# assembler embeds (the same emit_currency_registry output the monolith gets
# from #@@embed-currency-registry).  CU_* is the evaluated copy for this run.
# currency_source_status is the read-only accessor: it prints one row's status
# and reason exactly as the monolith's currency_evaluate would, so a check
# fragment can refuse honestly when its reference row is not CURRENT.
set -A CU_ID; set -A CU_LABEL; set -A CU_CLASS; set -A CU_REQUIRED
set -A CU_LOADED; set -A CU_VERSION; set -A CU_VERSION_BASIS
set -A CU_ASOF; set -A CU_ASOF_BASIS; set -A CU_SHA256; set -A CU_LOCATOR
set -A CU_THRESHOLD; set -A CU_INTEGRITY; set -A CU_PROVENANCE
set -A CU_AGE; set -A CU_STATUS; set -A CU_REASON; set -A CU_OVERRIDE
CURRENCY_STATUS=UNVERIFIED
CURRENCY_INTERNAL_ERROR=""

function currency_normalize_metadata {
  typeset value
  value=$1
  case "$value" in
    ""|unknown) printf '%s' unknown; return 0;;
  esac
  if printf '%s\n' "$value" \
      | awk '$0 ~ /^[ \t]*$/ {blank=1} END{exit blank?0:1}'; then
    printf '%s' unknown
  else
    printf '%s' "$value"
  fi
}

# currency_source_index <source-id> — echoes the CU_ row index for a source id,
# rc 0 when found, rc 1 when absent.  Byte-for-byte the monolith's helper.
function currency_source_index {
  typeset wanted ci
  wanted=$1; ci=0
  while [ "$ci" -lt "$CURRENCY_SOURCE_COUNT" ]; do
    if [ "${CU_ID[$ci]}" = "$wanted" ]; then echo "$ci"; return 0; fi
    ci=$((ci+1))
  done
  return 1
}

# currency_copy_registry — evaluate a copy of the embedded CR_* rows, leaving
# the CR_* arrays themselves untouched.
function currency_copy_registry {
  typeset ci
  ci=0
  while [ "$ci" -lt "$CURRENCY_SOURCE_COUNT" ]; do
    CU_ID[$ci]=${CR_ID[$ci]}
    CU_LABEL[$ci]=${CR_LABEL[$ci]}
    CU_CLASS[$ci]=${CR_CLASS[$ci]}
    CU_REQUIRED[$ci]=${CR_REQUIRED[$ci]}
    CU_LOADED[$ci]=${CR_LOADED[$ci]}
    CU_VERSION[$ci]=${CR_VERSION[$ci]}
    CU_VERSION_BASIS[$ci]=${CR_VERSION_BASIS[$ci]}
    CU_ASOF[$ci]=${CR_AS_OF[$ci]}
    CU_ASOF_BASIS[$ci]=${CR_AS_OF_BASIS[$ci]}
    CU_SHA256[$ci]=${CR_SHA256[$ci]}
    CU_LOCATOR[$ci]=${CR_LOCATOR[$ci]}
    CU_THRESHOLD[$ci]=${CR_THRESHOLD[$ci]}
    CU_INTEGRITY[$ci]=${CR_INTEGRITY[$ci]}
    CU_PROVENANCE[$ci]=${CR_PROVENANCE[$ci]}
    CU_OVERRIDE[$ci]=0
    ci=$((ci+1))
  done
}

# currency_load_fixture_records <file> — replace the CU_ metadata rows from a
# fixture TSV in the shape of tests/fixtures/currency/<state>/source-records.tsv
# (id, loaded, version, version_basis, as_of, as_of_basis, content_sha256,
# record_locator, integrity, provenance).  Applied AFTER currency_copy_registry,
# so identity and threshold come from the embedded registry while the fixture
# drives the evaluated fields.  Same malformed and out-of-order rejection as the
# monolith: exact row count, rows in CR_ID order, loaded true/false, no extra
# columns.  On rejection CURRENCY_INTERNAL_ERROR is set and rc 1 is returned.
function currency_load_fixture_records {
  typeset fixture_file tab ci rid rloaded rversion rvbasis rasof rabasis
  typeset rsha rlocator rintegrity rprovenance extra
  fixture_file=$1
  tab=$(printf '\t')
  ci=0
  while IFS="$tab" read rid rloaded rversion rvbasis rasof rabasis rsha rlocator rintegrity rprovenance extra; do
    case "$rid" in ""|\#*) continue;; esac
    if [ "$ci" -ge "$CURRENCY_SOURCE_COUNT" ] \
        || [ "$rid" != "${CR_ID[$ci]}" ] || [ -n "${extra:-}" ]; then
      CURRENCY_INTERNAL_ERROR="malformed or out-of-order currency fixture record at row $((ci+1))"
      return 1
    fi
    case "$rloaded" in true) CU_LOADED[$ci]=1;; false) CU_LOADED[$ci]=0;;
      *) CURRENCY_INTERNAL_ERROR="invalid loaded value in currency fixture for $rid"; return 1;;
    esac
    CU_VERSION[$ci]=$rversion
    CU_VERSION_BASIS[$ci]=$rvbasis
    CU_ASOF[$ci]=$rasof
    CU_ASOF_BASIS[$ci]=$rabasis
    CU_SHA256[$ci]=$rsha
    CU_LOCATOR[$ci]=$rlocator
    CU_INTEGRITY[$ci]=$rintegrity
    CU_PROVENANCE[$ci]=$rprovenance
    ci=$((ci+1))
  done < "$fixture_file"
  if [ "$ci" -ne "$CURRENCY_SOURCE_COUNT" ]; then
    CURRENCY_INTERNAL_ERROR="currency fixture has $ci rows; expected $CURRENCY_SOURCE_COUNT"
    return 1
  fi
  return 0
}

# currency_evaluate_row <ci> <today_j> — evaluate one CU_ row with the
# monolith's currency_evaluate semantics and print "<STATUS>\t<reason>".
function currency_evaluate_row {
  typeset ci today_j asof age unknowns digest_ok stale
  ci=$1
  today_j=$2
  CU_AGE[$ci]=""
  CU_STATUS[$ci]=UNKNOWN
  CU_REASON[$ci]="source identity or provenance is unknown"
  CU_VERSION[$ci]=$(currency_normalize_metadata "${CU_VERSION[$ci]}")
  CU_VERSION_BASIS[$ci]=$(currency_normalize_metadata "${CU_VERSION_BASIS[$ci]}")
  CU_ASOF[$ci]=$(currency_normalize_metadata "${CU_ASOF[$ci]}")
  CU_ASOF_BASIS[$ci]=$(currency_normalize_metadata "${CU_ASOF_BASIS[$ci]}")
  CU_SHA256[$ci]=$(currency_normalize_metadata "${CU_SHA256[$ci]}")
  CU_LOCATOR[$ci]=$(currency_normalize_metadata "${CU_LOCATOR[$ci]}")
  asof=${CU_ASOF[$ci]}
  if [ "${CU_LOADED[$ci]}" -ne 1 ] \
      && { [ "${CU_INTEGRITY[$ci]}" = invalid ] \
        || [ "${CU_PROVENANCE[$ci]}" = invalid ]; }; then
    CU_STATUS[$ci]=INVALID
    case "${CU_LOCATOR[$ci]}" in
      operator-supplied*)
        CU_REASON[$ci]="operator-supplied source could not be read"
        ;;
      *)
        CU_REASON[$ci]="source was not loaded and its proof state is invalid"
        ;;
    esac
  elif [ "${CU_LOADED[$ci]}" -ne 1 ]; then
    CU_REASON[$ci]="source was not loaded"
  elif [ "${CU_INTEGRITY[$ci]}" != verified ] \
      && [ "${CU_INTEGRITY[$ci]}" != unknown ] \
      && [ "${CU_INTEGRITY[$ci]}" != invalid ]; then
    CU_STATUS[$ci]=INVALID
    CU_REASON[$ci]="integrity proof state is malformed"
  elif [ "${CU_PROVENANCE[$ci]}" != verified ] \
      && [ "${CU_PROVENANCE[$ci]}" != unknown ] \
      && [ "${CU_PROVENANCE[$ci]}" != invalid ]; then
    CU_STATUS[$ci]=INVALID
    CU_REASON[$ci]="provenance proof state is malformed"
  elif [ "${CU_INTEGRITY[$ci]}" = invalid ]; then
    CU_STATUS[$ci]=INVALID
    CU_REASON[$ci]="loaded bytes failed integrity validation"
  elif [ "${CU_PROVENANCE[$ci]}" = invalid ]; then
    CU_STATUS[$ci]=INVALID
    CU_REASON[$ci]="source provenance is invalid or internally conflicting"
  else
    digest_ok=1
    if [ "${CU_SHA256[$ci]}" != unknown ]; then
      if [ "${#CU_SHA256[$ci]}" -ne 71 ] \
          || ! printf '%s\n' "${CU_SHA256[$ci]}" \
            | awk '$0 ~ /^sha256:[0-9a-f]+$/ {ok=1} END{exit ok?0:1}'; then
        digest_ok=0
        CU_STATUS[$ci]=INVALID
        CU_REASON[$ci]="content SHA-256 is malformed"
      fi
    fi
    if [ "$digest_ok" -eq 1 ] && [ "$asof" != unknown ]; then
      if [ "$(valid_ymd "$asof")" -eq 1 ]; then
        age=$(( today_j - $(d2j "$asof") ))
        CU_AGE[$ci]=$age
      else
        CU_ASOF[$ci]=unknown
        asof=unknown
        CU_REASON[$ci]="as-of date is unknown"
      fi
    fi
  fi
  if [ "${CU_LOADED[$ci]}" -eq 1 ] \
      && [ "${CU_STATUS[$ci]}" != INVALID ]; then
    unknowns=""
    [ -n "${CU_VERSION[$ci]}" ] && [ "${CU_VERSION[$ci]}" != unknown ] \
      || unknowns="version"
    if [ -z "${CU_VERSION_BASIS[$ci]}" ] || [ "${CU_VERSION_BASIS[$ci]}" = unknown ]; then
      unknowns="$unknowns${unknowns:+, }version basis"
    fi
    if [ -z "${CU_ASOF[$ci]}" ] || [ "${CU_ASOF[$ci]}" = unknown ]; then
      unknowns="$unknowns${unknowns:+, }as-of date"
    fi
    if [ -z "${CU_ASOF_BASIS[$ci]}" ] || [ "${CU_ASOF_BASIS[$ci]}" = unknown ]; then
      unknowns="$unknowns${unknowns:+, }as-of basis"
    fi
    if [ -z "${CU_SHA256[$ci]}" ] || [ "${CU_SHA256[$ci]}" = unknown ]; then
      unknowns="$unknowns${unknowns:+, }content digest"
    fi
    if [ -z "${CU_LOCATOR[$ci]}" ] || [ "${CU_LOCATOR[$ci]}" = unknown ]; then
      unknowns="$unknowns${unknowns:+, }record locator"
    fi
    if [ "${CU_INTEGRITY[$ci]}" != verified ]; then
      unknowns="$unknowns${unknowns:+, }integrity proof"
    fi
    if [ "${CU_PROVENANCE[$ci]}" != verified ]; then
      unknowns="$unknowns${unknowns:+, }provenance proof"
    fi
    if [ -n "$unknowns" ]; then
      CU_STATUS[$ci]=UNKNOWN
      CU_REASON[$ci]="$unknowns is unknown"
    elif [ -z "${CU_AGE[$ci]}" ]; then
      CU_STATUS[$ci]=UNKNOWN
      CU_REASON[$ci]="as-of date is unknown"
    elif [ "${CU_AGE[$ci]}" -lt 0 ]; then
      CU_STATUS[$ci]=FUTURE
      CU_REASON[$ci]="as-of date is $((0-CU_AGE[$ci])) day(s) after the evaluation date"
    else
      stale=$(awk -v age="${CU_AGE[$ci]}" -v limit="${CU_THRESHOLD[$ci]}" \
        'BEGIN{print (age+0 > limit+0) ? 1 : 0}')
      if [ "$stale" -eq 1 ]; then
        CU_STATUS[$ci]=STALE
        CU_REASON[$ci]="source is ${CU_AGE[$ci]} days old; configured limit ${CU_THRESHOLD[$ci]} days"
      else
        CU_STATUS[$ci]=CURRENT
        CU_REASON[$ci]="identified, integrity-verified, and within the configured limit"
      fi
    fi
  fi
  printf '%s\t%s\n' "${CU_STATUS[$ci]}" "${CU_REASON[$ci]}"
}

# currency_source_status <source-id> [<fixture-file>] — the read-only accessor.
# Prints "<STATUS>\t<reason>" for one source row, with semantics identical to
# the monolith's currency_evaluate.  A fixture TSV (the shape the monolith reads
# from $AIXRAY_FIXTURES/source-records.tsv) overrides the embedded metadata for
# the evaluated row; identity and threshold always come from the embedded
# registry.  Missing/malformed registry, an unreadable or malformed or
# out-of-order fixture, an absent source id, and an unavailable evaluation date
# all refuse with INVALID and a non-empty reason — never CURRENT on absent data,
# never a silent success.  age_days is computed from AIXRAY_TODAY (via the
# prelude's d2j), never a live clock.
function currency_source_status {
  typeset wanted fixture_file count ci today_j
  wanted=${1:-}
  fixture_file=${2:-}
  count=${CURRENCY_SOURCE_COUNT:-0}
  # Fail-closed on every call: an unreadable fixture must refuse with the same
  # deterministic reason regardless of what an earlier call left in the shared
  # internal-error slot.
  CURRENCY_INTERNAL_ERROR=""
  if [ "$count" -lt 1 ]; then
    printf 'INVALID\tcurrency registry is not embedded in this tool\n'
    return 0
  fi
  if [ -z "$fixture_file" ] && [ -n "${AIXRAY_FIXTURES:-}" ] \
      && [ -r "$AIXRAY_FIXTURES/source-records.tsv" ]; then
    fixture_file="$AIXRAY_FIXTURES/source-records.tsv"
  fi
  currency_copy_registry
  if [ -n "$fixture_file" ]; then
    # The monolith only calls currency_load_fixture_records behind a [ -r ]
    # guard; a fixture the accessor cannot open must refuse here,
    # deterministically, instead of letting the loader's failed redirection
    # produce a misleading row count or a stale reason.
    if [ ! -f "$fixture_file" ] || [ ! -r "$fixture_file" ]; then
      printf 'INVALID\tcurrency fixture %s could not be read\n' "$fixture_file"
      return 0
    fi
    if ! currency_load_fixture_records "$fixture_file"; then
      printf 'INVALID\t%s\n' "$CURRENCY_INTERNAL_ERROR"
      return 0
    fi
  fi
  if ! ci=$(currency_source_index "$wanted"); then
    printf 'INVALID\tno registry row for source id %s\n' "$wanted"
    return 0
  fi
  today_j=${TODAY_J:-0}
  if [ "$today_j" -eq 0 ]; then
    if [ -n "${AIXRAY_TODAY:-}" ]; then
      today_j=$(d2j "$AIXRAY_TODAY") 2>/dev/null || today_j=0
    elif [ -n "${TODAY:-}" ]; then
      today_j=$(d2j "$TODAY") 2>/dev/null || today_j=0
    fi
  fi
  if [ "$today_j" -eq 0 ]; then
    printf 'INVALID\tevaluation date is unavailable (set AIXRAY_TODAY)\n'
    return 0
  fi
  currency_evaluate_row "$ci" "$today_j"
  return 0
}

function nr_warn {
  typeset nr_status nr_severity
  nr_status=${7:-WARN}
  nr_severity=${8:-med}
  if [ "${MYUID:-1}" != "0" ]; then
    add "$1" "$2" "$3" "$nr_status" "$nr_severity" "n/a" "Could not read $4 (needs root)." \
      "re-run $AIXRAY_TOOL as root, or inspect '$5' manually."
  else
    add "$1" "$2" "$3" "$nr_status" "$nr_severity" "n/a" "Could not read $4 (unexpected as root)." \
      "inspect '$5' manually."
  fi
}

# Constants and accumulator values read by the already-extracted literal cuts.
STOR_PP_PER_PV_HI=3048
STOR_HUGE_PP_MB=512
STOR_SMALL_VG_PPS=64
STOR_SLACK_PCT=10
STOR_SLACK_MB=512
STOR_FACT_MAX_FS_MB=4294967296
STOR_FACT_MAX_USED_PCT=101
ERR_CRIT_RECUR=3
ERRDEMON_LOG_MIN=1048576
LIFECYCLE_VINTAGE=""

CRIT_ERRIDS="
SC_DISK_ERR1|disk operation error (adapter or drive) — investigate the drive and its path
SC_DISK_ERR2|permanent disk hardware error (drive or SAN path) — PERM means replace or repair
SC_DISK_ERR3|disk command/adapter error — I/O to the drive is failing
SC_DISK_ERR4|disk media / bad-block error — sectors going bad; recurring means replace the disk
DISK_ERR1|disk heavily worn — plan a replacement
DISK_ERR2|disk error (often loss of electrical power) — investigate
DISK_ERR3|disk error (often loss of electrical power) — investigate
DISK_ERR4|bad blocks on disk — more than one in a week means replace the disk
SCSI_ERR1|SCSI adapter hardware error
SCSI_ERR10|SCSI adapter/bus error — cabling, termination, or the adapter itself
SCSI_ARRAY_ERR6|RAID array error — a member disk or the array itself degraded
SCSI_ARRAY_ERR7|RAID array error — a member disk or the array itself degraded
FCS_ERR10|Fibre Channel adapter error — SAN link or path degrading
LVM_SA_QUORCLOSE|volume group lost quorum and was forced offline — an LVM disk dropped
LVM_SA_STALEPP|a mirror copy went stale — the mirror is out of sync
LVM_SA_PVMISS|a physical volume in a volume group went missing
LVM_IO_FAIL|LVM detected an I/O failure to a disk
EPOW_SUS|environmental/power event (EPOW) — power, thermal, or fan; call IBM service
EPOW_RES_CHRP|environmental/power event on the platform — check power and cooling
SCAN_ERROR_CHRP|processor/memory scan error (often correctable ECC over threshold) — a DIMM or CPU is degrading
FIRMWARE_EVENT|platform firmware logged a service event — check the service processor
DMPCHK_SMALL|the configured dump device is too small for a full dump — a panic will truncate it
FWDMP_IFAIL|firmware-assisted dump initialization failed — a panic may not capture a usable dump
"

FACT_PAGING_SPACES=""
FACT_PAGING_MAX=""
FACT_PAGING_ROOT=""
FACT_PAGING_DUP=""
FACT_PAGING_READ=0
FACT_STORAGE_FS_ROWS=""
FACT_STORAGE_WORST_FS_PCT=""
FACT_STORAGE_WORST_FS_MOUNT=""
FACT_STORAGE_WORST_VG_PCT=""
FACT_STORAGE_WORST_VG=""
FACT_STORAGE_MAX_INODE=""
FACT_STORAGE_FS_USED_UNREAD=0
FACT_STORAGE_FS_IUSED_UNREAD=0
FACT_STORAGE_DF_READ=0
FACT_STORAGE_VG_READ=0

function standalone_initialize {
  typeset today_overridden
  # Prime the capture-dir warning in this shell so $(aix)/$(aixv) subshells
  # inherit AIXRAY_CAPTURE_DIR_WARNED and the directory is named once.
  if [ -n "${AIXRAY_CAPTURE_DIR:-}" ]; then
    aix_capture_dir_ok || :
  fi
  today_overridden=0
  if [ "${AIXRAY_TODAY+x}" = x ]; then
    TODAY=$AIXRAY_TODAY
    today_overridden=1
  else
    TODAY=$(date +%Y-%m-%d)
  fi
  if [ "$(valid_ymd "$TODAY")" != 1 ]; then
    if [ "$today_overridden" -eq 1 ]; then
      echo "$AIXRAY_TOOL: AIXRAY_TODAY must be a real calendar date in YYYY-MM-DD format" >&2
    else
      echo "$AIXRAY_TOOL: system date must be a real calendar date in YYYY-MM-DD format" >&2
    fi
    return 2
  fi
  TODAY_J=$(d2j "$TODAY") || return 1
  C7=$(errpt_cutoff 7) || return 1
  C30=$(errpt_cutoff 30) || return 1
  if [ "$today_overridden" -eq 1 ]; then
    NOW=$TODAY
  else
    NOW=$(date '+%Y-%m-%d %H:%M %Z')
  fi
}

function standalone_emit {
  typeset i sep
  printf '{\n'
  printf '  "generated": "%s",\n' "$(printf '%s' "$NOW" | jesc)"
  printf '  "version": "%s",\n' "$AIXRAY_STANDALONE_VERSION"
  printf '  "tool": "%s",\n' "$AIXRAY_TOOL"
  printf '  "findings": ['
  if [ "$NFIND" -gt 0 ]; then
    printf '\n'
  fi
  i=0
  while [ "$i" -lt "$NFIND" ]; do
    sep=','
    [ "$i" -eq $((NFIND - 1)) ] && sep=''
    printf '    { "id": "%s", "category": "%s", "status": "%s", "severity": "%s", "observed": "%s", "meaning": "%s", "fix": "%s" }%s\n' \
      "$(printf '%s' "${F_ID[$i]}" | jesc)" \
      "$(printf '%s' "${F_CAT[$i]}" | jesc)" \
      "${F_ST[$i]}" \
      "$(printf '%s' "${F_SEV[$i]}" | jesc)" \
      "$(printf '%s' "${F_OBS[$i]}" | jesc)" \
      "$(printf '%s' "${F_MEAN[$i]}" | jesc)" \
      "$(printf '%s' "${F_FIX[$i]}" | jesc)" \
      "$sep"
    i=$((i + 1))
  done
  printf '  ]\n}\n'
}

function standalone_main {
  typeset i assessed initialize_rc run_rc uid_rc vios_rc vios_marker vios_rows vios_match vios_nonempty
  if [ "$#" -ne 1 ] || [ "$1" != "--json" ]; then
    echo "usage: $0 --json" >&2
    return 2
  fi
  if [ -z "${AIXRAY_FIXTURES:-}" ] \
      && [ "$(/usr/bin/uname -s 2>/dev/null)" != "AIX" ]; then
    echo "$AIXRAY_TOOL: this standalone check runs on AIX" >&2
    return 2
  fi
  MYUID=$(aix id_u /usr/bin/id -u)
  uid_rc=$?
  if [ "$uid_rc" -ne 0 ] || [ "$MYUID" != 0 ]; then
    echo "$AIXRAY_TOOL: root is required; re-run this standalone check as root. No assessment was run." >&2
    return 2
  fi
  # VIOS is AIX underneath, so uname cannot distinguish it. Match the AIX
  # runner's local marker gate before date initialization or any check probe.
  vios_marker=$(aix ls_ioscli /usr/bin/ls /usr/ios/cli/ioscli)
  vios_rc=$?
  vios_rows=$(printf '%s\n' "$vios_marker" | awk '
    $0=="/usr/ios/cli/ioscli"{n++} NF{all++} END{print n+0 ":" all+0}')
  vios_match=${vios_rows%%:*}
  vios_nonempty=${vios_rows#*:}
  if [ "$vios_rc" -eq 0 ] \
      && [ "$vios_match" -eq 1 ] \
      && [ "$vios_nonempty" -eq 1 ] \
      && [ "${AIXRAY_VIOS_DEV:-0}" != 1 ]; then
    echo "$AIXRAY_TOOL: VIOS assessment is temporarily disabled in this release; no assessment was run." >&2
    return 2
  fi
  standalone_initialize
  initialize_rc=$?
  [ "$initialize_rc" -eq 0 ] || return "$initialize_rc"
  standalone_run
  run_rc=$?
  [ "$run_rc" -eq 0 ] || return 1
  standalone_emit || return 1
  assessed=0
  i=0
  while [ "$i" -lt "$NFIND" ]; do
    [ "${F_ST[$i]}" != "NOT_ASSESSED" ] && assessed=1
    i=$((i + 1))
  done
  [ "$assessed" -eq 1 ] && return 0
  return 3
}
CURRENCY_REGISTRY_SCHEMA='ptxray-source-registry/1'
CURRENCY_SOURCE_COUNT=9
set -A CR_ID 'ibm-aix-lifecycle' 'ibm-security-advisories' 'cisa-kev' 'ibm-apar-csv' 'ibmi-psp-group-levels' 'ibm-flrtvc' 'ibm-flrt-firmware' 'cis-ibm-aix' 'disa-stig-ibm-aix-7'
set -A CR_LABEL 'IBM AIX lifecycle reference data' 'IBM security advisory seed' 'CISA Known Exploited Vulnerabilities catalog' 'IBM FLRT apar.csv' 'IBM i PSP group PTF levels' 'IBM FLRTVC engine' 'IBM FLRT firmware lifecycle response' 'CIS IBM AIX benchmark' 'DISA STIG for IBM AIX 7.x'
set -A CR_CLASS 'advisory' 'advisory' 'cve' 'apar' 'advisory' 'flrt' 'flrt' 'benchmark' 'benchmark'
set -A CR_REQUIRED '1' '1' '1' '1' '1' '1' '1' '1' '1'
set -A CR_LOADED '1' '1' '0' '0' '0' '0' '0' '1' '1'
set -A CR_VERSION 'sha256:60fd717d0f4cd79875654d7be134baf47453b36f4ace74f529394570dd4bd770' 'sha256:ab3c95ca7fdc47ad68978930afcfd70d42eed0ea9580926ab44a0a775b30caed' 'unknown' 'unknown' 'unknown' 'unknown' 'unknown' 'v1.2.0' 'V3R3'
set -A CR_VERSION_BASIS 'content-sha256' 'content-sha256' 'unknown' 'unknown' 'unknown' 'unknown' 'unknown' 'publisher-version' 'publisher-version'
set -A CR_AS_OF '2026-08-15' '2026-08-18' 'unknown' 'unknown' 'unknown' 'unknown' 'unknown' '2026-08-18' '2026-06-15'
set -A CR_AS_OF_BASIS 'curator-verified' 'curator-review' 'unknown' 'unknown' 'unknown' 'unknown' 'unknown' 'curator-verified' 'publisher-benchmark-date'
set -A CR_SHA256 'sha256:60fd717d0f4cd79875654d7be134baf47453b36f4ace74f529394570dd4bd770' 'sha256:ab3c95ca7fdc47ad68978930afcfd70d42eed0ea9580926ab44a0a775b30caed' 'unknown' 'unknown' 'unknown' 'unknown' 'unknown' 'sha256:3645a841eb8f05078a8c0a043f62ed200bd7483a578c615ea652c7f15f68bd3b' 'sha256:e4109ceb3a15beddbf1e84e29e593cd18cc260e9be1789429554b9d66e2cfeb9'
set -A CR_LOCATOR 'https://www.ibm.com/support/pages/aix-standard-edition720 (no announced AIX 7.2 EOS shown; supported state is a curator inference from that absence); https://www.ibm.com/support/pages/aix-support-lifecycle-information (AIX 7.2 TL5 EoFS: To be determined)' 'embedded SEC_APARS table' 'operator-supplied local CISA KEV JSON' 'operator-supplied local apar.csv or provenanced FLRTVC report' 'https://public.dhe.ibm.com/services/us/igsc/PSP/xmldoc.xml' 'operator-supplied pinned flrtvc.ksh or provenanced report' 'https://esupport.ibm.com/customercare/flrt/report?format=json&plat=power&ucode=ptxray' 'embedded numeric-only CIS L1 crosswalk' 'embedded R_FILEPERM/R_SECATTR/R_NETTUNE/R_SVCOFF tables'
set -A CR_THRESHOLD '30' '30' '30' '30' '30' '30' '30' '180' '180'
set -A CR_INTEGRITY 'verified' 'verified' 'unknown' 'unknown' 'unknown' 'unknown' 'unknown' 'verified' 'verified'
set -A CR_PROVENANCE 'verified' 'verified' 'unknown' 'unknown' 'unknown' 'unknown' 'unknown' 'verified' 'verified'

AIXRAY_TOOL=ck-alt-disk-recoverability

_AIXRAY_SESSION_KEYS=""
# Assess the alt-disk recovery path and emit its graded finding plus the two
# Step-0 recovery facts owned by this one read-only job. Include-safe: the
# assembled scanner calls check_alt_disk_recoverability after the shared aix
# wrapper and finding helper are available, then renders the cached facts.

function alt_disk_json_escape {
  awk '
    {
      value=$0
      gsub(/\\/, "\\\\", value)
      gsub(/"/, "\\\"", value)
      gsub(/\t/, "\\t", value)
      gsub(/\r/, "\\r", value)
      gsub(/[\001-\010\013\014\016-\037]/, "", value)
      if (seen++) printf "\\n"
      printf "%s", value
    }
  '
}

function alt_disk_jstring {
  printf '"%s"' "$(printf '%s' "$1" | alt_disk_json_escape)"
}

function alt_disk_jnullable_string {
  if [ -n "$1" ]; then alt_disk_jstring "$1"; else printf 'null'; fi
}

function alt_disk_jbool {
  case "$1" in
    true|false) printf '%s' "$1";;
    *) printf 'null';;
  esac
}

function alt_disk_jnumber {
  case "$1" in
    ''|*[!0-9]*) printf 'null';;
    *) printf '%s' "$1";;
  esac
}

function alt_disk_jlist {
  typeset ALT_LIST_ITEM ALT_LIST_SEP
  ALT_LIST_SEP=""
  printf '['
  for ALT_LIST_ITEM in $1; do
    printf '%s"%s"' "$ALT_LIST_SEP" "$ALT_LIST_ITEM"
    ALT_LIST_SEP=','
  done
  printf ']'
}

function alt_disk_jnullable_list {
  if [ -n "$1" ]; then alt_disk_jlist "$1"; else printf 'null'; fi
}

function alt_disk_has_nonblank {
  printf '%s\n' "$1" | awk 'NF { found=1 } END { exit(found ? 0 : 1) }'
}

function alt_disk_add_reason {
  if [ -z "$1" ]; then
    printf '%s' "$2"
  elif [ -z "$2" ]; then
    printf '%s' "$1"
  else
    printf '%s; %s' "$1" "$2"
  fi
}

# The check phase owns the measurement.  Cache its rendered fact members so the
# later Contract 1.1 facts renderer cannot re-probe a changing live system and
# disagree with the finding derived from this same assessment.
ALT_DISK_RECOVERY_JSON=""
ALT_DISK_RECOVERY_ASSESSED=0
ALT_DISK_FINDING_ADDED=0
ALT_DISK_FINDING_STATUS=""
ALT_DISK_FINDING_SEVERITY=""
ALT_DISK_FINDING_OBSERVED=""
ALT_DISK_FINDING_MEANING=""
ALT_DISK_FINDING_FIX=""

function alt_disk_append {
  ALT_DISK_RECOVERY_JSON="${ALT_DISK_RECOVERY_JSON}$1"
}

function alt_disk_finding_value {
  if [ -n "$1" ]; then printf '%s' "$1"; else printf 'null'; fi
}

function alt_disk_finding_disks {
  if [ -z "$1" ]; then
    printf '[]'
  else
    printf '%s\n' "$1" | awk '
      NF {
        for (field=1; field<=NF; field++)
          printf "%s%s", (seen++ ? "," : "["), $field
      }
      END { print "]" }
    '
  fi
}

function alt_disk_finding_device_states {
  if [ -n "$1" ]; then printf '[%s]' "$1"; else printf 'null'; fi
}

# Derive the graded finding only from values already used to render
# alt_disk_usability.  The observed field is the sibling finding model's
# evidence carrier, so it names both measured values and the read-only source
# commands that produced them.
function alt_disk_set_finding {
  typeset ALT_FIND_FACT_STATUS ALT_FIND_USABLE ALT_FIND_VG ALT_FIND_DISKS
  typeset ALT_FIND_BOOT ALT_FIND_DEVICE_STATES ALT_FIND_BOOTABLE ALT_FIND_BOOTLIST
  typeset ALT_FIND_OS ALT_FIND_UPDATED ALT_FIND_AGE ALT_FIND_FRESHNESS ALT_FIND_REASON
  typeset ALT_FIND_DISK_JSON ALT_FIND_DISKS_KNOWN ALT_FIND_FIRST
  typeset ALT_FIND_SOURCES ALT_FIND_SOURCE_OVERRIDE
  typeset ALT_FIND_REASON_SUFFIX ALT_FIND_MISSING ALT_FIND_MISSING_SUFFIX

  ALT_FIND_FACT_STATUS=$1
  ALT_FIND_USABLE=$2
  ALT_FIND_VG=$3
  ALT_FIND_DISKS=$4
  ALT_FIND_BOOT=$5
  ALT_FIND_DEVICE_STATES=$6
  ALT_FIND_BOOTABLE=$7
  ALT_FIND_BOOTLIST=$8
  ALT_FIND_OS=$9
  ALT_FIND_UPDATED=${10}
  ALT_FIND_AGE=${11}
  ALT_FIND_FRESHNESS=${12}
  ALT_FIND_REASON=${13}
  ALT_FIND_DISKS_KNOWN=${14:-true}
  ALT_FIND_SOURCE_OVERRIDE=${15:-}
  ALT_FIND_MISSING=${16:-}

  if [ "$ALT_FIND_FACT_STATUS" = NOT_ASSESSED ] && [ -n "$ALT_FIND_MISSING" ]; then
    ALT_FIND_MISSING=$(printf '%s\n' "$ALT_FIND_MISSING" | awk '
      {
        for (field=1; field<=NF; field++)
          if ($field != "usable")
            printf "%s%s", (seen++ ? " " : ""), $field
      }
    ')
  else
    ALT_FIND_MISSING=""
  fi

  if [ "$ALT_FIND_DISKS_KNOWN" = true ]; then
    ALT_FIND_DISK_JSON=$(alt_disk_finding_disks "$ALT_FIND_DISKS")
  else
    ALT_FIND_DISK_JSON=null
  fi
  ALT_FIND_FIRST=$(printf '%s\n' "$ALT_FIND_DISKS" | awk 'NF { print $1; exit }')
  if [ -n "$ALT_FIND_SOURCE_OVERRIDE" ]; then
    ALT_FIND_SOURCES=$ALT_FIND_SOURCE_OVERRIDE
  else
    ALT_FIND_SOURCES="lspv"
    if [ -n "$ALT_FIND_DISKS" ]; then
      ALT_FIND_SOURCES="$ALT_FIND_SOURCES; lsdev -Cc disk -F \"name:status\""
      ALT_FIND_SOURCES="$ALT_FIND_SOURCES; alt_rootvg_op -q -d $ALT_FIND_FIRST"
      if [ -n "$ALT_FIND_BOOT" ]; then
        ALT_FIND_SOURCES="$ALT_FIND_SOURCES; bootinfo -B $ALT_FIND_BOOT"
        ALT_FIND_SOURCES="$ALT_FIND_SOURCES; bootlist -m normal -o"
      fi
      ALT_FIND_SOURCES="$ALT_FIND_SOURCES; oslevel -s"
      ALT_FIND_SOURCES="$ALT_FIND_SOURCES; cat /var/adm/ras/alt_disk_inst.log"
    fi
  fi
  if [ -n "$ALT_FIND_REASON" ]; then
    ALT_FIND_REASON_SUFFIX="; reason=$ALT_FIND_REASON"
  else
    ALT_FIND_REASON_SUFFIX=""
  fi
  if [ -n "$ALT_FIND_MISSING" ]; then
    ALT_FIND_MISSING_SUFFIX="; missing_evidence=$(alt_disk_finding_disks "$ALT_FIND_MISSING")"
  else
    ALT_FIND_MISSING_SUFFIX=""
  fi

  ALT_DISK_FINDING_OBSERVED="status=$ALT_FIND_FACT_STATUS; usable=$(alt_disk_finding_value "$ALT_FIND_USABLE"); volume_group=$(alt_disk_finding_value "$ALT_FIND_VG"); disks=$ALT_FIND_DISK_JSON"
  if [ -n "$ALT_FIND_DISKS" ]; then
    ALT_DISK_FINDING_OBSERVED="$ALT_DISK_FINDING_OBSERVED; boot_disk=$(alt_disk_finding_value "$ALT_FIND_BOOT"); device_states=$(alt_disk_finding_device_states "$ALT_FIND_DEVICE_STATES"); platform_bootable=$(alt_disk_finding_value "$ALT_FIND_BOOTABLE"); in_normal_bootlist=$(alt_disk_finding_value "$ALT_FIND_BOOTLIST"); running_oslevel=$(alt_disk_finding_value "$ALT_FIND_OS"); freshness=$(alt_disk_finding_value "$ALT_FIND_FRESHNESS"); last_updated=$(alt_disk_finding_value "$ALT_FIND_UPDATED"); age_days=$(alt_disk_finding_value "$ALT_FIND_AGE")"
  fi
  ALT_DISK_FINDING_OBSERVED="$ALT_DISK_FINDING_OBSERVED$ALT_FIND_MISSING_SUFFIX$ALT_FIND_REASON_SUFFIX; source_commands=[$ALT_FIND_SOURCES]"

  case "$ALT_FIND_FACT_STATUS" in
    USABLE)
      if [ "$ALT_FIND_BOOTLIST" = true ] && [ -n "$ALT_FIND_OS" ]; then
        ALT_DISK_FINDING_STATUS=PASS
        ALT_DISK_FINDING_SEVERITY=low
        ALT_DISK_FINDING_MEANING="A current, platform-bootable alternate rootvg clone is measured and present in the normal bootlist."
        ALT_DISK_FINDING_FIX="n/a"
      elif [ "$ALT_FIND_BOOTLIST" = true ]; then
        ALT_DISK_FINDING_STATUS=NOT_ASSESSED
        ALT_DISK_FINDING_SEVERITY=high
        ALT_DISK_FINDING_MEANING="The clone appears current, bootable, and bootlisted, but the running OS level was unreadable; no complete currency grade is claimed."
        ALT_DISK_FINDING_FIX="rerun 'oslevel -s', resolve the read failure, and confirm the clone's documented update baseline before relying on rollback."
      elif [ "$ALT_FIND_BOOTLIST" = false ]; then
        ALT_DISK_FINDING_STATUS=WARN
        ALT_DISK_FINDING_SEVERITY=high
        ALT_DISK_FINDING_MEANING="A current, platform-bootable alternate rootvg clone exists, but it is not in the normal bootlist; rollback requires an explicit, tested bootlist change."
        ALT_DISK_FINDING_FIX="validate and document the rollback procedure; select $ALT_FIND_BOOT with 'bootlist -m normal' only during an approved rollback."
      else
        ALT_DISK_FINDING_STATUS=NOT_ASSESSED
        ALT_DISK_FINDING_SEVERITY=high
        ALT_DISK_FINDING_MEANING="The clone appears current and bootable, but normal-bootlist readiness was unreadable; no complete fast-rollback grade is claimed."
        ALT_DISK_FINDING_FIX="rerun 'bootlist -m normal -o', resolve the read failure, and validate the rollback boot selection."
      fi
      ;;
    NOT_CURRENT|NOT_USABLE)
      ALT_DISK_FINDING_STATUS=WARN
      ALT_DISK_FINDING_SEVERITY=high
      ALT_DISK_FINDING_MEANING="The measured alternate rootvg is not a reliable current fast-rollback path: $ALT_FIND_REASON."
      ALT_DISK_FINDING_FIX="create or refresh an alt_disk_copy clone of rootvg on a platform-bootable alternate disk, then verify its completion and rollback boot selection."
      ;;
    NOT_APPLICABLE)
      ALT_DISK_FINDING_STATUS=WARN
      ALT_DISK_FINDING_SEVERITY=high
      ALT_DISK_FINDING_MEANING="No alternate rootvg clone is configured, so this system has no measured fast-rollback path."
      ALT_DISK_FINDING_FIX="create and regularly refresh an alt_disk_copy clone of rootvg on a platform-bootable alternate disk; verify it with alt_rootvg_op and bootlist."
      ;;
    *)
      ALT_DISK_FINDING_STATUS=NOT_ASSESSED
      ALT_DISK_FINDING_SEVERITY=high
      ALT_DISK_FINDING_MEANING="The alt-disk recovery path could not be assessed from the captured read-only probes; no usability claim is made."
      ALT_DISK_FINDING_FIX="resolve the reported capture failure and rerun the lspv, lsdev, alt_rootvg_op, bootinfo, bootlist, oslevel, and alt_disk_inst.log probes."
      ;;
  esac
}

# Validate every lspv row before any hdisk token can become a capture key or
# command argument. The optional state is retained as one tab-delimited field.
function alt_disk_parse_lspv {
  awk '
    function hdisk(value) { return value ~ /^hdisk[0-9][0-9]*$/ }
    function pvid(value) {
      return value == "none" ||
        (value ~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/ &&
         substr(value,16,1) != "" && substr(value,17,1) == "")
    }
    function vg(value) {
      return value ~ /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/
    }
    function state_ok(value) {
      return value == "" || value == "active" || value == "missing" ||
        value == "removed" || value == "varied off" || value == "locked"
    }
    /^[ \t]*$/ { next }
    {
      rows++
      state=""
      for (field=4; field<=NF; field++)
        state=state (state=="" ? "" : " ") $field
      if (NF < 3 || !hdisk($1) || !pvid($2) || !vg($3) ||
          !state_ok(state) || seen[$1]++) {
        bad=1
        next
      }
      disk[rows]=$1
      disk_pvid[rows]=$2
      disk_vg[rows]=$3
      disk_state[rows]=state
    }
    END {
      if (bad || rows == 0) exit 1
      for (row=1; row<=rows; row++)
        printf "%s\t%s\t%s\t%s\n", disk[row], disk_pvid[row],
          disk_vg[row], disk_state[row]
    }
  '
}

function alt_disk_parse_lsdev_states {
  awk -F ':' '
    function hdisk(value) { return value ~ /^hdisk[0-9][0-9]*$/ }
    /^[ \t]*$/ { next }
    {
      rows++
      if (NF != 2 || !hdisk($1) ||
          ($2 != "Available" && $2 != "Defined" && $2 != "Stopped") ||
          seen[$1]++) {
        bad=1
        next
      }
      disk[rows]=$1
      state[rows]=$2
    }
    END {
      if (bad || rows == 0) exit 1
      for (row=1; row<=rows; row++)
        printf "%s\t%s\n", disk[row], state[row]
    }
  '
}

function alt_disk_positive_integer {
  awk '
    /^[ \t]*$/ { next }
    {
      rows++
      if (NF != 1 || $1 !~ /^[1-9][0-9]*$/) bad=1
      value=$1
    }
    END {
      if (bad || rows != 1) exit 1
      print value
    }
  '
}

function alt_disk_rootvg_pp_size {
  awk '
    {
      for (field=1; field+2<=NF; field++) {
        if ($field == "PP" && $(field+1) == "SIZE:" &&
            $(field+2) ~ /^[1-9][0-9]*$/) {
          matches++
          value=$(field+2)
        }
      }
    }
    END {
      if (matches != 1) exit 1
      print value
    }
  '
}

function alt_disk_rootvg_lp_count {
  awk '
    /^[ \t]*$/ { next }
    nonblank == 0 {
      nonblank++
      if ($0 !~ /^[ \t]*rootvg:[ \t]*$/) bad=1
      next
    }
    nonblank == 1 {
      nonblank++
      if ($1 != "LV" || $2 != "NAME" || $3 != "TYPE" ||
          $4 != "LPs" || $5 != "PPs" || $6 != "PVs") bad=1
      next
    }
    {
      nonblank++
      if (NF < 7 || $1 !~ /^[A-Za-z][A-Za-z0-9_.-]*$/ ||
          $2 !~ /^[A-Za-z][A-Za-z0-9_.-]*$/ ||
          $3 !~ /^[1-9][0-9]*$/ || $4 !~ /^[1-9][0-9]*$/ ||
          $5 !~ /^[1-9][0-9]*$/ || seen[$1]++) {
        bad=1
        next
      }
      rows++
      total += $3
    }
    END {
      if (bad || rows == 0 || total < 1) exit 1
      printf "%.0f\n", total
    }
  '
}

function alt_disk_oslevel_value {
  awk '
    /^[ \t]*$/ { next }
    {
      rows++
      if (NF != 1 ||
          $1 !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9]$/)
        bad=1
      value=$1
    }
    END {
      if (bad || rows != 1) exit 1
      print value
    }
  '
}

function alt_disk_boot_disk_value {
  typeset ALT_BOOT_MEMBERS
  ALT_BOOT_MEMBERS=$(printf '%s\n' "$1" | awk \
    'NF { printf "%s%s", (seen++ ? " " : ""), $1 }')
  awk -v members="$ALT_BOOT_MEMBERS" '
    BEGIN {
      count=split(members, item, " ")
      for (slot=1; slot<=count; slot++) allowed[item[slot]]=1
    }
    /^[ \t]*$/ { next }
    {
      rows++
      if (NF != 1 || $1 !~ /^hdisk[0-9][0-9]*$/ || !allowed[$1]) bad=1
      value=$1
    }
    END {
      if (bad || rows != 1) exit 1
      print value
    }
  '
}

function alt_disk_bootinfo_value {
  awk '
    /^[ \t]*$/ { next }
    {
      rows++
      if (NF != 1 || ($1 != "0" && $1 != "1")) bad=1
      value=$1
    }
    END {
      if (bad || rows != 1) exit 1
      print value
    }
  '
}

function alt_disk_bootlist_membership {
  typeset ALT_BOOTLIST_WANTED
  ALT_BOOTLIST_WANTED=$1
  awk -v wanted="$ALT_BOOTLIST_WANTED" '
    /^[ \t]*$/ { next }
    {
      rows++
      if ($1 !~ /^hdisk[0-9][0-9]*$/) {
        bad=1
        next
      }
      for (field=2; field<=NF; field++)
        if ($field !~ /^[A-Za-z][A-Za-z0-9_]*=[^ \t][^ \t]*$/) bad=1
      if ($1 == wanted) found=1
    }
    END {
      if (bad || rows == 0) exit 1
      print found ? "true" : "false"
    }
  '
}

function alt_disk_valid_ymd {
  typeset ALT_YMD ALT_YEAR ALT_REST ALT_MONTH ALT_DAY ALT_DIM
  ALT_YMD=$1
  case "$ALT_YMD" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
    *) return 1;;
  esac
  ALT_YEAR=${ALT_YMD%%-*}
  ALT_REST=${ALT_YMD#*-}
  ALT_MONTH=${ALT_REST%%-*}
  ALT_DAY=${ALT_REST#*-}
  ALT_MONTH=${ALT_MONTH#0}
  ALT_DAY=${ALT_DAY#0}
  [ -n "$ALT_MONTH" ] || ALT_MONTH=0
  [ -n "$ALT_DAY" ] || ALT_DAY=0
  case "$ALT_MONTH" in
    1|3|5|7|8|10|12) ALT_DIM=31;;
    4|6|9|11) ALT_DIM=30;;
    2)
      if [ $((ALT_YEAR % 400)) -eq 0 ] ||
         { [ $((ALT_YEAR % 4)) -eq 0 ] && [ $((ALT_YEAR % 100)) -ne 0 ]; }; then
        ALT_DIM=29
      else
        ALT_DIM=28
      fi
      ;;
    *) return 1;;
  esac
  [ "$ALT_DAY" -ge 1 ] && [ "$ALT_DAY" -le "$ALT_DIM" ]
}

function alt_disk_d2j {
  typeset ALT_DATE ALT_YEAR ALT_REST ALT_MONTH ALT_DAY ALT_A
  ALT_DATE=$1
  ALT_YEAR=${ALT_DATE%%-*}
  ALT_REST=${ALT_DATE#*-}
  ALT_MONTH=${ALT_REST%%-*}
  ALT_DAY=${ALT_REST#*-}
  ALT_MONTH=${ALT_MONTH#0}
  ALT_DAY=${ALT_DAY#0}
  [ -n "$ALT_MONTH" ] || ALT_MONTH=0
  [ -n "$ALT_DAY" ] || ALT_DAY=0
  ALT_A=$(( (14 - ALT_MONTH) / 12 ))
  ALT_YEAR=$(( ALT_YEAR + 4800 - ALT_A ))
  ALT_MONTH=$(( ALT_MONTH + 12*ALT_A - 3 ))
  echo $(( ALT_DAY + (153*ALT_MONTH + 2)/5 + 365*ALT_YEAR +
    ALT_YEAR/4 - ALT_YEAR/100 + ALT_YEAR/400 - 32045 ))
}

# Print YYYY-MM-DD<TAB>hdiskN for the last completed Phase-3 record whose -d
# target set is exactly the topology-specific disk set supplied by the caller.
function alt_disk_log_completion {
  typeset ALT_LOG_DISKS
  ALT_LOG_DISKS=$(printf '%s\n' "$1" | awk \
    'NF { printf "%s%s", (seen++ ? " " : ""), $1 }')
  awk -v wanted="$ALT_LOG_DISKS" '
    function normalized_targets(line, count, field, start, value, k) {
      gsub(/"/, " ", line)
      gsub(/\047/, " ", line)
      count=split(line, token, /[ \t]+/)
      start=0
      for (k in target) delete target[k]
      target_count=0
      for (field=1; field<=count; field++) {
        if (token[field] == "-d") {
          start=field+1
          break
        }
      }
      if (!start) return 0
      for (field=start; field<=count; field++) {
        value=token[field]
        if (value == "") continue
        if (substr(value,1,1) == "-") break
        if (value !~ /^hdisk[0-9][0-9]*$/ || target[value]++) return 0
        target_count++
      }
      if (target_count != wanted_count) return 0
      for (value in wanted_set) if (!target[value]) return 0
      return 1
    }
    BEGIN {
      month["Jan"]="01"; month["Feb"]="02"; month["Mar"]="03"
      month["Apr"]="04"; month["May"]="05"; month["Jun"]="06"
      month["Jul"]="07"; month["Aug"]="08"; month["Sep"]="09"
      month["Oct"]="10"; month["Nov"]="11"; month["Dec"]="12"
      wanted_count=split(wanted, wanted_item, " ")
      for (slot=1; slot<=wanted_count; slot++)
        wanted_set[wanted_item[slot]]=1
    }
    $1 ~ /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$/ && month[$2] != "" &&
      $3 ~ /^[0-9][0-9]*$/ && $4 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/ &&
      $6 ~ /^[0-9][0-9][0-9][0-9]$/ {
        day=$3+0
        if (day >= 1 && day <= 31) {
          current_date=sprintf("%04d-%s-%02d", $6+0, month[$2], day)
          record_match=0
        }
        next
      }
    /^cmd:/ {
      record_match=0
      if (current_date != "" && $0 ~ /(^|\/)alt_disk_copy([ \t]|$)/ &&
          normalized_targets($0)) {
        record_match=1
        completed_date=""
        completed_boot=""
      }
      next
    }
    record_match && /^Bootlist is set to the boot disk:[ \t]+hdisk[0-9]/ {
      boot=""
      for (field=1; field<=NF; field++)
        if ($field ~ /^hdisk[0-9][0-9]*$/) { boot=$field; break }
      if (boot != "" && wanted_set[boot]) {
        completed_date=current_date
        completed_boot=boot
      }
    }
    END {
      if (completed_date == "" || completed_boot == "") exit 1
      printf "%s\t%s\n", completed_date, completed_boot
    }
  '
}

function alt_disk_emit_spare_sources {
  alt_disk_append '"source_commands":{'
  alt_disk_append '"inventory":"lspv",'
  alt_disk_append '"rootvg":"lsvg rootvg",'
  alt_disk_append '"rootvg_lvs":"lsvg -l rootvg",'
  alt_disk_append '"device_state":"lsdev -Cc disk -F \"name:status\"",'
  alt_disk_append '"disk_size":"getconf DISK_SIZE /dev/<hdisk>",'
  alt_disk_append '"platform_bootable":"bootinfo -B <hdisk>"}'
}

function alt_disk_emit_alt_sources {
  alt_disk_append '"source_commands":{'
  alt_disk_append '"inventory":"lspv",'
  alt_disk_append '"device_state":"lsdev -Cc disk -F \"name:status\"",'
  alt_disk_append '"boot_disk":"alt_rootvg_op -q -d <hdisk>",'
  alt_disk_append '"platform_bootable":"bootinfo -B <hdisk>",'
  alt_disk_append '"normal_bootlist":"bootlist -m normal -o",'
  alt_disk_append '"running_oslevel":"oslevel -s",'
  alt_disk_append '"completion_log":"cat /var/adm/ras/alt_disk_inst.log"}'
}

function alt_disk_emit_inventory_unreadable {
  typeset ALT_FATAL_REASON ALT_ESCAPED_REASON
  ALT_FATAL_REASON=$1
  ALT_ESCAPED_REASON=$(printf '%s' "$ALT_FATAL_REASON" | alt_disk_json_escape)

  alt_disk_append '"usable_spare":{'
  alt_disk_append "$(printf '"status":"NOT_ASSESSED","eligible":null,"candidate_disk":null,"reason":"%s",' \
    "$ALT_ESCAPED_REASON")"
  alt_disk_append '"rootvg_required_mb":null,"checks":null,'
  alt_disk_emit_spare_sources
  alt_disk_append ',"basis":"not_assessed",'
  alt_disk_append '"unreadable":["eligible","candidate_disk","rootvg_required_mb","checks"],'
  alt_disk_append '"not_applicable":[]},'

  alt_disk_append '"alt_disk_usability":{'
  alt_disk_append "$(printf '"status":"NOT_ASSESSED","usable":null,"volume_group":null,"disks":null,"boot_disk":null,"device_states":null,"platform_bootable":null,"in_normal_bootlist":null,"running_oslevel":null,"last_updated":null,"age_days":null,"freshness":null,"freshness_basis":null,"completion_target_disks":null,"reason":"%s",' \
    "$ALT_ESCAPED_REASON")"
  alt_disk_emit_alt_sources
  alt_disk_append ',"basis":"not_assessed",'
  alt_disk_append '"unreadable":["usable","volume_group","disks","boot_disk","device_states","platform_bootable","in_normal_bootlist","running_oslevel","last_updated","age_days","freshness","freshness_basis","completion_target_disks"],'
  alt_disk_append '"not_applicable":[]}'
  alt_disk_set_finding NOT_ASSESSED "" "" "" "" "" "" "" "" "" "" "" \
    "$ALT_FATAL_REASON" false
}

function alt_disk_emit_no_spare {
  alt_disk_append '"usable_spare":{'
  alt_disk_append '"status":"INELIGIBLE","eligible":false,"candidate_disk":null,'
  alt_disk_append '"reason":"lspv reported no disks with volume group None",'
  alt_disk_append '"rootvg_required_mb":null,"checks":[],'
  alt_disk_emit_spare_sources
  alt_disk_append ',"basis":"observed","unreadable":[],'
  alt_disk_append '"not_applicable":["candidate_disk","rootvg_required_mb"]}'
}

function alt_disk_emit_no_existing {
  alt_disk_append '"alt_disk_usability":{'
  alt_disk_append '"status":"NOT_APPLICABLE","usable":null,"volume_group":null,'
  alt_disk_append '"disks":[],"boot_disk":null,"device_states":[],'
  alt_disk_append '"platform_bootable":null,"in_normal_bootlist":null,'
  alt_disk_append '"running_oslevel":null,"last_updated":null,"age_days":null,'
  alt_disk_append '"freshness":null,"freshness_basis":null,"completion_target_disks":null,'
  alt_disk_append '"reason":"lspv reported no altinst_rootvg or old_rootvg",'
  alt_disk_emit_alt_sources
  alt_disk_append ',"basis":"observed","unreadable":[],'
  alt_disk_append '"not_applicable":["usable","volume_group","boot_disk","platform_bootable","in_normal_bootlist","running_oslevel","last_updated","age_days","freshness","freshness_basis","completion_target_disks"]}'
  alt_disk_set_finding NOT_APPLICABLE "" "" "" "" "" "" "" "" "" "" "" \
    "lspv reported no altinst_rootvg or old_rootvg"
}

function alt_disk_assess_recoverability {
  typeset ALT_LSPV ALT_LSPV_RC ALT_ROWS ALT_PARSE_RC
  typeset ALT_FREE_ROWS ALT_FREE_DISKS ALT_EXISTING_ROWS ALT_EXISTING_DISKS ALT_ROOTVG_DISKS
  typeset ALT_VGS ALT_VG_COUNT ALT_VG
  typeset ALT_LSDEV ALT_LSDEV_RC ALT_LSDEV_ROWS ALT_LSDEV_PARSE_RC ALT_LSDEV_REASON
  typeset ALT_ROOTVG ALT_ROOTVG_RC ALT_ROOTLV ALT_ROOTLV_RC
  typeset ALT_PP_SIZE ALT_PP_RC ALT_LP_COUNT ALT_LP_RC ALT_REQUIRED ALT_ROOT_REASON
  typeset ALT_DISK ALT_PVID ALT_ROW_VG ALT_PV_STATE ALT_DEVICE_STATE ALT_LOOKUP_RC
  typeset ALT_LSPV_STATE ALT_PV_STATE_SAFE
  typeset ALT_STATE_KNOWN ALT_AVAILABLE ALT_SIZE_RAW ALT_SIZE_RC ALT_SIZE ALT_SIZE_PARSE_RC
  typeset ALT_SIZE_KNOWN ALT_SIZE_SUFFICIENT ALT_ROW_ELIGIBLE ALT_ROW_STATUS ALT_ROW_REASON
  typeset ALT_SPARE_BOOTABLE_RAW ALT_SPARE_BOOTABLE_RC ALT_SPARE_BOOTABLE_TOKEN
  typeset ALT_SPARE_BOOTABLE_PARSE_RC ALT_SPARE_BOOTABLE ALT_SPARE_BOOTABLE_REASON
  typeset ALT_ROW_UNREAD ALT_CHECKS ALT_CHECK ALT_ANY_ELIGIBLE ALT_ANY_UNKNOWN
  typeset ALT_SELECTED ALT_SPARE_STATUS ALT_SPARE_ELIGIBLE ALT_SPARE_REASON
  typeset ALT_SPARE_BASIS ALT_SPARE_UNREAD ALT_SPARE_NA ALT_ANY_ROW_GAP
  typeset ALT_DEVICE_ITEMS ALT_DEVICE_ITEM ALT_DEVICE_UNKNOWN ALT_DEVICE_BAD
  typeset ALT_ALT_STATE_BAD ALT_ALT_STATE_REASON ALT_FIRST_DISK
  typeset ALT_BOOT_RAW ALT_BOOT_RC ALT_BOOT_DISK ALT_BOOT_PARSE_RC ALT_BOOT_REASON
  typeset ALT_BOOTABLE_RAW ALT_BOOTABLE_RC ALT_BOOTABLE_TOKEN ALT_BOOTABLE_PARSE_RC
  typeset ALT_PLATFORM_BOOTABLE ALT_BOOTABLE_REASON
  typeset ALT_BOOTLIST ALT_BOOTLIST_RC ALT_IN_BOOTLIST ALT_BOOTLIST_PARSE_RC ALT_BOOTLIST_REASON
  typeset ALT_OS_RAW ALT_OS_RC ALT_RUNNING_OS ALT_OS_PARSE_RC ALT_OS_REASON
  typeset ALT_LOG ALT_LOG_RC ALT_COMPLETION ALT_COMPLETION_RC ALT_LAST_UPDATED ALT_LOG_BOOT
  typeset ALT_TODAY ALT_AGE ALT_FRESHNESS ALT_LOG_REASON ALT_LAST_J ALT_TODAY_J
  typeset ALT_LOG_TARGET_DISKS ALT_FRESHNESS_BASIS
  typeset ALT_USABLE ALT_STATUS ALT_REASON ALT_BASIS ALT_UNREAD ALT_NA
  typeset ALT_ESCAPED ALT_ITEM_STATE ALT_ITEM_AVAILABLE ALT_ITEM_STATUS ALT_ITEM_REASON
  typeset ALT_ITEM_PV_STATE ALT_ITEM_PV_SAFE

  ALT_DISK_RECOVERY_JSON=""
  ALT_DISK_RECOVERY_ASSESSED=1
  FACT_RECOVERY_ALT=""
  ALT_LSPV=$(aix lspv lspv)
  ALT_LSPV_RC=$?
  if [ "$ALT_LSPV_RC" -ne 0 ]; then
    alt_disk_emit_inventory_unreadable "lspv capture failed (rc=$ALT_LSPV_RC)"
    return 0
  fi
  if ! alt_disk_has_nonblank "$ALT_LSPV"; then
    alt_disk_emit_inventory_unreadable "lspv capture empty (rc=0)"
    return 0
  fi
  ALT_ROWS=$(printf '%s\n' "$ALT_LSPV" | alt_disk_parse_lspv)
  ALT_PARSE_RC=$?
  if [ "$ALT_PARSE_RC" -ne 0 ] || [ -z "$ALT_ROWS" ]; then
    alt_disk_emit_inventory_unreadable "lspv capture unparseable (rc=0)"
    return 0
  fi

  ALT_FREE_ROWS=$(printf '%s\n' "$ALT_ROWS" | awk -F '\t' '$3 == "None"')
  ALT_FREE_DISKS=$(printf '%s\n' "$ALT_FREE_ROWS" | awk -F '\t' 'NF { print $1 }')
  ALT_EXISTING_ROWS=$(printf '%s\n' "$ALT_ROWS" |
    awk -F '\t' '$3 == "altinst_rootvg" || $3 == "old_rootvg"')
  ALT_EXISTING_DISKS=$(printf '%s\n' "$ALT_EXISTING_ROWS" |
    awk -F '\t' 'NF { print $1 }')
  if [ -n "$ALT_EXISTING_DISKS" ]; then
    FACT_RECOVERY_ALT=true
  else
    FACT_RECOVERY_ALT=false
  fi
  ALT_ROOTVG_DISKS=$(printf '%s\n' "$ALT_ROWS" | awk -F '\t' '$3 == "rootvg" { print $1 }')

  ALT_LSDEV_ROWS=""
  ALT_LSDEV_REASON=""
  if [ -n "$ALT_FREE_DISKS" ] || [ -n "$ALT_EXISTING_DISKS" ]; then
    ALT_LSDEV=$(aix lsdev_disk_state lsdev -Cc disk -F "name:status")
    ALT_LSDEV_RC=$?
    if [ "$ALT_LSDEV_RC" -ne 0 ]; then
      ALT_LSDEV_REASON="lsdev -Cc disk -F \"name:status\" capture failed (rc=$ALT_LSDEV_RC)"
    elif ! alt_disk_has_nonblank "$ALT_LSDEV"; then
      ALT_LSDEV_REASON="lsdev -Cc disk -F \"name:status\" capture empty (rc=0)"
    else
      ALT_LSDEV_ROWS=$(printf '%s\n' "$ALT_LSDEV" | alt_disk_parse_lsdev_states)
      ALT_LSDEV_PARSE_RC=$?
      if [ "$ALT_LSDEV_PARSE_RC" -ne 0 ] || [ -z "$ALT_LSDEV_ROWS" ]; then
        ALT_LSDEV_ROWS=""
        ALT_LSDEV_REASON="lsdev -Cc disk -F \"name:status\" capture unparseable (rc=0)"
      fi
    fi
  fi

  # ---- New-clone spare eligibility -------------------------------------------------
  if [ -z "$ALT_FREE_DISKS" ]; then
    alt_disk_emit_no_spare
  else
    ALT_ROOT_REASON=""
    ALT_REQUIRED=""
    ALT_ROOTVG=$(aix lsvg_rootvg lsvg rootvg)
    ALT_ROOTVG_RC=$?
    ALT_ROOTLV=$(aix lsvg_l_rootvg lsvg -l rootvg)
    ALT_ROOTLV_RC=$?
    if [ "$ALT_ROOTVG_RC" -ne 0 ]; then
      ALT_ROOT_REASON="lsvg rootvg capture failed (rc=$ALT_ROOTVG_RC)"
    elif ! alt_disk_has_nonblank "$ALT_ROOTVG"; then
      ALT_ROOT_REASON="lsvg rootvg capture empty (rc=0)"
    else
      ALT_PP_SIZE=$(printf '%s\n' "$ALT_ROOTVG" | alt_disk_rootvg_pp_size)
      ALT_PP_RC=$?
      if [ "$ALT_PP_RC" -ne 0 ] || [ -z "$ALT_PP_SIZE" ]; then
        ALT_ROOT_REASON="lsvg rootvg capture unparseable (rc=0; PP SIZE unavailable)"
      fi
    fi
    if [ "$ALT_ROOTLV_RC" -ne 0 ]; then
      ALT_ROOT_REASON=$(alt_disk_add_reason "$ALT_ROOT_REASON" \
        "lsvg -l rootvg capture failed (rc=$ALT_ROOTLV_RC)")
    elif ! alt_disk_has_nonblank "$ALT_ROOTLV"; then
      ALT_ROOT_REASON=$(alt_disk_add_reason "$ALT_ROOT_REASON" \
        "lsvg -l rootvg capture empty (rc=0)")
    else
      ALT_LP_COUNT=$(printf '%s\n' "$ALT_ROOTLV" | alt_disk_rootvg_lp_count)
      ALT_LP_RC=$?
      if [ "$ALT_LP_RC" -ne 0 ] || [ -z "$ALT_LP_COUNT" ]; then
        ALT_ROOT_REASON=$(alt_disk_add_reason "$ALT_ROOT_REASON" \
          "lsvg -l rootvg capture unparseable (rc=0; LP footprint unavailable)")
      fi
    fi
    if [ -z "$ALT_ROOT_REASON" ]; then
      ALT_REQUIRED=$(awk -v pp="$ALT_PP_SIZE" -v lps="$ALT_LP_COUNT" \
        'BEGIN { value=pp*lps; if (value < 1 || value != int(value)) exit 1; printf "%.0f", value }')
      [ -n "$ALT_REQUIRED" ] || ALT_ROOT_REASON="rootvg LP footprint arithmetic failed"
    fi

    ALT_CHECKS=""
    ALT_ANY_ELIGIBLE=0
    ALT_ANY_UNKNOWN=0
    ALT_ANY_ROW_GAP=0
    ALT_SELECTED=""
    while IFS='	' read -r ALT_DISK ALT_PVID ALT_ROW_VG ALT_PV_STATE
    do
      [ -n "$ALT_DISK" ] || continue
      ALT_ROW_REASON=""
      ALT_ROW_UNREAD=""
      case "$ALT_PV_STATE" in
        '') ALT_LSPV_STATE=not_reported; ALT_PV_STATE_SAFE=true;;
        'varied off') ALT_LSPV_STATE=varied_off; ALT_PV_STATE_SAFE=false;;
        *) ALT_LSPV_STATE=$ALT_PV_STATE; ALT_PV_STATE_SAFE=false;;
      esac
      if [ "$ALT_PV_STATE_SAFE" = false ]; then
        ALT_ROW_REASON="$ALT_DISK lspv state is $ALT_PV_STATE, not an unreported free-PV state"
      fi
      ALT_DEVICE_STATE=""
      ALT_STATE_KNOWN=0
      ALT_AVAILABLE=""
      if [ -n "$ALT_LSDEV_REASON" ]; then
        ALT_ROW_REASON=$(alt_disk_add_reason "$ALT_ROW_REASON" "$ALT_LSDEV_REASON")
        ALT_ROW_UNREAD="device_state available"
      else
        ALT_DEVICE_STATE=$(printf '%s\n' "$ALT_LSDEV_ROWS" | awk -F '\t' \
          -v wanted="$ALT_DISK" '$1 == wanted { print $2; found=1; exit } END { if (!found) exit 1 }')
        ALT_LOOKUP_RC=$?
        if [ "$ALT_LOOKUP_RC" -eq 0 ] && [ -n "$ALT_DEVICE_STATE" ]; then
          ALT_STATE_KNOWN=1
          if [ "$ALT_DEVICE_STATE" = Available ]; then
            ALT_AVAILABLE=true
          else
            ALT_AVAILABLE=false
            ALT_ROW_REASON=$(alt_disk_add_reason "$ALT_ROW_REASON" \
              "$ALT_DISK device state is $ALT_DEVICE_STATE, not Available")
          fi
        else
          ALT_ROW_REASON=$(alt_disk_add_reason "$ALT_ROW_REASON" \
            "lsdev disk-state capture reported no row for $ALT_DISK (rc=0)")
          ALT_ROW_UNREAD="device_state available"
        fi
      fi

      ALT_SIZE=""
      ALT_SIZE_KNOWN=0
      ALT_SIZE_RAW=$(aix "getconf_disk_size_$ALT_DISK" getconf DISK_SIZE "/dev/$ALT_DISK")
      ALT_SIZE_RC=$?
      if [ "$ALT_SIZE_RC" -ne 0 ]; then
        ALT_ROW_REASON=$(alt_disk_add_reason "$ALT_ROW_REASON" \
          "getconf DISK_SIZE /dev/$ALT_DISK capture failed (rc=$ALT_SIZE_RC)")
        ALT_ROW_UNREAD="$ALT_ROW_UNREAD size_mb"
      elif ! alt_disk_has_nonblank "$ALT_SIZE_RAW"; then
        ALT_ROW_REASON=$(alt_disk_add_reason "$ALT_ROW_REASON" \
          "getconf DISK_SIZE /dev/$ALT_DISK capture empty (rc=0)")
        ALT_ROW_UNREAD="$ALT_ROW_UNREAD size_mb"
      else
        ALT_SIZE=$(printf '%s\n' "$ALT_SIZE_RAW" | alt_disk_positive_integer)
        ALT_SIZE_PARSE_RC=$?
        if [ "$ALT_SIZE_PARSE_RC" -eq 0 ] && [ -n "$ALT_SIZE" ]; then
          ALT_SIZE_KNOWN=1
        else
          ALT_SIZE=""
          ALT_ROW_REASON=$(alt_disk_add_reason "$ALT_ROW_REASON" \
            "getconf DISK_SIZE /dev/$ALT_DISK capture unparseable (rc=0)")
          ALT_ROW_UNREAD="$ALT_ROW_UNREAD size_mb"
        fi
      fi

      ALT_SIZE_SUFFICIENT=""
      if [ -n "$ALT_REQUIRED" ] && [ "$ALT_SIZE_KNOWN" -eq 1 ]; then
        if [ "$ALT_SIZE" -ge "$ALT_REQUIRED" ]; then
          ALT_SIZE_SUFFICIENT=true
        else
          ALT_SIZE_SUFFICIENT=false
          ALT_ROW_REASON=$(alt_disk_add_reason "$ALT_ROW_REASON" \
            "$ALT_DISK size ${ALT_SIZE}MB is below rootvg LP footprint ${ALT_REQUIRED}MB")
        fi
      else
        [ -n "$ALT_ROOT_REASON" ] &&
          ALT_ROW_REASON=$(alt_disk_add_reason "$ALT_ROW_REASON" "$ALT_ROOT_REASON")
        [ -n "$ALT_REQUIRED" ] || ALT_ROW_UNREAD="$ALT_ROW_UNREAD rootvg_required_mb"
        ALT_ROW_UNREAD="$ALT_ROW_UNREAD size_sufficient"
      fi

      ALT_SPARE_BOOTABLE=""
      ALT_SPARE_BOOTABLE_REASON=""
      ALT_SPARE_BOOTABLE_RAW=$(aix "bootinfo_bootable_$ALT_DISK" bootinfo -B "$ALT_DISK")
      ALT_SPARE_BOOTABLE_RC=$?
      if [ "$ALT_SPARE_BOOTABLE_RC" -ne 0 ]; then
        ALT_SPARE_BOOTABLE_REASON="bootinfo -B $ALT_DISK capture failed (rc=$ALT_SPARE_BOOTABLE_RC)"
      elif ! alt_disk_has_nonblank "$ALT_SPARE_BOOTABLE_RAW"; then
        ALT_SPARE_BOOTABLE_REASON="bootinfo -B $ALT_DISK capture empty (rc=0)"
      else
        ALT_SPARE_BOOTABLE_TOKEN=$(printf '%s\n' "$ALT_SPARE_BOOTABLE_RAW" |
          alt_disk_bootinfo_value)
        ALT_SPARE_BOOTABLE_PARSE_RC=$?
        if [ "$ALT_SPARE_BOOTABLE_PARSE_RC" -eq 0 ]; then
          if [ "$ALT_SPARE_BOOTABLE_TOKEN" = 1 ]; then ALT_SPARE_BOOTABLE=true
          else ALT_SPARE_BOOTABLE=false; fi
        else
          ALT_SPARE_BOOTABLE_REASON="bootinfo -B $ALT_DISK capture unparseable (rc=0)"
        fi
      fi
      if [ "$ALT_SPARE_BOOTABLE" = false ]; then
        ALT_ROW_REASON=$(alt_disk_add_reason "$ALT_ROW_REASON" \
          "$ALT_DISK is not platform-bootable according to bootinfo -B")
      elif [ -z "$ALT_SPARE_BOOTABLE" ]; then
        ALT_ROW_REASON=$(alt_disk_add_reason "$ALT_ROW_REASON" \
          "$ALT_SPARE_BOOTABLE_REASON")
        ALT_ROW_UNREAD="$ALT_ROW_UNREAD platform_bootable"
      fi

      ALT_ROW_ELIGIBLE=""
      if [ "$ALT_PV_STATE_SAFE" = false ]; then
        ALT_ROW_ELIGIBLE=false
      elif [ "$ALT_STATE_KNOWN" -eq 1 ] && [ "$ALT_AVAILABLE" = false ]; then
        ALT_ROW_ELIGIBLE=false
      elif [ -n "$ALT_SIZE_SUFFICIENT" ] && [ "$ALT_SIZE_SUFFICIENT" = false ]; then
        ALT_ROW_ELIGIBLE=false
      elif [ "$ALT_SPARE_BOOTABLE" = false ]; then
        ALT_ROW_ELIGIBLE=false
      elif [ "$ALT_PV_STATE_SAFE" = true ] &&
           [ "$ALT_STATE_KNOWN" -eq 1 ] && [ "$ALT_AVAILABLE" = true ] &&
           [ "$ALT_SIZE_SUFFICIENT" = true ] && [ "$ALT_SPARE_BOOTABLE" = true ]; then
        ALT_ROW_ELIGIBLE=true
      else
        ALT_ROW_UNREAD="$ALT_ROW_UNREAD eligible"
      fi

      ALT_ROW_UNREAD=$(printf '%s\n' "$ALT_ROW_UNREAD" | awk '
        { for (field=1; field<=NF; field++) if (!seen[$field]++)
            output=output (output=="" ? "" : " ") $field }
        END { print output }')
      if [ "$ALT_ROW_ELIGIBLE" = true ]; then
        ALT_ROW_STATUS=ELIGIBLE
        ALT_ANY_ELIGIBLE=1
        [ -n "$ALT_SELECTED" ] || ALT_SELECTED=$ALT_DISK
      elif [ "$ALT_ROW_ELIGIBLE" = false ]; then
        ALT_ROW_STATUS=INELIGIBLE
      else
        ALT_ROW_STATUS=NOT_ASSESSED
        ALT_ANY_UNKNOWN=1
      fi
      [ -z "$ALT_ROW_UNREAD" ] || ALT_ANY_ROW_GAP=1

      ALT_CHECK=$(printf '%s' '{')
      ALT_CHECK="$ALT_CHECK\"hdisk\":$(alt_disk_jstring "$ALT_DISK"),"
      ALT_CHECK="$ALT_CHECK\"pvid\":$(alt_disk_jstring "$ALT_PVID"),"
      ALT_CHECK="$ALT_CHECK\"vg\":$(alt_disk_jstring "$ALT_ROW_VG"),"
      ALT_CHECK="$ALT_CHECK\"not_in_volume_group\":true,"
      ALT_CHECK="$ALT_CHECK\"lspv_state\":$(alt_disk_jstring "$ALT_LSPV_STATE"),"
      ALT_CHECK="$ALT_CHECK\"pv_state_safe\":$(alt_disk_jbool "$ALT_PV_STATE_SAFE"),"
      ALT_CHECK="$ALT_CHECK\"device_state\":$(alt_disk_jnullable_string "$ALT_DEVICE_STATE"),"
      ALT_CHECK="$ALT_CHECK\"available\":$(alt_disk_jbool "$ALT_AVAILABLE"),"
      ALT_CHECK="$ALT_CHECK\"size_mb\":$(alt_disk_jnumber "$ALT_SIZE"),"
      ALT_CHECK="$ALT_CHECK\"rootvg_required_mb\":$(alt_disk_jnumber "$ALT_REQUIRED"),"
      ALT_CHECK="$ALT_CHECK\"size_sufficient\":$(alt_disk_jbool "$ALT_SIZE_SUFFICIENT"),"
      ALT_CHECK="$ALT_CHECK\"platform_bootable\":$(alt_disk_jbool "$ALT_SPARE_BOOTABLE"),"
      ALT_CHECK="$ALT_CHECK\"eligible\":$(alt_disk_jbool "$ALT_ROW_ELIGIBLE"),"
      ALT_CHECK="$ALT_CHECK\"status\":$(alt_disk_jstring "$ALT_ROW_STATUS"),"
      ALT_CHECK="$ALT_CHECK\"reason\":$(alt_disk_jnullable_string "$ALT_ROW_REASON"),"
      ALT_CHECK="$ALT_CHECK\"unreadable\":$(alt_disk_jlist "$ALT_ROW_UNREAD")}"
      if [ -n "$ALT_CHECKS" ]; then ALT_CHECKS="$ALT_CHECKS,$ALT_CHECK"; else ALT_CHECKS=$ALT_CHECK; fi
    done <<EOF
$ALT_FREE_ROWS
EOF

    ALT_SPARE_UNREAD=""
    ALT_SPARE_NA=""
    if [ "$ALT_ANY_ELIGIBLE" -eq 1 ]; then
      ALT_SPARE_STATUS=ELIGIBLE
      ALT_SPARE_ELIGIBLE=true
      ALT_SPARE_REASON=""
    elif [ "$ALT_ANY_UNKNOWN" -eq 1 ]; then
      ALT_SPARE_STATUS=NOT_ASSESSED
      ALT_SPARE_ELIGIBLE=""
      ALT_SPARE_REASON="one or more free disks could not be fully assessed for clone eligibility"
      ALT_SPARE_UNREAD="eligible candidate_disk"
    else
      ALT_SPARE_STATUS=INELIGIBLE
      ALT_SPARE_ELIGIBLE=false
      ALT_SPARE_REASON="every disk with volume group None failed at least one captured eligibility check"
      ALT_SPARE_NA="candidate_disk"
    fi
    if [ -z "$ALT_REQUIRED" ]; then
      ALT_SPARE_UNREAD="$ALT_SPARE_UNREAD rootvg_required_mb"
    fi
    if [ "$ALT_ANY_ROW_GAP" -eq 1 ] || [ -n "$ALT_SPARE_UNREAD" ]; then
      ALT_SPARE_BASIS=partial
    else
      ALT_SPARE_BASIS=observed
    fi

    alt_disk_append '"usable_spare":{'
    alt_disk_append "$(printf '"status":"%s","eligible":%s,"candidate_disk":%s,"reason":%s,' \
      "$ALT_SPARE_STATUS" "$(alt_disk_jbool "$ALT_SPARE_ELIGIBLE")" \
      "$(alt_disk_jnullable_string "$ALT_SELECTED")" \
      "$(alt_disk_jnullable_string "$ALT_SPARE_REASON")")"
    alt_disk_append "$(printf '"rootvg_required_mb":%s,"checks":[%s],' \
      "$(alt_disk_jnumber "$ALT_REQUIRED")" "$ALT_CHECKS")"
    alt_disk_emit_spare_sources
    alt_disk_append "$(printf ',"basis":"%s","unreadable":%s,"not_applicable":%s}' \
      "$ALT_SPARE_BASIS" "$(alt_disk_jlist "$ALT_SPARE_UNREAD")" \
      "$(alt_disk_jlist "$ALT_SPARE_NA")")"
  fi

  alt_disk_append ','

  # ---- Existing alternate-rootvg rollback usability --------------------------------
  if [ -z "$ALT_EXISTING_DISKS" ]; then
    alt_disk_emit_no_existing
    return 0
  fi

  ALT_VGS=$(printf '%s\n' "$ALT_EXISTING_ROWS" | awk -F '\t' '!seen[$3]++ { print $3 }')
  ALT_VG_COUNT=$(printf '%s\n' "$ALT_VGS" | awk 'NF { count++ } END { print count+0 }')
  if [ "$ALT_VG_COUNT" -ne 1 ]; then
    ALT_ESCAPED="lspv reported more than one alternate-rootvg name; usability is ambiguous"
    alt_disk_append '"alt_disk_usability":{'
    alt_disk_append "$(printf '"status":"NOT_ASSESSED","usable":null,"volume_group":null,"disks":%s,' \
      "$(alt_disk_jlist "$ALT_EXISTING_DISKS")")"
    alt_disk_append '"boot_disk":null,"device_states":null,"platform_bootable":null,"in_normal_bootlist":null,"running_oslevel":null,"last_updated":null,"age_days":null,"freshness":null,"freshness_basis":null,"completion_target_disks":null,'
    alt_disk_append "$(printf '"reason":%s,' "$(alt_disk_jstring "$ALT_ESCAPED")")"
    alt_disk_emit_alt_sources
    alt_disk_append ',"basis":"partial",'
    alt_disk_append '"unreadable":["usable","volume_group","boot_disk","device_states","platform_bootable","in_normal_bootlist","running_oslevel","last_updated","age_days","freshness","freshness_basis","completion_target_disks"],"not_applicable":[]}'
    alt_disk_set_finding NOT_ASSESSED "" "" "$ALT_EXISTING_DISKS" "" "" "" "" \
      "" "" "" "" "$ALT_ESCAPED" true \
      'lspv; lsdev -Cc disk -F "name:status"'
    return 0
  fi
  ALT_VG=$(printf '%s\n' "$ALT_VGS" | awk 'NF { print; exit }')
  ALT_EXISTING_DISKS=$(printf '%s\n' "$ALT_EXISTING_ROWS" | awk -F '\t' -v vg="$ALT_VG" '$3 == vg { print $1 }')
  ALT_FIRST_DISK=$(printf '%s\n' "$ALT_EXISTING_DISKS" | awk 'NF { print; exit }')
  if [ "$ALT_VG" = old_rootvg ]; then
    ALT_LOG_TARGET_DISKS=$ALT_ROOTVG_DISKS
    ALT_FRESHNESS_BASIS=current_rootvg_phase3_completion
  else
    ALT_LOG_TARGET_DISKS=$ALT_EXISTING_DISKS
    ALT_FRESHNESS_BASIS=alternate_vg_phase3_completion
  fi

  ALT_DEVICE_ITEMS=""
  ALT_DEVICE_UNKNOWN=0
  ALT_DEVICE_BAD=0
  ALT_ALT_STATE_BAD=0
  ALT_ALT_STATE_REASON=""
  while IFS='	' read -r ALT_DISK ALT_PVID ALT_ROW_VG ALT_PV_STATE
  do
    [ "$ALT_ROW_VG" = "$ALT_VG" ] || continue
    ALT_ITEM_REASON=""
    case "$ALT_PV_STATE" in
      '') ALT_ITEM_PV_STATE=not_reported; ALT_ITEM_PV_SAFE=true;;
      'varied off') ALT_ITEM_PV_STATE=varied_off; ALT_ITEM_PV_SAFE=true;;
      *)
        ALT_ITEM_PV_STATE=$ALT_PV_STATE
        ALT_ITEM_PV_SAFE=false
        ALT_ALT_STATE_BAD=1
        ALT_ALT_STATE_REASON=$(alt_disk_add_reason "$ALT_ALT_STATE_REASON" \
          "$ALT_DISK lspv state is ${ALT_PV_STATE:-unknown}, not a sleeping alternate-rootvg state")
        ALT_ITEM_REASON="$ALT_DISK lspv state is ${ALT_PV_STATE:-unknown}, not a sleeping alternate-rootvg state"
        ;;
    esac

    ALT_ITEM_STATE=""
    ALT_ITEM_AVAILABLE=""
    ALT_ITEM_STATUS=NOT_ASSESSED
    if [ -n "$ALT_LSDEV_REASON" ]; then
      ALT_ITEM_REASON=$(alt_disk_add_reason "$ALT_ITEM_REASON" "$ALT_LSDEV_REASON")
      ALT_DEVICE_UNKNOWN=1
    else
      ALT_ITEM_STATE=$(printf '%s\n' "$ALT_LSDEV_ROWS" | awk -F '\t' \
        -v wanted="$ALT_DISK" '$1 == wanted { print $2; found=1; exit } END { if (!found) exit 1 }')
      ALT_LOOKUP_RC=$?
      if [ "$ALT_LOOKUP_RC" -eq 0 ] && [ -n "$ALT_ITEM_STATE" ]; then
        ALT_ITEM_STATUS=OBSERVED
        if [ "$ALT_ITEM_STATE" = Available ]; then
          ALT_ITEM_AVAILABLE=true
        else
          ALT_ITEM_AVAILABLE=false
          ALT_DEVICE_BAD=1
          ALT_ITEM_REASON=$(alt_disk_add_reason "$ALT_ITEM_REASON" \
            "$ALT_DISK device state is $ALT_ITEM_STATE, not Available")
        fi
      else
        ALT_ITEM_REASON=$(alt_disk_add_reason "$ALT_ITEM_REASON" \
          "lsdev disk-state capture reported no row for $ALT_DISK (rc=0)")
        ALT_DEVICE_UNKNOWN=1
      fi
    fi
    ALT_DEVICE_ITEM="{\"hdisk\":$(alt_disk_jstring "$ALT_DISK"),"
    ALT_DEVICE_ITEM="$ALT_DEVICE_ITEM\"lspv_state\":$(alt_disk_jstring "$ALT_ITEM_PV_STATE"),"
    ALT_DEVICE_ITEM="$ALT_DEVICE_ITEM\"pv_state_safe\":$(alt_disk_jbool "$ALT_ITEM_PV_SAFE"),"
    ALT_DEVICE_ITEM="$ALT_DEVICE_ITEM\"state\":$(alt_disk_jnullable_string "$ALT_ITEM_STATE"),"
    ALT_DEVICE_ITEM="$ALT_DEVICE_ITEM\"available\":$(alt_disk_jbool "$ALT_ITEM_AVAILABLE"),"
    ALT_DEVICE_ITEM="$ALT_DEVICE_ITEM\"status\":$(alt_disk_jstring "$ALT_ITEM_STATUS"),"
    ALT_DEVICE_ITEM="$ALT_DEVICE_ITEM\"reason\":$(alt_disk_jnullable_string "$ALT_ITEM_REASON")}"
    if [ -n "$ALT_DEVICE_ITEMS" ]; then
      ALT_DEVICE_ITEMS="$ALT_DEVICE_ITEMS,$ALT_DEVICE_ITEM"
    else
      ALT_DEVICE_ITEMS=$ALT_DEVICE_ITEM
    fi
  done <<EOF
$ALT_EXISTING_ROWS
EOF

  ALT_BOOT_DISK=""
  ALT_BOOT_REASON=""
  ALT_BOOT_RAW=$(aix "alt_rootvg_boot_$ALT_FIRST_DISK" alt_rootvg_op -q -d "$ALT_FIRST_DISK")
  ALT_BOOT_RC=$?
  if [ "$ALT_BOOT_RC" -ne 0 ]; then
    ALT_BOOT_REASON="alt_rootvg_op -q -d $ALT_FIRST_DISK capture failed (rc=$ALT_BOOT_RC)"
  elif ! alt_disk_has_nonblank "$ALT_BOOT_RAW"; then
    ALT_BOOT_REASON="alt_rootvg_op -q -d $ALT_FIRST_DISK capture empty (rc=0)"
  else
    ALT_BOOT_DISK=$(printf '%s\n' "$ALT_BOOT_RAW" |
      alt_disk_boot_disk_value "$ALT_EXISTING_DISKS")
    ALT_BOOT_PARSE_RC=$?
    if [ "$ALT_BOOT_PARSE_RC" -ne 0 ] || [ -z "$ALT_BOOT_DISK" ]; then
      ALT_BOOT_DISK=""
      ALT_BOOT_REASON="alt_rootvg_op -q -d $ALT_FIRST_DISK capture unparseable or outside the alternate VG (rc=0)"
    fi
  fi

  ALT_PLATFORM_BOOTABLE=""
  ALT_BOOTABLE_REASON=""
  ALT_IN_BOOTLIST=""
  ALT_BOOTLIST_REASON=""
  if [ -n "$ALT_BOOT_DISK" ]; then
    ALT_BOOTABLE_RAW=$(aix "bootinfo_bootable_$ALT_BOOT_DISK" bootinfo -B "$ALT_BOOT_DISK")
    ALT_BOOTABLE_RC=$?
    if [ "$ALT_BOOTABLE_RC" -ne 0 ]; then
      ALT_BOOTABLE_REASON="bootinfo -B $ALT_BOOT_DISK capture failed (rc=$ALT_BOOTABLE_RC)"
    elif ! alt_disk_has_nonblank "$ALT_BOOTABLE_RAW"; then
      ALT_BOOTABLE_REASON="bootinfo -B $ALT_BOOT_DISK capture empty (rc=0)"
    else
      ALT_BOOTABLE_TOKEN=$(printf '%s\n' "$ALT_BOOTABLE_RAW" | alt_disk_bootinfo_value)
      ALT_BOOTABLE_PARSE_RC=$?
      if [ "$ALT_BOOTABLE_PARSE_RC" -eq 0 ]; then
        if [ "$ALT_BOOTABLE_TOKEN" = 1 ]; then ALT_PLATFORM_BOOTABLE=true
        else ALT_PLATFORM_BOOTABLE=false; fi
      else
        ALT_BOOTABLE_REASON="bootinfo -B $ALT_BOOT_DISK capture unparseable (rc=0)"
      fi
    fi

    ALT_BOOTLIST=$(aix bootlist bootlist -m normal -o)
    ALT_BOOTLIST_RC=$?
    if [ "$ALT_BOOTLIST_RC" -ne 0 ]; then
      ALT_BOOTLIST_REASON="bootlist -m normal -o capture failed (rc=$ALT_BOOTLIST_RC)"
    elif ! alt_disk_has_nonblank "$ALT_BOOTLIST"; then
      ALT_BOOTLIST_REASON="bootlist -m normal -o capture empty (rc=0)"
    else
      ALT_IN_BOOTLIST=$(printf '%s\n' "$ALT_BOOTLIST" |
        alt_disk_bootlist_membership "$ALT_BOOT_DISK")
      ALT_BOOTLIST_PARSE_RC=$?
      if [ "$ALT_BOOTLIST_PARSE_RC" -ne 0 ] || [ -z "$ALT_IN_BOOTLIST" ]; then
        ALT_IN_BOOTLIST=""
        ALT_BOOTLIST_REASON="bootlist -m normal -o capture unparseable (rc=0)"
      fi
    fi
  fi

  ALT_RUNNING_OS=""
  ALT_OS_REASON=""
  ALT_OS_RAW=$(aix oslevel_s oslevel -s)
  ALT_OS_RC=$?
  if [ "$ALT_OS_RC" -ne 0 ]; then
    ALT_OS_REASON="oslevel -s capture failed (rc=$ALT_OS_RC)"
  elif ! alt_disk_has_nonblank "$ALT_OS_RAW"; then
    ALT_OS_REASON="oslevel -s capture empty (rc=0)"
  else
    ALT_RUNNING_OS=$(printf '%s\n' "$ALT_OS_RAW" | alt_disk_oslevel_value)
    ALT_OS_PARSE_RC=$?
    if [ "$ALT_OS_PARSE_RC" -ne 0 ] || [ -z "$ALT_RUNNING_OS" ]; then
      ALT_RUNNING_OS=""
      ALT_OS_REASON="oslevel -s capture unparseable (rc=0)"
    fi
  fi

  ALT_LAST_UPDATED=""
  ALT_AGE=""
  ALT_FRESHNESS=""
  ALT_LOG_REASON=""
  ALT_LOG=$(aix alt_disk_inst_log cat /var/adm/ras/alt_disk_inst.log)
  ALT_LOG_RC=$?
  if [ -z "$ALT_LOG_TARGET_DISKS" ]; then
    ALT_LOG_REASON="lspv reported no current rootvg disks for old_rootvg freshness correlation"
  elif [ "$ALT_LOG_RC" -ne 0 ]; then
    ALT_LOG_REASON="alt_disk_inst.log capture failed (rc=$ALT_LOG_RC)"
  elif ! alt_disk_has_nonblank "$ALT_LOG"; then
    ALT_LOG_REASON="alt_disk_inst.log capture empty (rc=0)"
  else
    ALT_COMPLETION=$(printf '%s\n' "$ALT_LOG" |
      alt_disk_log_completion "$ALT_LOG_TARGET_DISKS")
    ALT_COMPLETION_RC=$?
    if [ "$ALT_COMPLETION_RC" -eq 0 ] && [ -n "$ALT_COMPLETION" ]; then
      ALT_LAST_UPDATED=$(printf '%s\n' "$ALT_COMPLETION" | awk -F '\t' 'NF == 2 { print $1 }')
      ALT_LOG_BOOT=$(printf '%s\n' "$ALT_COMPLETION" | awk -F '\t' 'NF == 2 { print $2 }')
      ALT_TODAY=${AIXRAY_TODAY:-$(date +%Y-%m-%d)}
      if [ "$ALT_VG" = altinst_rootvg ] && [ -n "$ALT_BOOT_DISK" ] &&
         [ "$ALT_LOG_BOOT" != "$ALT_BOOT_DISK" ]; then
        ALT_LAST_UPDATED=""
        ALT_LOG_REASON="alt_disk_inst.log Phase-3 boot disk $ALT_LOG_BOOT does not match queried boot disk $ALT_BOOT_DISK"
      elif alt_disk_valid_ymd "$ALT_LAST_UPDATED" && alt_disk_valid_ymd "$ALT_TODAY"; then
        ALT_LAST_J=$(alt_disk_d2j "$ALT_LAST_UPDATED")
        ALT_TODAY_J=$(alt_disk_d2j "$ALT_TODAY")
        ALT_AGE=$((ALT_TODAY_J - ALT_LAST_J))
        if [ "$ALT_AGE" -lt 0 ]; then
          ALT_AGE=""
          ALT_FRESHNESS=""
          ALT_LOG_REASON="alt_disk_inst.log completion date $ALT_LAST_UPDATED is in the future"
        elif [ "$ALT_AGE" -le 30 ]; then
          ALT_FRESHNESS=FRESH
        elif [ "$ALT_AGE" -le 90 ]; then
          ALT_FRESHNESS=AGING
        else
          ALT_FRESHNESS=STALE
        fi
      else
        ALT_LAST_UPDATED=""
        ALT_LOG_REASON="alt_disk_inst.log completion date or assessment date is unparseable"
      fi
    else
      ALT_LOG_REASON="alt_disk_inst.log has no completed Phase-3 record for the exact $ALT_FRESHNESS_BASIS disk set"
    fi
  fi

  ALT_STATUS=""
  ALT_USABLE=""
  ALT_REASON=""
  if [ "$ALT_ALT_STATE_BAD" -eq 1 ]; then
    ALT_STATUS=NOT_USABLE
    ALT_USABLE=false
    ALT_REASON=$ALT_ALT_STATE_REASON
  elif [ "$ALT_DEVICE_BAD" -eq 1 ]; then
    ALT_STATUS=NOT_USABLE
    ALT_USABLE=false
    ALT_REASON="one or more alternate-rootvg disks are not Available"
  elif [ "$ALT_PLATFORM_BOOTABLE" = false ]; then
    ALT_STATUS=NOT_USABLE
    ALT_USABLE=false
    ALT_REASON="$ALT_BOOT_DISK is not platform-bootable according to bootinfo -B"
  elif [ "$ALT_FRESHNESS" = STALE ]; then
    ALT_STATUS=NOT_CURRENT
    ALT_USABLE=false
    ALT_REASON="matched alternate-rootvg Phase-3 completion is older than 90 days"
  elif [ "$ALT_DEVICE_UNKNOWN" -eq 1 ] || [ -z "$ALT_BOOT_DISK" ] ||
       [ -z "$ALT_PLATFORM_BOOTABLE" ] || [ -z "$ALT_FRESHNESS" ]; then
    ALT_STATUS=NOT_ASSESSED
    ALT_USABLE=""
  else
    ALT_STATUS=USABLE
    ALT_USABLE=true
    if [ "$ALT_IN_BOOTLIST" = false ]; then
      ALT_REASON="alternate boot disk is not in the current normal bootlist; rollback requires a bootlist change"
    fi
  fi

  [ "$ALT_DEVICE_UNKNOWN" -eq 1 ] &&
    ALT_REASON=$(alt_disk_add_reason "$ALT_REASON" \
      "one or more alternate-rootvg device states are unreadable")
  [ -n "$ALT_BOOT_REASON" ] &&
    ALT_REASON=$(alt_disk_add_reason "$ALT_REASON" "$ALT_BOOT_REASON")
  [ -n "$ALT_BOOTABLE_REASON" ] &&
    ALT_REASON=$(alt_disk_add_reason "$ALT_REASON" "$ALT_BOOTABLE_REASON")
  [ -n "$ALT_BOOTLIST_REASON" ] &&
    ALT_REASON=$(alt_disk_add_reason "$ALT_REASON" "$ALT_BOOTLIST_REASON")
  [ -n "$ALT_OS_REASON" ] &&
    ALT_REASON=$(alt_disk_add_reason "$ALT_REASON" "$ALT_OS_REASON")
  [ -n "$ALT_LOG_REASON" ] &&
    ALT_REASON=$(alt_disk_add_reason "$ALT_REASON" "$ALT_LOG_REASON")

  ALT_UNREAD=""
  [ -z "$ALT_USABLE" ] && ALT_UNREAD="$ALT_UNREAD usable"
  [ -z "$ALT_BOOT_DISK" ] && ALT_UNREAD="$ALT_UNREAD boot_disk"
  [ -z "$ALT_PLATFORM_BOOTABLE" ] && ALT_UNREAD="$ALT_UNREAD platform_bootable"
  [ -z "$ALT_IN_BOOTLIST" ] && ALT_UNREAD="$ALT_UNREAD in_normal_bootlist"
  [ -z "$ALT_RUNNING_OS" ] && ALT_UNREAD="$ALT_UNREAD running_oslevel"
  [ -z "$ALT_LAST_UPDATED" ] && ALT_UNREAD="$ALT_UNREAD last_updated"
  [ -z "$ALT_AGE" ] && ALT_UNREAD="$ALT_UNREAD age_days"
  [ -z "$ALT_FRESHNESS" ] && ALT_UNREAD="$ALT_UNREAD freshness"
  [ -z "$ALT_FRESHNESS_BASIS" ] && ALT_UNREAD="$ALT_UNREAD freshness_basis"
  [ -z "$ALT_LOG_TARGET_DISKS" ] && ALT_UNREAD="$ALT_UNREAD completion_target_disks"
  ALT_UNREAD=$(printf '%s\n' "$ALT_UNREAD" | awk '
    { for (field=1; field<=NF; field++) if (!seen[$field]++)
        output=output (output=="" ? "" : " ") $field }
    END { print output }')
  if [ -n "$ALT_UNREAD" ] || [ "$ALT_DEVICE_UNKNOWN" -eq 1 ]; then
    ALT_BASIS=partial
  else
    ALT_BASIS=observed
  fi
  ALT_NA=""

  alt_disk_append '"alt_disk_usability":{'
  alt_disk_append "$(printf '"status":"%s","usable":%s,"volume_group":%s,"disks":%s,' \
    "$ALT_STATUS" "$(alt_disk_jbool "$ALT_USABLE")" \
    "$(alt_disk_jstring "$ALT_VG")" "$(alt_disk_jlist "$ALT_EXISTING_DISKS")")"
  alt_disk_append "$(printf '"boot_disk":%s,"device_states":[%s],' \
    "$(alt_disk_jnullable_string "$ALT_BOOT_DISK")" "$ALT_DEVICE_ITEMS")"
  alt_disk_append "$(printf '"platform_bootable":%s,"in_normal_bootlist":%s,' \
    "$(alt_disk_jbool "$ALT_PLATFORM_BOOTABLE")" "$(alt_disk_jbool "$ALT_IN_BOOTLIST")")"
  alt_disk_append "$(printf '"running_oslevel":%s,"last_updated":%s,"age_days":%s,"freshness":%s,' \
    "$(alt_disk_jnullable_string "$ALT_RUNNING_OS")" \
    "$(alt_disk_jnullable_string "$ALT_LAST_UPDATED")" \
    "$(alt_disk_jnumber "$ALT_AGE")" "$(alt_disk_jnullable_string "$ALT_FRESHNESS")")"
  alt_disk_append "$(printf '"freshness_basis":%s,"completion_target_disks":%s,' \
    "$(alt_disk_jnullable_string "$ALT_FRESHNESS_BASIS")" \
    "$(alt_disk_jnullable_list "$ALT_LOG_TARGET_DISKS")")"
  alt_disk_append "$(printf '"reason":%s,' "$(alt_disk_jnullable_string "$ALT_REASON")")"
  alt_disk_emit_alt_sources
  alt_disk_append "$(printf ',"basis":"%s","unreadable":%s,"not_applicable":%s}' \
    "$ALT_BASIS" "$(alt_disk_jlist "$ALT_UNREAD")" "$(alt_disk_jlist "$ALT_NA")")"
  alt_disk_set_finding "$ALT_STATUS" "$ALT_USABLE" "$ALT_VG" "$ALT_EXISTING_DISKS" \
    "$ALT_BOOT_DISK" "$ALT_DEVICE_ITEMS" "$ALT_PLATFORM_BOOTABLE" "$ALT_IN_BOOTLIST" \
    "$ALT_RUNNING_OS" "$ALT_LAST_UPDATED" "$ALT_AGE" "$ALT_FRESHNESS" "$ALT_REASON" \
    true "" "$ALT_UNREAD"
}

function check_alt_disk_recoverability {
  if [ "$ALT_DISK_RECOVERY_ASSESSED" -ne 1 ]; then
    alt_disk_assess_recoverability
  fi
  if [ "$ALT_DISK_FINDING_ADDED" -ne 1 ]; then
    add resilience alt_disk "Alternate rootvg clone" \
      "$ALT_DISK_FINDING_STATUS" "$ALT_DISK_FINDING_SEVERITY" \
      "$ALT_DISK_FINDING_OBSERVED" "$ALT_DISK_FINDING_MEANING" \
      "$ALT_DISK_FINDING_FIX"
    ALT_DISK_FINDING_ADDED=1
  fi
}

function emit_fact_alt_disk_recoverability {
  if [ "$ALT_DISK_RECOVERY_ASSESSED" -ne 1 ]; then
    alt_disk_assess_recoverability
  fi
  printf '%s' "$ALT_DISK_RECOVERY_JSON"
}

function standalone_run {
  check_alt_disk_recoverability
}

standalone_main "$@"
exit $?
