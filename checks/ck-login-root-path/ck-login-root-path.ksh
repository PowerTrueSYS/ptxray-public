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

AIXRAY_TOOL=ck-login-root-path


function standalone_check {
_AIXRAY_SESSION_KEYS=""

  # login_root_path — root's login-shell PATH must not carry the current-directory
  # token ('.') or any empty component. A leading colon, trailing colon, or doubled
  # colon in PATH resolves to the current directory at runtime — the same exposure
  # as an explicit '.'. The live runtime PATH is not obtainable honestly: opening
  # a root login shell through the su command (as the deleted probe did) would run
  # customer-authored login-shell code as root and would write /var/adm/sulog,
  # both of which violate PTxray's read-only charter. Instead this check reads the
  # files that DECLARE root's login PATH —
  # /etc/environment, /etc/profile, and /.profile (root's home directory is /) —
  # with a plain grep that executes nothing and writes nothing. It therefore
  # measures the PATH root's login shell is CONFIGURED to receive, never the
  # scanner's live environment.
  typeset LP_RAW LP_RC AWK_RC UNRESOLVED_LINE LS_RAW LS_RC
  typeset ENV_PRESENT PROF_PRESENT DOTPROF_PRESENT
  typeset LP_LINE
  typeset INDETERMINATE_PATHS ABSENT_PATHS ABSENT_DISCLOSURE ABSENT_MEANING

  # -------------------------------------------------------------------
  # Phase 0: establish which declaration files exist on this host.
  # aixv records stdout and stderr separately, then emits out-then-err so
  # the caller sees ls long-format rows (stdout) followed by per-file
  # diagnostics (stderr).
  LS_RAW=$(aixv ls_login_path_files ls -l /etc/environment /etc/profile /.profile)
  LS_RC=$?

  # Default to indeterminate: a declaration file the capture says nothing about
  # is a file PTxray did not read, and that must refuse rather than be assumed
  # absent. The classification below only ever moves a path OFF this default on
  # positive evidence.
  ENV_PRESENT="indeterminate"
  PROF_PRESENT="indeterminate"
  DOTPROF_PRESENT="indeterminate"

  if aix_capture_missing ls_login_path_files; then
    ENV_PRESENT="indeterminate"
    PROF_PRESENT="indeterminate"
    DOTPROF_PRESENT="indeterminate"
  elif [ "$LS_RC" -gt 2 ]; then
    # AIX ls exits 2 when a named operand is missing (verified on a live AIX
    # 7.2 box). A higher rc means the probe itself failed, not merely that a
    # declaration file is absent, so nothing can be classified.
    ENV_PRESENT="indeterminate"
    PROF_PRESENT="indeterminate"
    DOTPROF_PRESENT="indeterminate"
  else
    # Classify each declaration file from the capture alone, line by line:
    # "present" when a long-format row ENDS with the path, "absent" when a
    # line is exactly "<path> not found" (the AIX ls stderr form, verified on
    # a live AIX 7.2 box), "indeterminate" otherwise. Matching per line makes
    # the anchor exact, so a row for /etc/profile never satisfies /.profile.
    # Any other wording leaves the path indeterminate, which refuses -- AIX
    # grep says "can't open <path>" for BOTH an absent and an unreadable file,
    # so absence must be established here or not at all, and guessing it would
    # launder an unread violating PATH into a clean verdict.
    while read LP_LINE; do
      case "$LP_LINE" in
        "/etc/environment not found") ENV_PRESENT="absent" ;;
        "/etc/profile not found")     PROF_PRESENT="absent" ;;
        "/.profile not found")        DOTPROF_PRESENT="absent" ;;
        *"/etc/environment")          ENV_PRESENT="present" ;;
        *"/etc/profile")              PROF_PRESENT="present" ;;
        *"/.profile")                 DOTPROF_PRESENT="present" ;;
      esac
    done <<LPEOF
$LS_RAW
LPEOF
  fi

  # Build the indeterminate and absent lists for use in finding text.
  INDETERMINATE_PATHS=""
  ABSENT_PATHS=""
  case "$ENV_PRESENT" in
    indeterminate) INDETERMINATE_PATHS="/etc/environment" ;;
    absent) ABSENT_PATHS="/etc/environment" ;;
  esac
  case "$PROF_PRESENT" in
    indeterminate) INDETERMINATE_PATHS="${INDETERMINATE_PATHS:+$INDETERMINATE_PATHS, }/etc/profile" ;;
    absent) ABSENT_PATHS="${ABSENT_PATHS:+$ABSENT_PATHS, }/etc/profile" ;;
  esac
  case "$DOTPROF_PRESENT" in
    indeterminate) INDETERMINATE_PATHS="${INDETERMINATE_PATHS:+$INDETERMINATE_PATHS, }/.profile" ;;
    absent) ABSENT_PATHS="${ABSENT_PATHS:+$ABSENT_PATHS, }/.profile" ;;
  esac

  ABSENT_DISCLOSURE=""
  ABSENT_MEANING=""
  if [ -n "$ABSENT_PATHS" ]; then
    ABSENT_DISCLOSURE="; ${ABSENT_PATHS} does not exist on this host and declares no PATH"
    ABSENT_MEANING=" ${ABSENT_PATHS} does not exist on this host and declares no PATH."
  fi

  # -------------------------------------------------------------------
  # Phase 1: read the declared PATH assignments
  LP_RAW=$(aix login_path_decl grep -E '^[ \t]*(export[ \t]+)?PATH=' /etc/environment /etc/profile /.profile)
  LP_RC=$?

  # -------------------------------------------------------------------
  # Decision tree.  The adjudication (awk discriminator) lives in the final
  # else branch so the capture_missing, status, and emptiness gates all
  # structurally guard the use of LP_RAW.
  if aix_capture_missing login_path_decl; then
    add security login_root_path "Root login PATH" NOT_ASSESSED med \
        "not assessed — no capture exists for the declared login PATH probe" \
        "PTxray has no captured read of /etc/environment, /etc/profile, or /.profile, so the PATH declared for root's login shell is unknown." \
        "capture /etc/environment, /etc/profile, and /.profile for this check, then re-run PTxray." "cis-l1"

  elif [ -n "$INDETERMINATE_PATHS" ]; then
    add security login_root_path "Root login PATH" NOT_ASSESSED med \
        "not assessed — cannot establish whether ${INDETERMINATE_PATHS} exists (ls probe rc=$LS_RC)" \
        "PTxray cannot determine whether ${INDETERMINATE_PATHS} exists on this host; this file may declare a violating PATH that was not read. The ls -l probe returned rc $LS_RC." \
        "verify the file exists and is readable, then re-run PTxray." "cis-l1"

  elif [ "$LP_RC" -ge 2 ] && [ -z "$LP_RAW" ]; then
    # grep rc 2 means at least one named file could not be opened, but every
    # file is now classified as present or absent.  An absent file declares
    # nothing — the read is complete over the files that exist.  With no
    # PATH lines captured, this is the same refusal as rc 1.
    add security login_root_path "Root login PATH" NOT_ASSESSED med \
        "not assessed — no PATH assignment found in the declaration files that exist${ABSENT_DISCLOSURE}" \
        "The declaration files that exist on this host were read but no PATH assignment was captured; root's login shell would fall back to a default PATH that PTxray did not measure.${ABSENT_MEANING}" \
        "add an explicit PATH assignment to /etc/environment or a login profile, then re-run PTxray." "cis-l1"

  elif [ "$LP_RC" -eq 1 ]; then
    add security login_root_path "Root login PATH" NOT_ASSESSED med \
        "not assessed — no PATH assignment found in the declaration files that exist${ABSENT_DISCLOSURE}" \
        "The declaration files that exist on this host were read but no PATH assignment was captured; root's login shell would fall back to a default PATH that PTxray did not measure.${ABSENT_MEANING}" \
        "add an explicit PATH assignment to /etc/environment or a login profile, then re-run PTxray." "cis-l1"

  else
    # LP_RC is 0 (grep matched at least one PATH line), or LP_RC >= 2
    # with every file classified as present or absent and LP_RAW non-empty.
    # In either case the read is complete over the files that exist and
    # at least one captured PATH line is available for adjudication.
    # Discriminator contract:
    # awk rc 0 = at least one PATH element ANYWHERE in the capture was
    # adjudicated, no violation was found, and no line was ambiguous, rc 1 = a
    # violating element was found, rc 2 = a PATH line could not be parsed and
    # the state is genuinely unknown, rc 3 = NO PATH element anywhere in the
    # capture was adjudicated (every declaration reduced to all-variable
    # elements). Adjudication is per-capture, not per-declaration: a single
    # all-variable declaration does not refuse the whole check when another
    # declaration was adjudicated. Ordering: a determinate violation (hit)
    # beats everything; an ambiguous line (a ';' suffix that is not
    # "export PATH") outranks PASS, because the unparsed content may hide a
    # violation and the check cannot judge it; PASS needs at least one
    # adjudicated element AND no ambiguous line. An empty or whitespace-only
    # PATH value is a single empty field — the same class as a
    # leading/trailing/doubled colon — and is a FAIL, whether it was empty on
    # the line or emptied by stripping a '; export PATH' suffix; a line that
    # yields no elements at all is the same determinate empty FAIL and is never
    # an unresolved all-variable declaration. Only a genuine variable reference
    # — a $ followed by a name character or an opening brace, such as $PATH,
    # $HOME/bin or ${PATH} — is not statically resolvable and is skipped, not
    # judged; every other element, including $(...) command substitution,
    # backtick substitution, and a bare $, is adjudicated as an ordinary
    # element and fails the not-absolute rule. A '; export PATH' suffix is
    # recognized after stripping trailing whitespace and a carriage return, so
    # CRLF-formatted declaration files parse like LF ones. The unresolvable
    # declaration(s) are printed to stdout whenever any exist, so
    # UNRESOLVED_LINE is populated for both a NOT_ASSESSED (to name them) and a
    # PASS (to disclose what it did not judge).
    # UNRESOLVED_LINE is declared in the bare typeset at the top of this
    # function. Do NOT "tidy" this into `typeset UNRESOLVED_LINE=$(...)`: under
    # ksh, `typeset VAR=$(cmd)` returns the exit status of typeset — 0 — not
    # the command's, so AWK_RC would read 0 for every run and silently turn
    # every FAIL and every refusal into PASS.
    UNRESOLVED_LINE=$(printf '%s\n' "$LP_RAW" | awk '
      function empty(e) {
        return (e == "") || (e ~ /^[ \t]+$/)
      }
      {
        line=$0
        sub(/^\/etc\/environment:/, "", line)
        sub(/^\/etc\/profile:/, "", line)
        sub(/^\/\.profile:/, "", line)
        sub(/^[ \t]+/, "", line)
        sub(/^export[ \t]+/, "", line)
        if (line !~ /^PATH=/) next
        sub(/^PATH=/, "", line)
        # Strip a matching pair of surrounding quotes. Written as two explicit
        # branches with a literal anchored sub() rather than the obvious
        # length()-based tail comparison: tests/lint-ksh88.sh bans `length(`
        # followed by an identifier, because it cannot statically tell the
        # portable POSIX length(string) apart from the gawk-only
        # length(array). Rewriting is the honest fix; loosening the ban would
        # also unban the construct that actually breaks AIX awk.
        if (substr(line,1,1) == "\"") {
          line=substr(line,2)
          sub(/"$/, "", line)
        } else if (substr(line,1,1) == "\047") {
          line=substr(line,2)
          sub(/\047$/, "", line)
        }
        sub(/[ \t]+#.*/, "", line)
        sub(/[ \t]+$/, "", line)
        if (empty(line)) { hit=1; next }
        if (index(line, ";") > 0) {
          semicolon=index(line, ";")
          suffix=substr(line, semicolon+1)
          sub(/^[ \t]+/, "", suffix)
          sub(/[ \t\r]+$/, "", suffix)
          line=substr(line, 1, semicolon-1)
          sub(/[ \t\r]+$/, "", line)
          if (suffix != "export PATH") { ambiguous=1; next }
          # A value emptied by the suffix strip is a determinate empty PATH,
          # the same FAIL as the pre-strip empty check above.
          if (empty(line)) { hit=1; next }
        }
        n=split(line, element, ":")
        # No elements at all is a determinate empty PATH, not an unresolved
        # all-variable declaration: it must reach hit, never the per-capture
        # PASS relaxation.
        if (n == 0) { hit=1; next }
        count=0
        for (i=1; i<=n; i++) {
          piece=element[i]
          # Skip only a genuine variable reference: a $ followed by a name
          # character or an opening brace ($PATH, $HOME/bin, ${PATH}). Anything
          # else starting with $ — $(...), backticks, a bare $ — falls through
          # to ordinary adjudication, where the not-absolute rule fails it.
          if (piece ~ /^\$([A-Za-z0-9_]|[{])/) continue
          count++
          adjudicated++
          if (empty(piece)) { hit=1; continue }
          if (piece == ".") { hit=1; continue }
          if (piece !~ /^\//) { hit=1; continue }
        }
        # count == 0 now means only "every element was a $ reference". The
        # no-elements-at-all case is already handled above (n == 0 -> hit).
        if (count == 0 && n > 0) {
          unresolved=1
          line_norm=$0
          sub(/[ \t\r]+$/, "", line_norm)
          unresolved_list = unresolved_list (unresolved_list == "" ? line_norm : "; " line_norm)
        }
      }
      END {
        # The list is printed whenever it is non-empty, not only on rc 3, so a
        # PASS that left a declaration unadjudicated can still name it in the
        # finding text. The exit code carries the verdict.
        if (unresolved_list != "") print unresolved_list
        if (hit) exit 1
        if (ambiguous) exit 2
        if (adjudicated > 0) exit 0
        if (unresolved) exit 3
        exit 3
      }
    ')
    AWK_RC=$?
    case "$AWK_RC" in
      0)
        if [ -n "$UNRESOLVED_LINE" ]; then
          add security login_root_path "Root login PATH" PASS med \
              "declared root login PATH has no '.', empty, or relative component${ABSENT_DISCLOSURE}" \
              "Every PATH element that was adjudicated — captured from /etc/environment, /etc/profile, and /.profile, the files that declare root's login PATH — is built only from absolute, non-empty directory components: no current-directory token, no leading/trailing/doubled colon, and no relative element. The following declaration(s) were not adjudicated because every element is an unresolved variable reference, and were not judged: ${UNRESOLVED_LINE}.${ABSENT_MEANING}" \
              "n/a" "cis-l1"
        else
          add security login_root_path "Root login PATH" PASS med \
              "declared root login PATH has no '.', empty, or relative component${ABSENT_DISCLOSURE}" \
              "Every PATH element captured from /etc/environment, /etc/profile, and /.profile — the files that declare root's login PATH — is built only from absolute, non-empty directory components: no current-directory token, no leading/trailing/doubled colon, and no relative element. Variable references in an assignment are not statically resolvable and are not judged.${ABSENT_MEANING}" \
              "n/a" "cis-l1"
        fi
        ;;
      1)
        add security login_root_path "Root login PATH" FAIL high \
            "declared root login PATH contains '.' or an empty/relative component${ABSENT_DISCLOSURE}" \
            "A PATH assignment captured from /etc/environment, /etc/profile, or /.profile carries the current-directory token, an empty component (leading, trailing, or doubled colon), or a relative element, so a command invoked from an untrusted directory can resolve against the current directory.${ABSENT_MEANING}" \
            "remove '.' and any empty or relative component from the PATH assigned to root's login shell." "cis-l1"
        ;;
      2)
        add security login_root_path "Root login PATH" NOT_ASSESSED med \
            "not assessed — a declared PATH carries a ';' suffix that is not 'export PATH' and could not be judged${ABSENT_DISCLOSURE}" \
            "A PATH declaration captured from /etc/environment, /etc/profile, or /.profile contains a ';' suffix that is not 'export PATH' (for example, an additional command on the same line). PTxray cannot tell whether the PATH value is clean, so the declared login PATH is not assessed.${ABSENT_MEANING}" \
            "declare root's login PATH as a single assignment with no trailing command, then re-run PTxray." "cis-l1"
        ;;
      3)
        if [ -n "$UNRESOLVED_LINE" ]; then
          add security login_root_path "Root login PATH" NOT_ASSESSED med \
              "not assessed — declared PATH '${UNRESOLVED_LINE}' is built entirely from unresolved variable references${ABSENT_DISCLOSURE}" \
              "The PATH declaration \"${UNRESOLVED_LINE}\" is composed only of variable references (\$VAR) that PTxray cannot statically resolve, so zero of its elements were adjudicated. PASS requires at least one adjudicated element; a declaration that reduces to none cannot be confirmed clean.${ABSENT_MEANING}" \
              "declare a concrete absolute PATH for root's login shell, or include at least one absolute, non-variable component, then re-run PTxray." "cis-l1"
        else
          add security login_root_path "Root login PATH" NOT_ASSESSED med \
              "not assessed — no PATH element in the capture was adjudicated${ABSENT_DISCLOSURE}" \
              "No PATH element captured from /etc/environment, /etc/profile, and /.profile was adjudicated: every declaration reduced to unresolved variable references, or the capture carried no parseable declaration at all. PASS requires at least one adjudicated element, so the declared login PATH cannot be confirmed clean.${ABSENT_MEANING}" \
              "declare a concrete absolute PATH for root's login shell, or include at least one absolute, non-variable component, then re-run PTxray." "cis-l1"
        fi
        ;;
      *)
        add security login_root_path "Root login PATH" NOT_ASSESSED med \
            "not assessed — declared PATH discriminator failed (awk rc=$AWK_RC)${ABSENT_DISCLOSURE}" \
            "PTxray could not test the declared PATH assignments: the discriminator exited with an unexpected status, or a PATH line could not be parsed (for example, more than one command on the line).${ABSENT_MEANING}" \
            "re-run the check; if it persists, collect the captured PATH lines and inspect them manually." "cis-l1"
        ;;
    esac
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
