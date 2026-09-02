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

AIXRAY_TOOL=ck-network-inventory

_AIXRAY_SESSION_KEYS=""
# Standalone fact and finding producer for AIX interface, route, and resolver
# inventory. Include-safe: integration calls the fact emitter from the facts
# renderer and the check from the assessment spine.

function network_inventory_json_escape {
  awk '
    {
      s=$0
      gsub(/\\/, "\\\\", s)
      gsub(/"/, "\\\"", s)
      gsub(/\t/, "\\t", s)
      gsub(/\r/, "\\r", s)
      gsub(/[\001-\010\013\014\016-\037]/, "", s)
      if (seen++) printf "\\n"
      printf "%s", s
    }
  '
}

function network_inventory_ifconfig_shape {
  awk '
    function ipv4(value, part, count, i) {
      count=split(value, part, ".")
      if (count!=4) return 0
      for (i=1; i<=4; i++)
        if (part[i] !~ /^[0-9][0-9]*$/ || part[i]+0>255) return 0
      return 1
    }
    function netmask(value, raw) {
      if (ipv4(value)) return 1
      raw=value
      sub(/^0[xX]/, "", raw)
      return substr(raw,8,1)!="" && substr(raw,9,1)=="" &&
        raw ~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/
    }
    function ipv6_component(value, allow_ipv4) {
      if (index(value, ".")>0) {
        if (!allow_ipv4 || !ipv4(value)) return 0
        return 2
      }
      if (substr(value,1,1)=="" || substr(value,5,1)!="" ||
          value !~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/) return 0
      return 1
    }
    function ipv6_side(value, allow_ipv4, part, count, i, units, size) {
      count=split(value, part, ":")
      units=0
      for (i=1; i<=count; i++) {
        size=ipv6_component(part[i], allow_ipv4 && i==count)
        if (size==0) return -1
        units+=size
      }
      return units
    }
    function ipv6(value, percent, zone, compression, remainder, left,
                  right, left_units, right_units, total) {
      percent=index(value, "%")
      if (percent>0) {
        zone=substr(value, percent+1)
        if (zone=="" || index(zone, "%")>0 ||
            zone !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/) return 0
        value=substr(value, 1, percent-1)
      }
      if (value=="" || index(value, ":")==0) return 0
      compression=index(value, "::")
      if (compression>0) {
        remainder=substr(value, compression+2)
        if (index(remainder, "::")>0) return 0
        left=substr(value, 1, compression-1)
        right=remainder
        left_units=0
        right_units=0
        if (left!="") left_units=ipv6_side(left, 0)
        if (right!="") right_units=ipv6_side(right, 1)
        if (left_units<0 || right_units<0) return 0
        total=left_units+right_units
        return total<8
      }
      if (value ~ /^:/ || value ~ /:$/) return 0
      total=ipv6_side(value, 1)
      return total==8
    }
    function ipv6_prefix(value, slash, address, prefix) {
      slash=index(value, "/")
      if (slash==0) return ipv6(value)
      address=substr(value, 1, slash-1)
      prefix=substr(value, slash+1)
      if (address=="" || prefix !~ /^[0-9][0-9]*$/ ||
          prefix+0>128 || index(prefix, "/")>0) return 0
      return ipv6(address)
    }
    /^[ \t\r]*$/ { next }
    /^[^ \t]/ {
      if ($0 !~ /^[A-Za-z][A-Za-z0-9_.-]*:[ \t]*flags=[^<]*<[^>]*>/) {
        bad=1
        next
      }
      name=$1
      sub(/:.*/, "", name)
      if (name !~ /^[A-Za-z][A-Za-z0-9_.-]*$/ || seen[name]++) bad=1
      current=name
      headers++
      for (i=1; i<=NF; i++) {
        if ($i=="mtu") {
          mtu++
          if (i==NF || $(i+1) !~ /^[1-9][0-9]*$/) bad=1
        }
      }
      next
    }
    {
      if (current=="") { bad=1; next }
      if ($1=="inet") {
        if (!ipv4($2)) { bad=1; next }
        masks=0
        for (i=3; i<=NF; i++) {
          if ($i=="netmask") {
            masks++
            if (i==NF || !netmask($(i+1))) bad=1
          }
        }
        if (masks!=1) bad=1
      } else if ($1=="inet6") {
        if (!ipv6_prefix($2)) bad=1
      } else if ($1=="tcp_sendspace" || $1=="tcp_recvspace" ||
                 $1=="rfc1323") {
        if (NF<2 || NF%2!=0) { bad=1; next }
        for (i=1; i<=NF; i+=2) {
          if (($i!="tcp_sendspace" && $i!="tcp_recvspace" &&
               $i!="rfc1323") ||
              $(i+1) !~ /^[0-9][0-9]*$/) bad=1
        }
      } else {
        bad=1
      }
    }
    END { if (bad || headers==0) exit 1 }
  '
}

function network_inventory_parse_ifconfig {
  awk '
    /^[ \t\r]*$/ { next }
    /^[^ \t]/ {
      name=$1
      sub(/:.*/, "", name)
      flags=$0
      sub(/^[^<]*</, "", flags)
      sub(/>.*/, "", flags)
      count=split(flags, flag, ",")
      state="down"
      for (i=1; i<=count; i++) if (flag[i]=="UP") state="up"
      mtu=""
      for (i=1; i<=NF; i++) if ($i=="mtu") mtu=$(i+1)
      current=name
      printf "I\t%s\t%s\t%s\n", name, state, mtu
      next
    }
    $1=="inet" {
      mask=""
      for (i=3; i<=NF; i++) if ($i=="netmask") mask=$(i+1)
      printf "A\t%s\t%s\t%s\n", current, $2, mask
    }
  '
}

function network_inventory_lsattr_shape {
  awk '
    /^[ \t\r]*$/ { next }
    $1=="mtu" {
      seen++
      if (NF<2 || $2 !~ /^[1-9][0-9]*$/) bad=1
    }
    END { if (bad || seen!=1) exit 1 }
  '
}

function network_inventory_entstat_shape {
  typeset NI_ES_WANTED
  NI_ES_WANTED=$1
  awk -v wanted="$NI_ES_WANTED" '
    function trim(value) {
      sub(/^[ \t]+/, "", value)
      sub(/[ \t]+$/, "", value)
      return value
    }
    /^ETHERNET STATISTICS \(/ {
      value=$0
      sub(/^[^(]*\(/, "", value)
      sub(/\).*/, "", value)
      headers++
      if (value!=wanted) bad=1
    }
    /^Device Type:/ {
      value=$0
      sub(/^[^:]*:[ \t]*/, "", value)
      types++
      if (trim(value)=="") bad=1
    }
    END { if (bad || headers!=1 || types!=1) exit 1 }
  '
}

function network_inventory_entstat_type {
  awk '
    /^Device Type:/ {
      sub(/^[^:]*:[ \t]*/, "")
      sub(/[ \t]+$/, "")
      print
      exit
    }
  '
}

function network_inventory_entstat_speed {
  awk '
    function trim(value) {
      sub(/^[ \t]+/, "", value)
      sub(/[ \t]+$/, "", value)
      return value
    }
    function label(kind) {
      if (kind=="media") return "Media Speed Running"
      return "Adapter Data Rate"
    }
    function parse_speed(value, kind, part, unit, shown, number) {
      value=trim(value)
      split(value, part, /[ \t]+/)
      rows[kind]++
      shown=part[1]
      if (part[2]!="") shown=shown " " part[2]
      if (shown_values[kind]!="") shown_values[kind]=shown_values[kind] ", "
      shown_values[kind]=shown_values[kind] shown

      if (part[1] !~ /^[1-9][0-9]*$/) {
        reason[kind]=label(kind) " reported a non-numeric value"
        return
      }
      if (part[2]=="") {
        reason[kind]=label(kind) " value lacked a unit"
        return
      }
      number=part[1]
      unit=tolower(part[2])
      if (unit=="mbps") {
        converted[kind]=number
      } else if (unit=="gbps") {
        converted[kind]=(number * 1000)
      } else {
        reason[kind]=label(kind) " reported an unrecognized unit"
      }
    }
    /^Media Speed Running:/ {
      value=$0
      sub(/^[^:]*:[ \t]*/, "", value)
      parse_speed(value, "media")
    }
    /^Adapter Data Rate:/ {
      value=$0
      sub(/^[^:]*:[ \t]*/, "", value)
      parse_speed(value, "rate")
    }
    END {
      if (rows["media"]>0) kind="media"
      else if (rows["rate"]>0) kind="rate"
      else {
        print "NOT_ASSESSED|did not report media speed or adapter data rate"
        exit
      }

      if (rows[kind]!=1) {
        print "NOT_ASSESSED|" label(kind) " reported multiple rows (values: " shown_values[kind] ")"
      } else if (reason[kind]!="") {
        print "NOT_ASSESSED|" reason[kind]
      } else {
        print "OBSERVED|" converted[kind]
      }
    }
  '
}

function network_inventory_netstat_shape {
  awk '
    function ipv4(value, part, count, i) {
      count=split(value, part, ".")
      if (count!=4) return 0
      for (i=1; i<=4; i++)
        if (part[i] !~ /^[0-9][0-9]*$/ || part[i]+0>255) return 0
      return 1
    }
    function ipv6_component(value, allow_ipv4) {
      if (index(value, ".")>0) {
        if (!allow_ipv4 || !ipv4(value)) return 0
        return 2
      }
      if (substr(value,1,1)=="" || substr(value,5,1)!="" ||
          value !~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/) return 0
      return 1
    }
    function ipv6_side(value, allow_ipv4, part, count, i, units, size) {
      count=split(value, part, ":")
      units=0
      for (i=1; i<=count; i++) {
        size=ipv6_component(part[i], allow_ipv4 && i==count)
        if (size==0) return -1
        units+=size
      }
      return units
    }
    function ipv6(value, percent, zone, compression, remainder, left,
                  right, left_units, right_units, total) {
      percent=index(value, "%")
      if (percent>0) {
        zone=substr(value, percent+1)
        if (zone=="" || index(zone, "%")>0 ||
            zone !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/) return 0
        value=substr(value, 1, percent-1)
      }
      if (value=="" || index(value, ":")==0) return 0
      compression=index(value, "::")
      if (compression>0) {
        remainder=substr(value, compression+2)
        if (index(remainder, "::")>0) return 0
        left=substr(value, 1, compression-1)
        right=remainder
        left_units=0
        right_units=0
        if (left!="") left_units=ipv6_side(left, 0)
        if (right!="") right_units=ipv6_side(right, 1)
        if (left_units<0 || right_units<0) return 0
        total=left_units+right_units
        return total<8
      }
      if (value ~ /^:/ || value ~ /:$/) return 0
      total=ipv6_side(value, 1)
      return total==8
    }
    {
      lower=tolower($0)
      if ($1=="Routing" && $2=="tables") headers++
      if (lower ~ /protocol family[ \t]+24([ \t(:]|$)/ ||
          lower ~ /internet v6/) {
        family="ipv6"
        families++
        next
      }
      if (lower ~ /protocol family[ \t]+2([ \t(:]|$)/) {
        family="ipv4"
        families++
        next
      }
      if ($1=="default" || $1=="0.0.0.0" ||
          $1=="::/0" || $1=="::0/0") {
        route_family=family
        if ($1=="0.0.0.0") route_family="ipv4"
        if ($1=="::/0" || $1=="::0/0") route_family="ipv6"
        defaults++
        if (NF<3 || $3 !~ /^[A-Za-z][A-Za-z]*$/ || route_family=="" ||
            (route_family=="ipv4" && !ipv4($2)) ||
            (route_family=="ipv6" && !ipv6($2))) bad=1
      }
    }
    END { if (bad || headers!=1 || families==0) exit 1 }
  '
}

function network_inventory_parse_netstat {
  awk '
    {
      lower=tolower($0)
      if (lower ~ /protocol family[ \t]+24([ \t(:]|$)/ ||
          lower ~ /internet v6/) {
        family="ipv6"
        next
      }
      if (lower ~ /protocol family[ \t]+2([ \t(:]|$)/) {
        family="ipv4"
        next
      }
      if ($1=="default" || $1=="0.0.0.0" ||
          $1=="::/0" || $1=="::0/0") {
        route_family=family
        if ($1=="0.0.0.0") route_family="ipv4"
        if ($1=="::/0" || $1=="::0/0") route_family="ipv6"
        iface=""
        for (i=3; i<=NF; i++)
          if ($i ~ /^[A-Za-z][A-Za-z_.-]*[0-9][0-9]*$/) iface=$i
        if (iface=="")
          printf "%s\t%s\t\tPARTIAL\tnetstat -rn default route did not expose an interface\n", route_family, $2
        else
          printf "%s\t%s\t%s\tOBSERVED\t\n", route_family, $2, iface
      }
    }
  '
}

function network_inventory_resolv_shape {
  awk '
    function ipv4(value, part, count, i) {
      count=split(value, part, ".")
      if (count!=4) return 0
      for (i=1; i<=4; i++)
        if (part[i] !~ /^[0-9][0-9]*$/ || part[i]+0>255) return 0
      return 1
    }
    function ipv6_component(value, allow_ipv4) {
      if (index(value, ".")>0) {
        if (!allow_ipv4 || !ipv4(value)) return 0
        return 2
      }
      if (substr(value,1,1)=="" || substr(value,5,1)!="" ||
          value !~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/) return 0
      return 1
    }
    function ipv6_side(value, allow_ipv4, part, count, i, units, size) {
      count=split(value, part, ":")
      units=0
      for (i=1; i<=count; i++) {
        size=ipv6_component(part[i], allow_ipv4 && i==count)
        if (size==0) return -1
        units+=size
      }
      return units
    }
    function ipv6(value, percent, zone, compression, remainder, left,
                  right, left_units, right_units, total) {
      percent=index(value, "%")
      if (percent>0) {
        zone=substr(value, percent+1)
        if (zone=="" || index(zone, "%")>0 ||
            zone !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/) return 0
        value=substr(value, 1, percent-1)
      }
      if (value=="" || index(value, ":")==0) return 0
      compression=index(value, "::")
      if (compression>0) {
        remainder=substr(value, compression+2)
        if (index(remainder, "::")>0) return 0
        left=substr(value, 1, compression-1)
        right=remainder
        left_units=0
        right_units=0
        if (left!="") left_units=ipv6_side(left, 0)
        if (right!="") right_units=ipv6_side(right, 1)
        if (left_units<0 || right_units<0) return 0
        total=left_units+right_units
        return total<8
      }
      if (value ~ /^:/ || value ~ /:$/) return 0
      total=ipv6_side(value, 1)
      return total==8
    }
    /^[ \t\r]*$/ { next }
    /^[ \t]*[#;]/ { next }
    {
      if ($1=="nameserver") {
        if (NF<2 || (!ipv4($2) && !ipv6($2))) { bad=1; next }
        for (i=3; i<=NF; i++) {
          if (substr($i,1,1)=="#" || substr($i,1,1)==";") break
          bad=1
        }
      } else if ($1=="domain" || $1=="search" || $1=="sortlist" ||
                 $1=="options" || $1=="lookup") {
        if (NF<2) bad=1
      } else {
        bad=1
      }
    }
    END { if (bad) exit 1 }
  '
}

function network_inventory_parse_resolv {
  awk '
    /^[ \t]*nameserver[ \t]+/ { print $2 }
  '
}

function network_inventory_append_gap {
  typeset NI_AG_CURRENT NI_AG_REASON NI_AG_ESCAPED
  NI_AG_CURRENT=$1
  NI_AG_REASON=$2
  NI_AG_ESCAPED=$(printf '%s' "$NI_AG_REASON" |
    network_inventory_json_escape)
  if [ -n "$NI_AG_CURRENT" ]; then
    printf '%s, "%s"' "$NI_AG_CURRENT" "$NI_AG_ESCAPED"
  else
    printf '"%s"' "$NI_AG_ESCAPED"
  fi
}

function emit_fact_network_inventory {
  typeset NI_IFCONFIG NI_IFCONFIG_RC NI_IF_WHY NI_IF_SOURCE NI_PARSED
  typeset NI_NAMES NI_IF_ITEMS NI_IF_PARTIAL NI_IF NI_STATE NI_HEADER_MTU
  typeset NI_IPV4 NI_MTU NI_MTU_STATUS NI_MTU_REASON NI_MTU_REASON_JSON
  typeset NI_LSATTR NI_LSATTR_RC NI_ADAPTER NI_ADAPTER_TYPE
  typeset NI_ADAPTER_STATUS NI_ADAPTER_REASON NI_ADAPTER_REASON_JSON
  typeset NI_SPEED NI_SPEED_RESULT NI_SPEED_STATUS NI_SPEED_REASON
  typeset NI_SPEED_REASON_JSON
  typeset NI_ENTSTAT NI_ENTSTAT_RC NI_SUFFIX NI_ADAPTER_CANDIDATE
  typeset NI_ITEM_STATUS NI_ITEM_REASON
  typeset NI_ITEM_REASON_ESC NI_ITEM_REASON_JSON NI_ADAPTER_JSON NI_TYPE_ESC
  typeset NI_TYPE_JSON NI_SPEED_JSON NI_MTU_JSON NI_ITEM
  typeset NI_INTERFACES_STATUS NI_INTERFACES_REASON NI_INTERFACES_REASON_JSON
  typeset NI_NETSTAT NI_NETSTAT_RC NI_ROUTE_WHY NI_ROUTE_SOURCE NI_ROUTE_ROWS
  typeset NI_ROUTE_ITEMS NI_ROUTE_STATUS NI_ROUTE_REASON NI_ROUTE_REASON_JSON
  typeset NI_DNS_RAW NI_DNS_RC NI_DNS_WHY NI_DNS_SOURCE NI_DNS_ITEMS
  typeset NI_DNS_STATUS NI_DNS_REASON_JSON NI_GAPS NI_OBSERVED NI_COMPLETE
  typeset NI_TOP_STATUS NI_TOP_REASON NI_TOP_REASON_JSON

  NI_GAPS=""
  NI_IF_ITEMS=""
  NI_IF_PARTIAL=0

  NI_IFCONFIG=$(aix network_ifconfig_a ifconfig -a)
  NI_IFCONFIG_RC=$?
  NI_IF_SOURCE="{ \"capture\": \"network_ifconfig_a\", \"command\": \"ifconfig -a\", \"rc\": $NI_IFCONFIG_RC }"
  NI_IF_WHY=""
  if [ "$NI_IFCONFIG_RC" -ne 0 ]; then
    NI_IF_WHY="ifconfig -a capture failed (rc=$NI_IFCONFIG_RC)"
  elif [ -z "$NI_IFCONFIG" ]; then
    NI_IF_WHY="ifconfig -a capture empty (rc=0)"
  elif ! printf '%s\n' "$NI_IFCONFIG" | network_inventory_ifconfig_shape; then
    NI_IF_WHY="ifconfig -a capture unparseable (rc=0)"
  fi

  if [ -n "$NI_IF_WHY" ]; then
    NI_INTERFACES_STATUS="NOT_ASSESSED"
    NI_INTERFACES_REASON=$NI_IF_WHY
    NI_GAPS=$(network_inventory_append_gap "$NI_GAPS" "$NI_IF_WHY")
  else
    NI_PARSED=$(printf '%s\n' "$NI_IFCONFIG" |
      network_inventory_parse_ifconfig)
    NI_NAMES=$(printf '%s\n' "$NI_PARSED" |
      awk -F '\t' '$1=="I" { print $2 }')

    while IFS= read -r NI_IF
    do
      [ -n "$NI_IF" ] || continue
      NI_STATE=$(printf '%s\n' "$NI_PARSED" |
        awk -F '\t' -v wanted="$NI_IF" \
          '$1=="I" && $2==wanted { print $3; exit }')
      NI_HEADER_MTU=$(printf '%s\n' "$NI_PARSED" |
        awk -F '\t' -v wanted="$NI_IF" \
          '$1=="I" && $2==wanted { print $4; exit }')
      NI_IPV4=$(printf '%s\n' "$NI_PARSED" |
        awk -F '\t' -v wanted="$NI_IF" '
          $1=="A" && $2==wanted {
            if (seen++) printf ", "
            printf "{ \"address\": \"%s\", \"netmask\": \"%s\" }", $3, $4
          }')

      NI_MTU=""
      NI_MTU_STATUS="OBSERVED"
      NI_MTU_REASON=""
      if [ -n "$NI_HEADER_MTU" ]; then
        NI_MTU=$NI_HEADER_MTU
      else
        NI_LSATTR=$(aix "network_lsattr_$NI_IF" lsattr -El "$NI_IF")
        NI_LSATTR_RC=$?
        if [ "$NI_LSATTR_RC" -ne 0 ]; then
          NI_MTU_REASON="lsattr -El $NI_IF capture failed (rc=$NI_LSATTR_RC)"
        elif [ -z "$NI_LSATTR" ]; then
          NI_MTU_REASON="lsattr -El $NI_IF capture empty (rc=0)"
        elif ! printf '%s\n' "$NI_LSATTR" |
            network_inventory_lsattr_shape; then
          NI_MTU_REASON="lsattr -El $NI_IF capture unparseable (rc=0)"
        else
          NI_MTU=$(printf '%s\n' "$NI_LSATTR" |
            awk '$1=="mtu" { print $2; exit }')
        fi
        if [ -n "$NI_MTU_REASON" ]; then
          NI_MTU_STATUS="NOT_ASSESSED"
          NI_IF_PARTIAL=1
          NI_GAPS=$(network_inventory_append_gap "$NI_GAPS" "$NI_MTU_REASON")
        fi
      fi

      NI_ADAPTER=""
      NI_ADAPTER_TYPE=""
      NI_ADAPTER_STATUS="NOT_APPLICABLE"
      NI_ADAPTER_REASON="$NI_IF is not an Ethernet interface"
      NI_SPEED=""
      NI_SPEED_STATUS="NOT_APPLICABLE"
      NI_SPEED_REASON="$NI_IF is not an Ethernet interface"
      NI_SUFFIX=""
      NI_ADAPTER_CANDIDATE=""
      case "$NI_IF" in
        ent*) NI_SUFFIX=${NI_IF#ent} ;;
        en*) NI_SUFFIX=${NI_IF#en} ;;
        et*) NI_SUFFIX=${NI_IF#et} ;;
      esac
      case "$NI_SUFFIX" in
        ''|*[!0-9]*) ;;
        *)
          NI_ADAPTER_CANDIDATE="ent$NI_SUFFIX"
          NI_ENTSTAT=$(aix "network_entstat_$NI_ADAPTER_CANDIDATE" \
            entstat -d "$NI_ADAPTER_CANDIDATE")
          NI_ENTSTAT_RC=$?
          NI_ADAPTER_STATUS="NOT_ASSESSED"
          if [ "$NI_ENTSTAT_RC" -ne 0 ]; then
            NI_ADAPTER_REASON="entstat -d $NI_ADAPTER_CANDIDATE capture failed (rc=$NI_ENTSTAT_RC)"
          elif [ -z "$NI_ENTSTAT" ]; then
            NI_ADAPTER_REASON="entstat -d $NI_ADAPTER_CANDIDATE capture empty (rc=0)"
          elif ! printf '%s\n' "$NI_ENTSTAT" |
              network_inventory_entstat_shape "$NI_ADAPTER_CANDIDATE"; then
            NI_ADAPTER_REASON="entstat -d $NI_ADAPTER_CANDIDATE capture unparseable (rc=0)"
          else
            NI_ADAPTER=$NI_ADAPTER_CANDIDATE
            NI_ADAPTER_TYPE=$(printf '%s\n' "$NI_ENTSTAT" |
              network_inventory_entstat_type)
            NI_ADAPTER_STATUS="OBSERVED"
            NI_ADAPTER_REASON=""
            NI_SPEED_RESULT=$(printf '%s\n' "$NI_ENTSTAT" |
              network_inventory_entstat_speed)
          fi

          if [ "$NI_ADAPTER_STATUS" = "OBSERVED" ]; then
            NI_SPEED_STATUS=${NI_SPEED_RESULT%%\|*}
            NI_SPEED=${NI_SPEED_RESULT#*\|}
            if [ "$NI_SPEED_STATUS" = "OBSERVED" ]; then
              NI_SPEED_STATUS="OBSERVED"
              NI_SPEED_REASON=""
            else
              NI_SPEED_REASON=$NI_SPEED
              NI_SPEED=""
              NI_SPEED_STATUS="NOT_ASSESSED"
              if [ "$NI_SPEED_REASON" = \
                  "did not report media speed or adapter data rate" ]; then
                NI_SPEED_REASON="entstat -d $NI_ADAPTER_CANDIDATE $NI_SPEED_REASON"
              fi
            fi
          else
            NI_SPEED_STATUS="NOT_ASSESSED"
            NI_SPEED_REASON=$NI_ADAPTER_REASON
            NI_IF_PARTIAL=1
            NI_GAPS=$(network_inventory_append_gap "$NI_GAPS" "$NI_ADAPTER_REASON")
          fi
          ;;
      esac

      NI_ITEM_STATUS="OBSERVED"
      NI_ITEM_REASON=""
      if [ "$NI_MTU_STATUS" = "NOT_ASSESSED" ]; then
        NI_ITEM_STATUS="PARTIAL"
        NI_ITEM_REASON="MTU: $NI_MTU_REASON"
      fi
      if [ "$NI_ADAPTER_STATUS" = "NOT_ASSESSED" ]; then
        NI_ITEM_STATUS="PARTIAL"
        if [ -n "$NI_ITEM_REASON" ]; then
          NI_ITEM_REASON="$NI_ITEM_REASON; adapter: $NI_ADAPTER_REASON"
        else
          NI_ITEM_REASON="adapter: $NI_ADAPTER_REASON"
        fi
      fi

      if [ -n "$NI_MTU" ]; then NI_MTU_JSON=$NI_MTU; else NI_MTU_JSON=null; fi
      if [ -n "$NI_ADAPTER" ]; then
        NI_ADAPTER_JSON="\"$NI_ADAPTER\""
      else
        NI_ADAPTER_JSON=null
      fi
      if [ -n "$NI_ADAPTER_TYPE" ]; then
        NI_TYPE_ESC=$(printf '%s' "$NI_ADAPTER_TYPE" |
          network_inventory_json_escape)
        NI_TYPE_JSON="\"$NI_TYPE_ESC\""
      else
        NI_TYPE_JSON=null
      fi
      if [ -n "$NI_SPEED" ]; then NI_SPEED_JSON=$NI_SPEED; else NI_SPEED_JSON=null; fi

      if [ -n "$NI_MTU_REASON" ]; then
        NI_ITEM_REASON_ESC=$(printf '%s' "$NI_MTU_REASON" |
          network_inventory_json_escape)
        NI_MTU_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
      else
        NI_MTU_REASON_JSON=null
      fi
      if [ -n "$NI_ADAPTER_REASON" ]; then
        NI_ITEM_REASON_ESC=$(printf '%s' "$NI_ADAPTER_REASON" |
          network_inventory_json_escape)
        NI_ADAPTER_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
      else
        NI_ADAPTER_REASON_JSON=null
      fi
      if [ -n "$NI_SPEED_REASON" ]; then
        NI_ITEM_REASON_ESC=$(printf '%s' "$NI_SPEED_REASON" |
          network_inventory_json_escape)
        NI_SPEED_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
      else
        NI_SPEED_REASON_JSON=null
      fi
      if [ -n "$NI_ITEM_REASON" ]; then
        NI_ITEM_REASON_ESC=$(printf '%s' "$NI_ITEM_REASON" |
          network_inventory_json_escape)
        NI_ITEM_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
      else
        NI_ITEM_REASON_JSON=null
      fi

      NI_ITEM="{ \"name\": \"$NI_IF\", \"ipv4\": [$NI_IPV4], \"ipv4_status\": \"OBSERVED\", \"ipv4_reason\": null, \"state\": \"$NI_STATE\", \"state_status\": \"OBSERVED\", \"state_reason\": null, \"mtu\": $NI_MTU_JSON, \"mtu_status\": \"$NI_MTU_STATUS\", \"mtu_reason\": $NI_MTU_REASON_JSON, \"adapter\": $NI_ADAPTER_JSON, \"adapter_type\": $NI_TYPE_JSON, \"adapter_status\": \"$NI_ADAPTER_STATUS\", \"adapter_reason\": $NI_ADAPTER_REASON_JSON, \"media_speed_mbps\": $NI_SPEED_JSON, \"media_speed_status\": \"$NI_SPEED_STATUS\", \"media_speed_reason\": $NI_SPEED_REASON_JSON, \"status\": \"$NI_ITEM_STATUS\", \"reason\": $NI_ITEM_REASON_JSON }"
      if [ -n "$NI_IF_ITEMS" ]; then
        NI_IF_ITEMS="$NI_IF_ITEMS, $NI_ITEM"
      else
        NI_IF_ITEMS=$NI_ITEM
      fi
    done <<EOF
$NI_NAMES
EOF

    if [ "$NI_IF_PARTIAL" -eq 1 ]; then
      NI_INTERFACES_STATUS="PARTIAL"
      NI_INTERFACES_REASON="one or more interface attributes were not assessed; see per-interface reasons"
    else
      NI_INTERFACES_STATUS="COMPLETE"
      NI_INTERFACES_REASON=""
    fi
  fi

  if [ -n "$NI_INTERFACES_REASON" ]; then
    NI_ITEM_REASON_ESC=$(printf '%s' "$NI_INTERFACES_REASON" |
      network_inventory_json_escape)
    NI_INTERFACES_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
  else
    NI_INTERFACES_REASON_JSON=null
  fi

  NI_NETSTAT=$(aix network_netstat_rn netstat -rn)
  NI_NETSTAT_RC=$?
  NI_ROUTE_SOURCE="{ \"capture\": \"network_netstat_rn\", \"command\": \"netstat -rn\", \"rc\": $NI_NETSTAT_RC }"
  NI_ROUTE_WHY=""
  NI_ROUTE_ITEMS=""
  if [ "$NI_NETSTAT_RC" -ne 0 ]; then
    NI_ROUTE_WHY="netstat -rn capture failed (rc=$NI_NETSTAT_RC)"
  elif [ -z "$NI_NETSTAT" ]; then
    NI_ROUTE_WHY="netstat -rn capture empty (rc=0)"
  elif ! printf '%s\n' "$NI_NETSTAT" | network_inventory_netstat_shape; then
    NI_ROUTE_WHY="netstat -rn capture unparseable (rc=0)"
  fi

  if [ -n "$NI_ROUTE_WHY" ]; then
    NI_ROUTE_STATUS="NOT_ASSESSED"
    NI_ROUTE_REASON=$NI_ROUTE_WHY
    NI_GAPS=$(network_inventory_append_gap "$NI_GAPS" "$NI_ROUTE_WHY")
  else
    NI_ROUTE_ROWS=$(printf '%s\n' "$NI_NETSTAT" |
      network_inventory_parse_netstat)
    NI_ROUTE_ITEMS=$(printf '%s\n' "$NI_ROUTE_ROWS" | awk -F '\t' '
      NF {
        if (seen++) printf ", "
        if ($3=="") iface="null"; else iface="\"" $3 "\""
        if ($5=="") reason="null"; else reason="\"" $5 "\""
        printf "{ \"family\": \"%s\", \"gateway\": \"%s\", \"interface\": %s, \"status\": \"%s\", \"reason\": %s }", $1, $2, iface, $4, reason
      }')
    if printf '%s\n' "$NI_ROUTE_ROWS" |
        awk -F '\t' '$4=="PARTIAL" { found=1 } END { exit !found }'; then
      NI_ROUTE_STATUS="PARTIAL"
      NI_ROUTE_REASON="one or more default routes did not expose an interface"
      NI_GAPS=$(network_inventory_append_gap "$NI_GAPS" \
        "netstat -rn default route did not expose an interface")
    else
      NI_ROUTE_STATUS="COMPLETE"
      NI_ROUTE_REASON=""
    fi
  fi
  if [ -n "$NI_ROUTE_REASON" ]; then
    NI_ITEM_REASON_ESC=$(printf '%s' "$NI_ROUTE_REASON" |
      network_inventory_json_escape)
    NI_ROUTE_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
  else
    NI_ROUTE_REASON_JSON=null
  fi

  NI_DNS_RAW=$(aix network_resolv_conf cat /etc/resolv.conf)
  NI_DNS_RC=$?
  NI_DNS_SOURCE="{ \"capture\": \"network_resolv_conf\", \"command\": \"cat /etc/resolv.conf\", \"rc\": $NI_DNS_RC }"
  NI_DNS_WHY=""
  NI_DNS_ITEMS=""
  if [ "$NI_DNS_RC" -ne 0 ]; then
    NI_DNS_WHY="cat /etc/resolv.conf capture failed (rc=$NI_DNS_RC)"
  elif [ -z "$NI_DNS_RAW" ]; then
    NI_DNS_WHY="cat /etc/resolv.conf capture empty (rc=0)"
  elif ! printf '%s\n' "$NI_DNS_RAW" | network_inventory_resolv_shape; then
    NI_DNS_WHY="cat /etc/resolv.conf capture unparseable (rc=0)"
  fi

  if [ -n "$NI_DNS_WHY" ]; then
    NI_DNS_STATUS="NOT_ASSESSED"
    NI_GAPS=$(network_inventory_append_gap "$NI_GAPS" "$NI_DNS_WHY")
  else
    NI_DNS_STATUS="COMPLETE"
    NI_DNS_ITEMS=$(printf '%s\n' "$NI_DNS_RAW" |
      network_inventory_parse_resolv |
      awk '{ if (seen++) printf ", "; printf "\"%s\"", $0 }')
  fi
  if [ -n "$NI_DNS_WHY" ]; then
    NI_ITEM_REASON_ESC=$(printf '%s' "$NI_DNS_WHY" |
      network_inventory_json_escape)
    NI_DNS_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
  else
    NI_DNS_REASON_JSON=null
  fi

  NI_OBSERVED=0
  NI_COMPLETE=0
  for NI_ITEM_STATUS in \
    "$NI_INTERFACES_STATUS" "$NI_ROUTE_STATUS" "$NI_DNS_STATUS"
  do
    [ "$NI_ITEM_STATUS" != "NOT_ASSESSED" ] && NI_OBSERVED=$((NI_OBSERVED + 1))
    [ "$NI_ITEM_STATUS" = "COMPLETE" ] && NI_COMPLETE=$((NI_COMPLETE + 1))
  done
  if [ "$NI_OBSERVED" -eq 0 ]; then
    NI_TOP_STATUS="NOT_ASSESSED"
    NI_TOP_REASON="no network fact source produced trustworthy output; see capture_gaps"
  elif [ "$NI_COMPLETE" -eq 3 ]; then
    NI_TOP_STATUS="COMPLETE"
    NI_TOP_REASON=""
  else
    NI_TOP_STATUS="PARTIAL"
    NI_TOP_REASON="one or more network fact sources or fields were not assessed; see sub-block reasons and capture_gaps"
  fi
  if [ -n "$NI_TOP_REASON" ]; then
    NI_ITEM_REASON_ESC=$(printf '%s' "$NI_TOP_REASON" |
      network_inventory_json_escape)
    NI_TOP_REASON_JSON="\"$NI_ITEM_REASON_ESC\""
  else
    NI_TOP_REASON_JSON=null
  fi

  printf '"network": { "status": "%s", "platform": "AIX", ' "$NI_TOP_STATUS"
  printf '"reason": %s, "capture_gaps": [%s], ' "$NI_TOP_REASON_JSON" "$NI_GAPS"
  if [ "$NI_INTERFACES_STATUS" = "NOT_ASSESSED" ]; then
    printf '"interfaces": { "status": "%s", "reason": %s, "source": %s, "interfaces": null }, ' \
      "$NI_INTERFACES_STATUS" "$NI_INTERFACES_REASON_JSON" "$NI_IF_SOURCE"
  else
    printf '"interfaces": { "status": "%s", "reason": %s, "source": %s, "interfaces": [%s] }, ' \
      "$NI_INTERFACES_STATUS" "$NI_INTERFACES_REASON_JSON" "$NI_IF_SOURCE" "$NI_IF_ITEMS"
  fi
  if [ "$NI_ROUTE_STATUS" = "NOT_ASSESSED" ]; then
    printf '"routing": { "status": "%s", "reason": %s, "source": %s, "default_gateways": null }, ' \
      "$NI_ROUTE_STATUS" "$NI_ROUTE_REASON_JSON" "$NI_ROUTE_SOURCE"
  else
    printf '"routing": { "status": "%s", "reason": %s, "source": %s, "default_gateways": [%s] }, ' \
      "$NI_ROUTE_STATUS" "$NI_ROUTE_REASON_JSON" "$NI_ROUTE_SOURCE" "$NI_ROUTE_ITEMS"
  fi
  if [ "$NI_DNS_STATUS" = "NOT_ASSESSED" ]; then
    printf '"dns": { "status": "%s", "reason": %s, "source": %s, "resolvers": null } }' \
      "$NI_DNS_STATUS" "$NI_DNS_REASON_JSON" "$NI_DNS_SOURCE"
  else
    printf '"dns": { "status": "%s", "reason": %s, "source": %s, "resolvers": [%s] } }' \
      "$NI_DNS_STATUS" "$NI_DNS_REASON_JSON" "$NI_DNS_SOURCE" "$NI_DNS_ITEMS"
  fi
}

# Network discovery is useful evidence, but without an approved expected-state
# baseline it is not itself a configuration assessment.
function check_network_inventory {
  typeset NI_CHECK_OUT NI_CHECK_RC NI_CHECK_COUNT NI_CHECK_NOUN NI_CHECK_VERB
  typeset NI_CHECK_OBS NI_CHECK_MEAN NI_CHECK_FIX

  NI_CHECK_OUT=$(aix network_ifconfig_a ifconfig -a); NI_CHECK_RC=$?
  if [ "$NI_CHECK_RC" -ne 0 ]; then
    NI_CHECK_OBS="not assessed — ifconfig -a interface inventory failed (rc=$NI_CHECK_RC)"
    NI_CHECK_MEAN="The interface inventory source was unavailable, so expected interfaces, addresses, routes, and resolvers could not be assessed."
    NI_CHECK_FIX="restore access to 'ifconfig -a', provide the site-approved network baseline, and rerun PTxray."
  elif [ -z "$NI_CHECK_OUT" ]; then
    NI_CHECK_OBS="not assessed — ifconfig -a reported no interface inventory (rc=0)"
    NI_CHECK_MEAN="An empty interface capture cannot establish the system's network configuration or compare it with expected state."
    NI_CHECK_FIX="verify the complete output of 'ifconfig -a', provide the site-approved network baseline, and rerun PTxray."
  elif ! printf '%s\n' "$NI_CHECK_OUT" |
      network_inventory_ifconfig_shape; then
    NI_CHECK_OBS="not assessed — ifconfig -a interface inventory was unparseable (rc=0)"
    NI_CHECK_MEAN="The interface capture did not match the expected AIX ifconfig structure, so network configuration could not be assessed."
    NI_CHECK_FIX="capture the complete output of 'ifconfig -a', correct the replay source if needed, provide the site-approved network baseline, and rerun PTxray."
  else
    NI_CHECK_COUNT=$(printf '%s\n' "$NI_CHECK_OUT" |
      network_inventory_parse_ifconfig |
      awk -F '	' '$1=="I" {n++} END{print n+0}')
    NI_CHECK_NOUN=interfaces
    NI_CHECK_VERB=were
    if [ "$NI_CHECK_COUNT" -eq 1 ]; then
      NI_CHECK_NOUN=interface
      NI_CHECK_VERB=was
    fi
    NI_CHECK_OBS="not assessed — $NI_CHECK_COUNT $NI_CHECK_NOUN $NI_CHECK_VERB inventoried from ifconfig -a, but no site-approved expected interface, address, route, and DNS baseline was available"
    NI_CHECK_MEAN="Observed network inventory alone cannot distinguish an intended configuration from a missing, unexpected, or misaddressed interface, route, or resolver."
    NI_CHECK_FIX="provide a site-approved expected interface, address, route, and DNS baseline, compare it with this inventory, and rerun PTxray."
  fi

  add config network_inventory "Network inventory baseline" \
    NOT_ASSESSED med "$NI_CHECK_OBS" "$NI_CHECK_MEAN" "$NI_CHECK_FIX"
}

function standalone_run {
  check_network_inventory
}

standalone_main "$@"
exit $?
