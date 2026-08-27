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

AIXRAY_STANDALONE_VERSION="1.6.0"

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
CURRENCY_SOURCE_COUNT=8
set -A CR_ID 'ibm-aix-lifecycle' 'ibm-security-advisories' 'cisa-kev' 'ibm-apar-csv' 'ibm-flrtvc' 'ibm-flrt-firmware' 'cis-ibm-aix' 'disa-stig-ibm-aix-7'
set -A CR_LABEL 'IBM AIX lifecycle reference data' 'IBM security advisory seed' 'CISA Known Exploited Vulnerabilities catalog' 'IBM FLRT apar.csv' 'IBM FLRTVC engine' 'IBM FLRT firmware lifecycle response' 'CIS IBM AIX benchmark' 'DISA STIG for IBM AIX 7.x'
set -A CR_CLASS 'advisory' 'advisory' 'cve' 'apar' 'flrt' 'flrt' 'benchmark' 'benchmark'
set -A CR_REQUIRED '1' '1' '1' '1' '1' '1' '1' '1'
set -A CR_LOADED '1' '1' '0' '0' '0' '0' '1' '1'
set -A CR_VERSION 'sha256:60fd717d0f4cd79875654d7be134baf47453b36f4ace74f529394570dd4bd770' 'sha256:ab3c95ca7fdc47ad68978930afcfd70d42eed0ea9580926ab44a0a775b30caed' 'unknown' 'unknown' 'unknown' 'unknown' 'v1.2.0' 'V3R3'
set -A CR_VERSION_BASIS 'content-sha256' 'content-sha256' 'unknown' 'unknown' 'unknown' 'unknown' 'publisher-version' 'publisher-version'
set -A CR_AS_OF '2026-08-15' '2026-08-18' 'unknown' 'unknown' 'unknown' 'unknown' '2026-08-18' '2026-06-15'
set -A CR_AS_OF_BASIS 'curator-verified' 'curator-review' 'unknown' 'unknown' 'unknown' 'unknown' 'curator-verified' 'publisher-benchmark-date'
set -A CR_SHA256 'sha256:60fd717d0f4cd79875654d7be134baf47453b36f4ace74f529394570dd4bd770' 'sha256:ab3c95ca7fdc47ad68978930afcfd70d42eed0ea9580926ab44a0a775b30caed' 'unknown' 'unknown' 'unknown' 'unknown' 'sha256:3645a841eb8f05078a8c0a043f62ed200bd7483a578c615ea652c7f15f68bd3b' 'sha256:e4109ceb3a15beddbf1e84e29e593cd18cc260e9be1789429554b9d66e2cfeb9'
set -A CR_LOCATOR 'https://www.ibm.com/support/pages/aix-standard-edition720 (no announced AIX 7.2 EOS shown; supported state is a curator inference from that absence); https://www.ibm.com/support/pages/aix-support-lifecycle-information (AIX 7.2 TL5 EoFS: To be determined)' 'embedded SEC_APARS table' 'operator-supplied local CISA KEV JSON' 'operator-supplied local apar.csv or provenanced FLRTVC report' 'operator-supplied pinned flrtvc.ksh or provenanced report' 'operator-supplied local IBM FLRT fetch envelope' 'embedded numeric-only CIS L1 crosswalk' 'embedded R_FILEPERM/R_SECATTR/R_NETTUNE/R_SVCOFF tables'
set -A CR_THRESHOLD '30' '30' '30' '30' '30' '30' '180' '180'
set -A CR_INTEGRITY 'verified' 'verified' 'unknown' 'unknown' 'unknown' 'unknown' 'verified' 'verified'
set -A CR_PROVENANCE 'verified' 'verified' 'unknown' 'unknown' 'unknown' 'unknown' 'verified' 'verified'

AIXRAY_TOOL=ck-hd5-sizing

# Shared online-volume-group capture retained outside check logic for standalone composition.
function capture_cap_lsvg_o {
  VGL=$(aix lsvg_o lsvg -o); VGLRC=$?
  VGL_OK=0; VGLWHY=""
  if [ "$VGLRC" -ne 0 ]; then
    VGLWHY="not assessed — lsvg -o capture failed (rc=$VGLRC)"
  elif [ -z "$VGL" ]; then
    VGLWHY="not assessed — lsvg -o capture empty (rc=0)"
  elif printf '%s\n' "$VGL" | awk '
      NF {
        n++
        if (NF != 1 || $1 !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/) bad=1
      }
      END { if (n == 0 || bad) exit 1 }
    '
  then
    VGL_OK=1
    FACT_STORAGE_VG_READ=1
  else
    VGLWHY="not assessed — lsvg -o capture unparseable (rc=0)"
  fi
  if [ "$VGL_OK" -eq 1 ]; then
    NVG=$(printf '%s\n' "$VGL" | awk 'NF{n++} END{print n+0}')
  else
    VGL=""; NVG=0
  fi
}


function standalone_check {
_AIXRAY_SESSION_KEYS=""

  # volume groups: stale copies + missing disks. Each verdict has its own
  # completeness state: an empty accumulator is clean evidence only after every
  # required command completed and every capture matched its stable AIX shape.
  STALE=""; MISSPV=""; VG_STALE_GAP=""; VG_PVS_GAP=""
  ROOTVG_LVL=""; ROOTVG_LVL_RC=1; ROOTVG_LVL_OK=0
  if [ "${VGL_OK:-0}" -ne 1 ]; then
    VG_STALE_GAP="${VGLWHY:-not assessed — lsvg -o capture unavailable}"
    VG_PVS_GAP="$VG_STALE_GAP"
  fi

  VG_PVLIST=$(aix lspv lspv); VG_PVLIST_RC=$?
  VG_PVLIST_OK=0; VG_PVLIST_WHY=""
  if [ "$VG_PVLIST_RC" -ne 0 ]; then
    VG_PVLIST_WHY="lspv capture failed (rc=$VG_PVLIST_RC)"
  elif [ -z "$VG_PVLIST" ]; then
    VG_PVLIST_WHY="lspv capture empty (rc=0)"
  elif printf '%s\n' "$VG_PVLIST" | awk '
      NF {
        n++
        if (NF < 3 || NF > 4 || $1 !~ /^hdisk[0-9][0-9]*$/ ||
            $2 !~ /^(none|[0-9A-Fa-f]{16,})$/ ||
            $3 !~ /^[A-Za-z0-9_.-]+$/ ||
            (NF == 4 && $4 !~ /^[A-Za-z0-9_.-]+$/)) bad=1
      }
      END { if (n == 0 || bad) exit 1 }
    '
  then
    VG_PVLIST_OK=1
  else
    VG_PVLIST_WHY="lspv capture unparseable (rc=0)"
  fi
  if [ "$VG_PVLIST_OK" -ne 1 ]; then
    VG_PVS_GAP="${VG_PVS_GAP}${VG_PVS_GAP:+; }$VG_PVLIST_WHY"
  fi

  if [ "${VGL_OK:-0}" -eq 1 ]; then
  for VG in $VGL; do
    LVOUT=$(aix "lsvg_l_$VG" lsvg -l "$VG"); LVRC=$?
    [ "$VG" = "rootvg" ] && { ROOTVG_LVL="$LVOUT"; ROOTVG_LVL_RC=$LVRC; }
    if [ "$LVRC" -ne 0 ]; then
      VG_STALE_GAP="${VG_STALE_GAP}${VG_STALE_GAP:+; }$VG lsvg -l capture failed (rc=$LVRC)"
    elif [ -z "$LVOUT" ]; then
      VG_STALE_GAP="${VG_STALE_GAP}${VG_STALE_GAP:+; }$VG lsvg -l capture empty (rc=0)"
    elif printf '%s\n' "$LVOUT" | awk -v vg="$VG" '
        NR == 1 { if ($1 != vg ":") bad=1; next }
        NR == 2 {
          if ($1 != "LV" || $2 != "NAME" || $3 != "TYPE" ||
              $4 != "LPs" || $5 != "PPs" || $6 != "PVs") bad=1
          next
        }
        NF {
          n++
          if (NF < 7 || $1 !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/ ||
              $2 !~ /^[A-Za-z0-9_.-][A-Za-z0-9_.-]*$/ ||
              $3 !~ /^[1-9][0-9]*$/ || $4 !~ /^[1-9][0-9]*$/ ||
              $5 !~ /^[1-9][0-9]*$/ ||
              $6 !~ /^(open|closed)\/(syncd|stale)$/) bad=1
        }
        END { if (n == 0 || bad) exit 1 }
      '
    then
      [ "$VG" = "rootvg" ] && ROOTVG_LVL_OK=1
      S=$(printf '%s\n' "$LVOUT" | awk '$6 ~ /\/stale$/ {printf "%s%s",(n++?",":""),$1}')
      [ -n "$S" ] && STALE="$STALE $VG($S)"
    else
      VG_STALE_GAP="${VG_STALE_GAP}${VG_STALE_GAP:+; }$VG lsvg -l capture unparseable (rc=0)"
    fi

    PVOUT=$(aix "lsvg_p_$VG" lsvg -p "$VG"); PVRC=$?
    if [ "$PVRC" -ne 0 ]; then
      VG_PVS_GAP="${VG_PVS_GAP}${VG_PVS_GAP:+; }$VG lsvg -p capture failed (rc=$PVRC)"
    elif [ -z "$PVOUT" ]; then
      VG_PVS_GAP="${VG_PVS_GAP}${VG_PVS_GAP:+; }$VG lsvg -p capture empty (rc=0)"
    elif printf '%s\n' "$PVOUT" | awk -v vg="$VG" '
        NR == 1 { if ($1 != vg ":") bad=1; next }
        NR == 2 {
          if ($1 != "PV_NAME" || $2 != "PV" || $3 != "STATE" ||
              $4 != "TOTAL" || $5 != "PPs") bad=1
          next
        }
        NF {
          n++
          if (NF < 5 || $1 !~ /^hdisk[0-9][0-9]*$/ ||
              $2 !~ /^(active|missing|removed)$/ ||
              $3 !~ /^[0-9][0-9]*$/ || $4 !~ /^[0-9][0-9]*$/) bad=1
        }
        END { if (n == 0 || bad) exit 1 }
      '
    then
      MP=$(printf '%s\n' "$PVOUT" | awk '$2=="missing" || $2=="removed" {printf "%s%s",(n++?",":""),$1}')
      [ -n "$MP" ] && MISSPV="$MISSPV $VG($MP)"
    else
      VG_PVS_GAP="${VG_PVS_GAP}${VG_PVS_GAP:+; }$VG lsvg -p capture unparseable (rc=0)"
    fi
  done
  fi
  if [ -n "$VG_STALE_GAP" ]; then
    add storage vg_stale "LV mirror sync" NOT_ASSESSED high "not assessed — $VG_STALE_GAP" \
        "LV mirror synchronization could not be assessed because one or more lsvg captures failed, were empty, or were unparseable." \
        "run 'lsvg -o' and 'lsvg -l <vg>' manually for every online VG, then rerun PTxray."
  elif [ -n "$STALE" ]; then
    add storage vg_stale "LV mirror sync" FAIL high "stale:$STALE" \
        "Mirror copies are out of sync — you believe you are protected and you are not." \
        "check the underlying disk first (errpt, lsvg -p), then resync with 'syncvg -v <vg>'."
  else
    add storage vg_stale "LV mirror sync" PASS low "no stale partitions" "All logical volume copies are in sync." "n/a"
  fi
  if [ -n "$VG_PVS_GAP" ]; then
    add storage vg_pvs "Volume group disks" NOT_ASSESSED high "not assessed — $VG_PVS_GAP" \
        "Volume-group disk state could not be assessed because lsvg or lspv evidence failed, was empty, unparseable, or internally incomplete." \
        "run 'lsvg -o', 'lsvg -p <vg>', and 'lspv' manually, then rerun PTxray."
  elif [ -n "$MISSPV" ]; then
    add storage vg_pvs "Volume group disks" FAIL high "missing:$MISSPV" \
        "A disk the volume group expects is gone — data redundancy or capacity is already degraded." \
        "identify the disk (lsvg -p, errpt), engage storage/hardware support before the next failure."
  else
    add storage vg_pvs "Volume group disks" PASS low "all PVs active" "Every volume group disk is present and active." "n/a"
  fi

  # hd5_sizing — boot-image LV sizing (v2 assessment contract Section 5 cap-filesets row): target
  # 64 MB (current IBM guidance), older 32 MB guidance cited alongside so a 32 MB hd5 on an older
  # box is not treated as automatically fine. hd5's own LP count comes from the SAME 'lsvg -l
  # rootvg' capture the vg_stale/vg_pvs checks above already made (ROOTVG_LVL, no duplicate
  # command); PP size comes from 'lsvg rootvg'. Live-verified on both real lab boxes, 2026-07-13:
  # a lab LPAR (AIX 7.2) hd5 = 2 LPs x 32 MB PP = 64 MB (current target, PASS); a lab LPAR (AIX 7.1) hd5 =
  # 1 LP x 32 MB PP = 32 MB (the older-guidance size exactly — a genuine, real WARN case, not a
  # hypothetical).
  RVGOUT=$(aix lsvg_rootvg lsvg rootvg); RVGOUT_RC=$?
  # NOTE: 'lsvg <vg>'s "PP SIZE:" shares its output line with "VG STATE:" (two
  # colon-separated key:value pairs on one row) -- a naive '-F: {print $2}' split
  # grabs the WRONG middle field ("...active...PP SIZE", no digits at all), a
  # real bug caught live against a lab LPAR during this check's own build (round 1
  # self-review: HD5LPS parsed correctly but PPSZ silently came back empty,
  # correctly degrading to WARN "unreadable" rather than a wrong number — but
  # still wrong, fixed here with a targeted sed extraction instead of a
  # positional colon-field assumption).
  PPSZ=$(printf '%s\n' "$RVGOUT" | sed -n 's/.*PP SIZE: *\([0-9][0-9]*\).*/\1/p' | head -1)
  HD5LPS=$(printf '%s\n' "$ROOTVG_LVL" | awk '$1=="hd5"{print $3; exit}')
  # hd5's own PV count from the SAME already-validated 'lsvg -l rootvg' row (field 5,
  # PVs) -- the independent completeness cross-check for the 'lslv -m hd5' mirror map
  # below (adversarial review round 4, 2026-07-14, HIGH: HD5PVS was derived SOLELY
  # from whichever 'lslv -m' columns survived capture, with no completeness check at
  # all -- a capture truncated to lose the PP2/PV2 columns hid a mirror copy entirely,
  # and if the still-visible copy happened to be contiguous this reached a false PASS
  # built on a mirror map that was never actually complete).
  HD5PVCNT=$(printf '%s\n' "$ROOTVG_LVL" | awk '$1=="hd5"{print $5; exit}')
  # Both source commands must have actually SUCCEEDED, not just produced a value that
  # happens to parse -- a failed 'lsvg rootvg' or 'lsvg -l rootvg' invocation that
  # nonetheless leaves plausible-looking stale/partial text behind must never be trusted
  # into a confident PASS/WARN/FAIL size verdict (adversarial review, M5, round 2,
  # finding #4: this check recorded ROOTVG_LVL_RC via the shared vg_stale/vg_pvs capture
  # above but never actually checked it here; 'lsvg rootvg's own rc was not recorded at
  # all). Same failed-source-to-verdict laundering class already fixed for the UAK checks
  # and multibos_residue in this same milestone.
  # A zero LP count or zero PP size is structurally invalid capture data (adversarial
  # review, 2026-07-14, LOW: the digits-only check below happily accepted "0", computing
  # HD5MB=0 and reaching a confident FAIL "0MB" -- a corrupt/garbled capture reporting
  # zero is not trustworthy evidence hd5 is actually zero-sized) -- treated the same as
  # non-numeric: never trusted into a size verdict.
  if [ "$ROOTVG_LVL_RC" -eq 0 ] && [ "$ROOTVG_LVL_OK" -eq 1 ] &&
     [ "$RVGOUT_RC" -eq 0 ] && [ -n "$PPSZ" ] && [ -n "$HD5LPS" ]; then
    case "$PPSZ$HD5LPS" in
      *[!0-9]*) HD5MB="";;
      *) [ "$PPSZ" -gt 0 ] && [ "$HD5LPS" -gt 0 ] && HD5MB=$(( PPSZ * HD5LPS )) || HD5MB="";;
    esac
  else
    HD5MB=""
  fi
  # Contiguity — size alone is NOT "upgrade-ready": both the v2 assessment contract (Section 5
  # cap-filesets row) and the sourced rule (upgrade-readiness-checks.md Sec 4) require hd5's
  # PPs to be CONTIGUOUS; noncontiguity is explicitly "not ready" regardless of total size
  # (adversarial review, M5, HIGH finding #1: the size math above was being trusted into a
  # PASS with no contiguity check at all). 'lslv -m hd5' identifies which disk(s) hd5's
  # copies land on; 'lspv -M <hdiskN>' then independently confirms those PPs form a
  # contiguous run on that disk. Never a PASS on inconclusive or noncontiguous evidence: no
  # readable PV/contiguity signal degrades to WARN "not assessed," never PASS.
  #
  # Multi-copy guard (adversarial review, 2026-07-14, HIGH finding #2): a MIRRORED hd5
  # has a full copy of every LP on EACH of its PVs (real 'lslv -m hd5' rows carry PP1/PV1,
  # PP2/PV2, PP3/PV3 column pairs, one pair per mirror copy) -- checking only copy 1's PV
  # (the prior version's HD5PV, singular) let a genuinely noncontiguous SECOND copy still
  # report an unscoped "contiguous" PASS, since copy 1 alone can look fine. Every PV any
  # row names for hd5 is enumerated (deduplicated, first-seen order) and independently
  # contiguity-checked below; the combined verdict is never better than the worst
  # individually-confirmed copy.
  LSLVM=$(aix lslv_m_hd5 lslv -m hd5); LSLVM_RC=$?
  HD5PVS=""
  if [ "$LSLVM_RC" -eq 0 ] && [ -n "$LSLVM" ]; then
    # skip the 'hd5:<mountpt>' header (line 1) and the 'LP PP1 PV1 ...' column-header row
    # (line 2); a real data row's own PP1 (field 2) must be numeric. Every odd field from 3
    # onward (PV1, PV2, PV3 -- whichever mirror-copy columns this row actually carries) is a
    # candidate PV; deduplicated across every row via the second awk's !seen[] idiom.
    HD5PVS=$(printf '%s\n' "$LSLVM" | awk 'NR>2 && NF>=3 && $2 ~ /^[0-9]+$/ {
        for (i=3; i<=NF; i+=2) if ($i != "" && $i != "-") print $i
      }' | awk '!seen[$0]++')
  fi
  # The mirror-map token is about to become both a fixture/command key and customer-
  # visible PASS evidence, so validate it before either use. AIX PV device names for this
  # supported path are hdisk plus a nonempty decimal index. The independently captured
  # `lspv` device list is required, must be usable, and must contain every shaped name;
  # two colluding files cannot invent NOT_A_PV!/hdisk9 and make it trusted by spelling it
  # consistently in `lslv -m` and `lspv -M`.
  HD5PVBAD=""; HD5PVLIST=""; HD5PVLIST_RC=127
  if [ -n "$HD5PVS" ]; then
    HD5PVLIST="$VG_PVLIST"; HD5PVLIST_RC=$VG_PVLIST_RC
    # Feed the extracted values as literal lines. An unquoted `for ... in $HD5PVS`
    # lets the launch directory pathname-expand an attacker-controlled token such as
    # hdisk* into a trusted hdisk0 before the validation below ever sees it.
    while IFS= read -r HPVC; do
      [ -n "$HPVC" ] || continue
      HPVWHY=""; HDISKNUM=${HPVC#hdisk}
      case "$HPVC" in
        hdisk[0-9]*) case "$HDISKNUM" in ''|*[!0-9]*) HPVWHY="not a valid hdisk device name";; esac ;;
        *) HPVWHY="not a valid hdisk device name" ;;
      esac
      if [ -z "$HPVWHY" ]; then
        if [ "${VG_PVLIST_OK:-0}" -ne 1 ]; then
          HPVWHY="could not be checked because the captured lspv device list failed, was empty, or was unparseable"
        else
          printf '%s\n' "$HD5PVLIST" | awk -v want="$HPVC" '$1==want{found=1} END{exit !found}' || \
            HPVWHY="not present in the captured lspv device list"
        fi
      fi
      [ -n "$HPVWHY" ] && HD5PVBAD="${HD5PVBAD}${HD5PVBAD:+, }$HPVC ($HPVWHY)"
    done <<EOF
$HD5PVS
EOF
  fi
  HD5MAPBAD=""; HD5PVQUERY="$HD5PVS"
  if [ -n "$HD5PVBAD" ]; then
    HD5MAPBAD="'lslv -m hd5' contains an invalid or independently unrecognized PV token: $HD5PVBAD"
    HD5PVQUERY=""
  fi
  HD5CONTIG=""
  HD5FOUNDCNT=""
  HD5OKPV=""; HD5BADPV=""; HD5INCPV=""; HD5NOSIGPV=""; HD5INCDETAIL=""
  # Mirror-map completeness cross-check (adversarial review round 4, 2026-07-14,
  # HIGH): the PV set parsed out of 'lslv -m hd5' must agree with the PV count
  # 'lsvg -l rootvg' independently states for hd5 (HD5PVCNT, field 5 of the same
  # already-rc-validated capture the LP count comes from). Fewer PVs seen = the map
  # was truncated and a whole mirror copy may be invisible; more = garbled. Either
  # way the map cannot be trusted into a PASS -- it is routed to the same detected-
  # assessment-gap NOT_ASSESSED outcome as a truncated 'lspv -M' capture (an
  # explicitly noncontiguous VISIBLE copy still wins, below: a real noncontiguity
  # signal is actionable regardless of what else the map failed to show).
  if [ -n "$HD5PVS" ]; then
    # Count the parsed records without subjecting untrusted values to a second shell
    # word-splitting/pathname-expansion pass. Only validated hdiskN values flow into
    # HD5PVQUERY and its per-PV command loop below.
    HD5PVSEEN=$(printf '%s\n' "$HD5PVS" | awk 'NF {n++} END {print n+0}')
    case "$HD5PVCNT" in
      ''|*[!0-9]*)
        HD5MAPBAD="hd5's own PV count could not be read from 'lsvg -l rootvg' (got '$HD5PVCNT'), so the 'lslv -m hd5' mirror map cannot be confirmed complete" ;;
      *)
        if [ "$HD5PVSEEN" -ne "$HD5PVCNT" ]; then
          HD5MAPBAD="'lslv -m hd5' shows $HD5PVSEEN PV(s) but 'lsvg -l rootvg' says hd5 spans $HD5PVCNT -- the mirror map looks truncated or garbled and may hide an entire copy"
        fi ;;
    esac
  fi
  if [ -n "$HD5PVS" ]; then
    for HPV in $HD5PVQUERY; do
      LSPVM=$(aix "lspv_M_$HPV" lspv -M "$HPV"); LSPVM_RC=$?
      if [ "$LSPVM_RC" -eq 0 ] && [ -n "$LSPVM" ]; then
        # Live-verified against real 'lspv -M' output on two lab LPARs, 2026-07-13: it
        # emits ONE PP per line (never a merged 'N-M' range) -- an earlier version of this
        # check wrongly assumed 'lspv -M' merges each LV's own consecutive PPs into a single
        # line and counted LINES naming hd5 as the contiguity signal; on real output that
        # miscounted a genuinely contiguous 2-PP hd5 (one line per PP) as "2 blocks" ==
        # noncontiguous -- a false FAIL-shaped WARN caught only by running against the real
        # lab boxes before shipping (exactly the failure mode 'prove before deploy' exists to
        # catch). Fixed here to build the actual SET of PP numbers hd5 owns on this disk
        # (expanding any 'N-M' range token defensively, in case a future AIX/lspv variant does
        # merge) and check that set has no gaps between its min and max -- the literal
        # "consecutive PPs" test the spec/sourced rule describe. Exact field-token match on
        # 'hd5' (never a substring match that would also catch a real 'hd50'-named LV); any
        # unparsable PP token on a matching line is treated as inconclusive, never guessed at.
        #
        # Capture-completeness guard (false-clean, cardinal-sin class, 2026-07-14): the above
        # rebuild-the-set logic only ever sees whatever lines actually made it into $LSPVM --
        # if the 'lspv -M' capture itself is TRUNCATED mid-stream (cut off after some but not
        # all of hd5's own PP lines, rc=0 nonetheless -- the exact failure mode this codebase's
        # own fixture-replay convention and a flaky/interrupted real capture can both produce),
        # the partial SET this builds can look trivially "contiguous" (a subset of a
        # noncontiguous layout, or simply too few PPs to show the real gap) and this used to
        # report "yes" -- a false PASS built on data that was never actually complete. We
        # already independently know hd5's true PP-per-copy count on this PV from the
        # already-validated 'lsvg -l rootvg' capture (HD5LPS, same source vg_stale/vg_pvs
        # above rely on) -- cross-check the count of DISTINCT PPs this capture actually shows
        # for hd5 against HD5LPS; anything other than an exact match means the capture cannot
        # be trusted to have shown the whole picture (fewer PPs = truncated before showing them
        # all; more PPs = a garbled/duplicated capture, equally untrustworthy) and is reported
        # as its own "incomplete" outcome, never silently folded into "yes" or "no". Also
        # requires the field immediately AFTER 'hd5' (its own per-copy LP-index marker,
        # 'hd5:N') to be present and numeric, and tracks the SET of those LP-index markers
        # separately from the physical PP set (adversarial review, 2026-07-14, HIGH finding
        # #1: a row truncated right after the bare 'hd5' token, with no trailing LP-index
        # field at all, was silently accepted as a valid match; and two DIFFERENT physical PPs
        # both mislabeled as hd5's SAME LP index, with hd5's other LP index never appearing at
        # all, still produced the expected PHYSICAL-PP count and a spuriously "contiguous"
        # PASS -- reproduced live against a synthetic capture. Requiring the LP-index set's own
        # size to also equal the expected count closes both).
        # Row grammar is validated per line, never token-scanned (adversarial review
        # round 4, 2026-07-14, HIGH: the previous version searched for an 'hd5' token at
        # ANY field position with numeric neighbors, so a garbled line like
        # 'garbage 1 hd5 1' -- valid-shaped tokens in coincidentally-right positions on a
        # line that matches no lspv -M row grammar at all -- was counted as a real PP and
        # could satisfy the completeness guard into a PASS). IBM documents 'lspv -M'
        # rows as 'PVname:PPnum[-PPnum] [LVname:LPnum[:Copynum] [PPstate]]': every
        # nonempty line must therefore start with EXACTLY the PV this capture was taken
        # from ($1 == pv) followed by a numeric PP token ($2); hd5 is only ever accepted
        # at the LVname position ($3), with its numeric LP index at $4. Any nonempty
        # line violating that grammar marks the WHOLE capture untrustworthy ("bad" --
        # the NOT_ASSESSED route), never skipped past.
        RES=$(printf '%s\n' "$LSPVM" | awk -F'[ \t:]+' -v want="$HD5LPS" -v pv="$HPV" '
            NF == 0 { next }
            {
              if ($1 != pv) { badpp=1; exit }
              pp=$2
              if (pp ~ /^[0-9]+-[0-9]+$/) { split(pp,r,"-"); lo=r[1]+0; hi=r[2]+0 }
              else if (pp ~ /^[0-9]+$/) { lo=pp+0; hi=pp+0 }
              else { badpp=1; exit }
              if (pp !~ /^[1-9][0-9]*$/ && pp !~ /^[1-9][0-9]*-[1-9][0-9]*$/) badindex=1
              if (NF >= 3 && $3 == "hd5") {
                lp=$4
                if (lp !~ /^[0-9]+$/) { badpp=1; exit }
                if (lp !~ /^[1-9][0-9]*$/) badindex=1
                for (p=lo; p<=hi; p++) seen[p]=1
                lpseen[lp]=1
                found=1
              }
            }
            END {
              if (badpp) { print "bad:0"; exit }
              if (badindex) { print "bad:0"; exit }
              if (!found) { print "none:0"; exit }
              cnt=0; for (p in seen) cnt++
              lpcnt=0; for (l in lpseen) lpcnt++
              lpbad=0
              if (want ~ /^[1-9][0-9]*$/) for (l=1; l<=want+0; l++) if (!(l in lpseen)) lpbad=1
              if (want !~ /^[1-9][0-9]*$/ || cnt != want+0 || lpcnt != want+0 || lpbad) { print "incomplete:" cnt; exit }
              mn=""; mx=""
              for (p in seen) { if (mn=="" || p<mn) mn=p; if (mx=="" || p>mx) mx=p }
              ok=1
              for (p=mn; p<=mx; p++) if (!(p in seen)) ok=0
              print (ok ? "yes:" cnt : "no:" cnt)
            }')
      else
        RES="none:0"
      fi
      RSTAT="${RES%%:*}"; RCNT="${RES#*:}"
      case "$RSTAT" in
        yes) HD5OKPV="$HD5OKPV$HPV "; HD5FOUNDCNT="$RCNT" ;;
        no) HD5BADPV="$HD5BADPV$HPV " ;;
        incomplete|bad)
          HD5INCPV="$HD5INCPV$HPV "
          HD5INCDETAIL="${HD5INCDETAIL}${HD5INCDETAIL:+, }$HPV ($RCNT/$HD5LPS PPs)"
          ;;
        none) HD5NOSIGPV="$HD5NOSIGPV$HPV " ;;
      esac
    done
    # Precedence across every copy checked: an explicitly detected noncontiguous copy
    # always wins (the strongest, most actionable signal, regardless of what any other
    # copy showed) -- then a detected incomplete/malformed capture on any copy (never a
    # silent PASS built on partial evidence from a DIFFERENT, clean-looking copy) -- only
    # if every copy this tool found a PV for was independently confirmed contiguous AND
    # no copy came back with zero usable signal does this reach an actual PASS; anything
    # else falls through to the existing "contiguity not assessed" WARN.
    # An untrustworthy mirror map (HD5MAPBAD) joins the incomplete route with its own
    # detail -- a PASS must never be built on a map that may be hiding a whole copy.
    # An explicitly noncontiguous VISIBLE copy still wins (real, actionable signal).
    if [ -n "$HD5MAPBAD" ]; then
      HD5INCDETAIL="${HD5INCDETAIL}${HD5INCDETAIL:+; }$HD5MAPBAD"
    fi
    if [ -n "$HD5BADPV" ]; then
      HD5CONTIG="no"
    elif [ -n "$HD5INCPV" ] || [ -n "$HD5MAPBAD" ]; then
      HD5CONTIG="incomplete"
    elif [ -n "$HD5OKPV" ] && [ -z "$HD5NOSIGPV" ]; then
      HD5CONTIG="yes"
    else
      HD5CONTIG=""
    fi
  fi
  if [ -n "$HD5MB" ]; then
    if [ "$HD5MB" -ge 64 ]; then
      case "$HD5CONTIG" in
        yes)
          add storage hd5_sizing "Boot logical volume (hd5) size" PASS low "${HD5MB}MB (${HD5LPS} LP x ${PPSZ}MB), contiguous on $(printf '%s' "$HD5OKPV" | sed 's/ $//;s/ /, /g')" \
              "hd5 meets IBM's current 64MB boot-image sizing guidance and its physical partitions are contiguous on disk (every copy checked: $(printf '%s' "$HD5OKPV" | sed 's/ $//;s/ /, /g'))." "n/a"
          ;;
        no)
          add storage hd5_sizing "Boot logical volume (hd5) size" WARN med "${HD5MB}MB (${HD5LPS} LP x ${PPSZ}MB), NONCONTIGUOUS on $(printf '%s' "$HD5BADPV" | sed 's/ $//;s/ /, /g')" \
              "hd5 meets the 64MB size target, but at least one of its copies is NOT contiguous on disk ('lspv -M' shows hd5's PPs split across separate, non-adjacent runs on $(printf '%s' "$HD5BADPV" | sed 's/ $//;s/ /, /g')). IBM's own upgrade-readiness guidance treats a noncontiguous hd5 as NOT upgrade-ready regardless of its total size — a boot-image rebuild needs EVERY copy in one contiguous run of space." \
              "reorganize hd5 onto contiguous PPs (e.g. 'reorgvg rootvg', or recreate hd5 via a supported boot-LV rebuild procedure) before the next TL/SP update or migration."
          ;;
        incomplete)
          # A truncated/garbled 'lspv -M' capture must never be laundered into a PASS via a
          # coincidentally-contiguous-looking partial PP set (see the guard comment above) --
          # this is a detected assessment gap, not merely "we lack a signal," so it is
          # reported as NOT_ASSESSED rather than folded into the generic WARN "contiguity not
          # assessed" fallback below (never PASS, per the no-false-clean rule).
          add storage hd5_sizing "Boot logical volume (hd5) size" NOT_ASSESSED low "${HD5MB}MB (${HD5LPS} LP x ${PPSZ}MB), TRUNCATED/INCONSISTENT ($HD5INCDETAIL)" \
              "hd5 meets the 64MB size target, but 'lspv -M' returned an incomplete or internally inconsistent picture of hd5's physical partitions on at least one of its copies (expected ${HD5LPS} distinct PPs and ${HD5LPS} distinct LP-index markers per copy, independently confirmed via 'lsvg -l rootvg': $HD5INCDETAIL) — this looks like a truncated, duplicated, or otherwise garbled capture, not a genuine reading, and contiguity (required by IBM's own upgrade-readiness guidance regardless of size) cannot be confirmed from it. This tool will not assert upgrade-ready, or PASS, on incomplete evidence." \
              "re-run 'lslv -m hd5' and 'lspv -M <hdiskN>' manually for every copy and confirm all ${HD5LPS} of hd5's physical partitions are captured and contiguous on each before relying on this as upgrade-ready."
          ;;
        *)
          add storage hd5_sizing "Boot logical volume (hd5) size" WARN low "${HD5MB}MB (${HD5LPS} LP x ${PPSZ}MB), contiguity not assessed" \
              "hd5 meets the 64MB size target, but its physical-partition contiguity could not be independently confirmed ('lslv -m hd5' and/or 'lspv -M <hdiskN>' did not return a usable result). IBM's guidance requires hd5's PPs to be CONTIGUOUS, not just large enough — this tool will not assert upgrade-ready from size alone." \
              "run 'lslv -m hd5' and 'lspv -M <hdiskN>' manually to confirm hd5's PPs are contiguous before relying on this as upgrade-ready."
          ;;
      esac
    elif [ "$HD5MB" -ge 32 ]; then
      add storage hd5_sizing "Boot logical volume (hd5) size" WARN med "${HD5MB}MB (${HD5LPS} LP x ${PPSZ}MB)" \
          "hd5 meets IBM's OLDER 32MB guidance but not the current 64MB target — a boot-image rebuild (bosboot, run automatically by most maintenance paths) can fail to fit on an undersized hd5, most likely discovered mid-update." \
          "grow hd5 to 64MB before the next TL/SP update ('chvg -bu' as needed, then extend hd5 via a supported procedure — plan this in a maintenance window, not during an update)."
    else
      add storage hd5_sizing "Boot logical volume (hd5) size" FAIL high "${HD5MB}MB (${HD5LPS} LP x ${PPSZ}MB)" \
          "hd5 is undersized even against IBM's older 32MB guidance — a boot-image rebuild is at real risk of failing to fit." \
          "grow hd5 before the next TL/SP update; do not wait for an update to force the issue."
    fi
  else
    add storage hd5_sizing "Boot logical volume (hd5) size" WARN low "unreadable" \
        "Could not read hd5's LP count ('lsvg -l rootvg', rc=$ROOTVG_LVL_RC) or rootvg's PP size ('lsvg rootvg', rc=$RVGOUT_RC)." \
        "check 'lsvg -l rootvg' and 'lsvg rootvg' manually."
  fi
}

function standalone_run {
  capture_cap_lsvg_o || return 1
  standalone_check
}

standalone_main "$@"
exit $?
