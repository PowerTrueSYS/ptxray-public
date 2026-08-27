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

AIXRAY_TOOL=ck-shell-timeout-readonly


function standalone_check {
_AIXRAY_SESSION_KEYS=""

  # shell_timeout_readonly — verify TMOUT/TIMEOUT are bounded and readonly.
  # The probe reads /etc/profile (the file the CIS standard's Remediation
  # section names) and keeps every line matching TMOUT or TIMEOUT.  It reads
  # the file, not the scanner's own shell: the scanner runs as a
  # non-interactive, non-login ksh that never sources /etc/profile, so the
  # readonly attribute configured there is simply absent from the scanner's
  # shell.  On a compliant system /etc/profile carries bounded numeric
  # assignments for both variables and a readonly declaration that covers
  # both and appears after the assignments, per the standard text.
  typeset STR_RAW STR_RC STR_PARSED STR_STATE STR_REST
  typeset STR_TMO_CLS STR_TMO_VAL STR_TO_CLS STR_TO_VAL STR_MISSING STR_TMP STR_BAD
  STR_RAW=$(aix shell_timeout_readonly grep -E 'TMOUT|TIMEOUT' /etc/profile); STR_RC=$?
  if [ "$STR_RC" -ge 2 ]; then
    add security shell_timeout_readonly "Interactive shell inactivity timeout" \
        NOT_ASSESSED low \
        "not assessed — /etc/profile TMOUT/TIMEOUT capture failed (rc=$STR_RC)" \
        "Could not read TMOUT/TIMEOUT evidence from /etc/profile, so idle-shell readonly-timeout enforcement is unknown." \
        "restore read access to /etc/profile, then rerun PTxray." "cis-l2"
  elif [ "$STR_RC" -eq 1 ]; then
    add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
        "no TMOUT, TIMEOUT, or readonly declaration in /etc/profile (grep rc=1)" \
        "No idle-shell timeout is enforced; interactive shell sessions can remain open indefinitely." \
        "set TMOUT=900, TIMEOUT=900, and readonly TMOUT TIMEOUT in /etc/profile, then rerun PTxray." "cis-l2"
  else
    # Parse assignments and readonly declarations.  Comments are stripped;
    # inline trailing shell comments are removed from values.  Assignment
    # ordering matters: the standard requires the readonly statement to be
    # the last statement among these lines, so an assignment that appears
    # after a readonly declaration is an ordering violation.  A readonly or
    # typeset -r declaration may carry its own assignments (for example
    # "readonly TMOUT=900"), which are parsed and also mark the variable
    # readonly.  A line that does not name TMOUT or TIMEOUT as the exact
    # variable being set or declared is neighbour noise (for example
    # LOGIN_TIMEOUT=60) and never voids determinate evidence.
    STR_PARSED=$(printf '%s\n' "$STR_RAW" | awk '
      function trim(s) {
        sub(/^[ \t]+/, "", s)
        sub(/[ \t]+$/, "", s)
        return s
      }
      function strip_quotes(v,   q) {
        q = sprintf("%c", 39)
        if (v ~ /^"[^"]*"$/) v = substr(v, 2, length("" v) - 2)
        else if (length("" v) >= 2 && substr(v, 1, 1) == q && substr(v, length("" v), 1) == q) v = substr(v, 2, length("" v) - 2)
        return v
      }
      function classify(val,   canon) {
        val = strip_quotes(val)
        if (val == "") return "empty"
        if (val !~ /^[0-9]+$/) return "nonnum"
        canon = val
        sub(/^0+/, "", canon)
        if (canon == "") return "zero"
        if (length("" canon) > 3) return "over"
        if (canon + 0 > 900) return "over"
        return "ok"
      }
      function record_assign(name, raw,   sep, suffix) {
        sep = index(raw, ";")
        if (sep > 0) {
          suffix = substr(raw, sep + 1)
          suffix = trim(suffix)
          raw = substr(raw, 1, sep - 1)
          raw = trim(raw)
          gsub(/[ \t]+/, " ", suffix)
          if (suffix != "" && suffix != "export " name) { malformed = 1; return }
        }
        raw = trim(raw)
        raw = strip_quotes(raw)
        raw = trim(raw)
        if (name == "TMOUT") {
          if (tmo_seen && tmo_val != raw) { tmo_conflict = 1 }
          tmo_seen = 1; tmo_val = raw; tmo_cls = classify(raw)
        } else if (name == "TIMEOUT") {
          if (tmoout_seen && tmoout_val != raw) { tmoout_conflict = 1 }
          tmoout_seen = 1; tmoout_val = raw; tmoout_cls = classify(raw)
        }
      }
      function parse_ro_operand(tok,   nm, vv, hit) {
        hit = 0
        if (tok ~ /^(TMOUT|TIMEOUT)[ \t]*=/) {
          nm = tok
          sub(/[=].*/, "", nm)
          sub(/[ \t]+$/, "", nm)
          vv = tok
          sub(/^[^=]*=/, "", vv)
          if (nm == "TMOUT") { tmo_readonly = 1; hit = 1 }
          else if (nm == "TIMEOUT") { tmoout_readonly = 1; hit = 1 }
          record_assign(nm, vv)
        } else {
          # Bare operand: tolerate a trailing statement terminator ("TMOUT;"
          # on "readonly TMOUT;").  Assignments keep their semicolons for
          # record_assign, which owns the separator handling.
          sub(/;+$/, "", tok)
          if (tok == "TMOUT") { tmo_readonly = 1; hit = 1 }
          else if (tok == "TIMEOUT") { tmoout_readonly = 1; hit = 1 }
        }
        return hit
      }
      {
        line = $0
        sub(/^[ \t]+/, "", line)
        if (line ~ /^#/) next
        sub(/[ \t]+#.*/, "", line)
        line = trim(line)
        if (line == "") next

        # readonly declaration — names and/or assigns one or both variables.
        if (line ~ /^readonly[ \t]/) {
          work = line
          sub(/^readonly[ \t]+/, "", work)
          n = split(work, tok, /[ \t]+/)
          for (i = 1; i <= n; i++) {
            if (tok[i] == "") continue
            if (parse_ro_operand(tok[i])) readonly_seen = 1
          }
          next
        }

        # typeset with a -r flag is the ksh88 spelling of readonly.
        if (line ~ /^typeset[ \t]+-/) {
          work = line
          sub(/^typeset[ \t]+/, "", work)
          flags = work
          sub(/[ \t].*/, "", flags)
          if (substr(flags, 1, 1) == "-" && flags ~ /r/) {
            rest = work
            sub(/^[^ \t]+[ \t]+/, "", rest)
            n = split(rest, tok, /[ \t]+/)
            for (i = 1; i <= n; i++) {
              if (tok[i] == "") continue
              if (parse_ro_operand(tok[i])) readonly_seen = 1
            }
          } else if (line ~ /(^|[^A-Za-z0-9_])(TMOUT|TIMEOUT)([^A-Za-z0-9_]|$)/) {
            malformed = 1
          }
          next
        }

        # Bare export of TMOUT and/or TIMEOUT — declares the export, assigns no value.
        if (line ~ /^export[ \t]+/) {
          work = line
          sub(/^export[ \t]+/, "", work)
          n = split(work, tok, /[ \t]+/)
          all_ok = 1
          for (i = 1; i <= n; i++) {
            if (tok[i] == "") continue
            if (tok[i] != "TMOUT" && tok[i] != "TIMEOUT") { all_ok = 0; break }
          }
          if (all_ok) next
        }

        # Assignment: optional export prefix, variable name, equal sign, value.
        # The bracket class in the sub regex defeats the AIX awk /= lexer trap.
        if (line ~ /^(export[ \t]+)?(TMOUT|TIMEOUT)[ \t]*=/) {
          if (readonly_seen) order_bad = 1
          name = line
          sub(/[=].*/, "", name)
          sub(/^export[ \t]+/, "", name)
          name = trim(name)
          val = line
          sub(/^[^=]*=/, "", val)
          record_assign(name, val)
          next
        }

        # Unrecognised line.  If it names TMOUT or TIMEOUT as the exact variable
        # being set or declared, the evidence is malformed (refusal).  Otherwise
        # it is neighbour noise (for example LOGIN_TIMEOUT=60) and must not void
        # determinate TMOUT/TIMEOUT evidence.
        if (line ~ /(^|[^A-Za-z0-9_])(TMOUT|TIMEOUT)([^A-Za-z0-9_]|$)/) malformed = 1
      }
      END {
        if (malformed) print "malformed|"
        else if (tmo_conflict || tmoout_conflict) print "value_conflict|"
        else if (!tmo_seen && !tmoout_seen) print "absent|"
        else if (tmo_seen && !tmoout_seen) print "missing|TIMEOUT"
        else if (!tmo_seen && tmoout_seen) print "missing|TMOUT"
        else if (!readonly_seen) print "no_readonly|" tmo_cls "|" tmo_val "|" tmoout_cls "|" tmoout_val
        else if (tmo_readonly && !tmoout_readonly) print "partial_readonly|TIMEOUT|" tmo_cls "|" tmo_val "|" tmoout_cls "|" tmoout_val
        else if (!tmo_readonly && tmoout_readonly) print "partial_readonly|TMOUT|" tmo_cls "|" tmo_val "|" tmoout_cls "|" tmoout_val
        else if (order_bad) print "order|" tmo_cls "|" tmo_val "|" tmoout_cls "|" tmoout_val
        else print "both|" tmo_cls "|" tmo_val "|" tmoout_cls "|" tmoout_val
      }
    ')
    STR_STATE=${STR_PARSED%%\|*}
    STR_REST=${STR_PARSED#*\|}
    case "$STR_STATE" in
      malformed)
        add security shell_timeout_readonly "Interactive shell inactivity timeout" \
            NOT_ASSESSED low \
            "not assessed — /etc/profile TMOUT/TIMEOUT lines are not parseable" \
            "PTxray found lines matching TMOUT/TIMEOUT in /etc/profile but none parse as an assignment or readonly declaration, so timeout enforcement cannot be established." \
            "inspect TMOUT/TIMEOUT lines in /etc/profile, correct malformed entries, and rerun PTxray." "cis-l2"
        ;;
      value_conflict)
        add security shell_timeout_readonly "Interactive shell inactivity timeout" \
            NOT_ASSESSED low \
            "not assessed — conflicting assignments for the same variable in /etc/profile" \
            "PTxray observed different values assigned to TMOUT or TIMEOUT across multiple lines in /etc/profile; the effective value cannot be determined from grep output alone." \
            "consolidate TMOUT and TIMEOUT to one assignment each in /etc/profile, then rerun PTxray." "cis-l2"
        ;;
      absent)
        add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
            "no active TMOUT or TIMEOUT assignment in /etc/profile" \
            "No idle-shell timeout is enforced; interactive shell sessions can remain open indefinitely." \
            "set TMOUT=900, TIMEOUT=900, and readonly TMOUT TIMEOUT in /etc/profile, then rerun PTxray." "cis-l2"
        ;;
      missing)
        STR_MISSING=$STR_REST
        add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
            "$STR_MISSING is not configured in /etc/profile; both TMOUT and TIMEOUT must be set" \
            "Only one timeout variable is configured in /etc/profile; both are required by the standard." \
            "add a $STR_MISSING assignment (1–900) and a readonly declaration covering both variables in /etc/profile, then rerun PTxray." "cis-l2"
        ;;
      no_readonly)
        STR_TMO_CLS=${STR_REST%%\|*}
        STR_TMP=${STR_REST#*\|}
        STR_TMO_VAL=${STR_TMP%%\|*}
        STR_TMP=${STR_TMP#*\|}
        STR_TO_CLS=${STR_TMP%%\|*}
        STR_TO_VAL=${STR_TMP#*\|}
        add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
            "TMOUT and TIMEOUT are set but not readonly; the interactive user can alter or unset them" \
            "Without readonly, an interactive user can change or unset the timeout, defeating the inactivity lock." \
            "add \"readonly TMOUT TIMEOUT\" as the last relevant statement in /etc/profile, then rerun PTxray." "cis-l2"
        ;;
      partial_readonly)
        STR_MISSING=${STR_REST%%\|*}
        STR_TMP=${STR_REST#*\|}
        STR_TMO_CLS=${STR_TMP%%\|*}
        STR_TMP=${STR_TMP#*\|}
        STR_TMO_VAL=${STR_TMP%%\|*}
        STR_TMP=${STR_TMP#*\|}
        STR_TO_CLS=${STR_TMP%%\|*}
        STR_TO_VAL=${STR_TMP#*\|}
        add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
            "$STR_MISSING is not readonly; both TMOUT and TIMEOUT must be readonly" \
            "Only one timeout variable carries the readonly marker; the other can still be altered or unset by the interactive user." \
            "add $STR_MISSING to the readonly declaration in /etc/profile, then rerun PTxray." "cis-l2"
        ;;
      order)
        STR_TMO_CLS=${STR_REST%%\|*}
        STR_TMP=${STR_REST#*\|}
        STR_TMO_VAL=${STR_TMP%%\|*}
        STR_TMP=${STR_TMP#*\|}
        STR_TO_CLS=${STR_TMP%%\|*}
        STR_TO_VAL=${STR_TMP#*\|}
        add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
            "readonly declaration precedes TMOUT/TIMEOUT assignment; the standard requires readonly to be the last statement" \
            "A readonly declaration that appears before an assignment line is ineffective: the later assignment would fail at shell parse time, or the readonly would not cover it." \
            "move \"readonly TMOUT TIMEOUT\" to be the last statement among the timeout lines in /etc/profile, then rerun PTxray." "cis-l2"
        ;;
      both)
        STR_TMO_CLS=${STR_REST%%\|*}
        STR_TMP=${STR_REST#*\|}
        STR_TMO_VAL=${STR_TMP%%\|*}
        STR_TMP=${STR_TMP#*\|}
        STR_TO_CLS=${STR_TMP%%\|*}
        STR_TO_VAL=${STR_TMP#*\|}
        if [ "$STR_TMO_CLS" = over ] || [ "$STR_TO_CLS" = over ]; then
          STR_BAD=""
          if [ "$STR_TMO_CLS" = over ]; then STR_BAD="TMOUT=${STR_TMO_VAL}"; fi
          if [ "$STR_TO_CLS" = over ]; then
            if [ -n "$STR_BAD" ]; then STR_BAD="${STR_BAD} and TIMEOUT=${STR_TO_VAL}"; else STR_BAD="TIMEOUT=${STR_TO_VAL}"; fi
          fi
          add security shell_timeout_readonly "Interactive shell inactivity timeout" WARN low \
              "${STR_BAD} above the 900-second cap" \
              "A readonly timeout above 900 seconds still leaves an idle session open for an excessive period." \
              "lower TMOUT and TIMEOUT to 900 seconds or less, keep both readonly, and rerun PTxray." "cis-l2"
        elif [ "$STR_TMO_CLS" = empty ] || [ "$STR_TMO_CLS" = nonnum ] || [ "$STR_TMO_CLS" = zero ] ||
             [ "$STR_TO_CLS" = empty ] || [ "$STR_TO_CLS" = nonnum ] || [ "$STR_TO_CLS" = zero ]; then
          STR_BAD=""
          if [ "$STR_TMO_CLS" = empty ]; then STR_BAD="TMOUT has no value"
          elif [ "$STR_TMO_CLS" = zero ]; then STR_BAD="TMOUT=0"
          elif [ "$STR_TMO_CLS" = nonnum ]; then STR_BAD="TMOUT is not a positive integer"
          fi
          if [ "$STR_TO_CLS" = empty ]; then
            if [ -n "$STR_BAD" ]; then STR_BAD="${STR_BAD} and TIMEOUT has no value"; else STR_BAD="TIMEOUT has no value"; fi
          elif [ "$STR_TO_CLS" = zero ]; then
            if [ -n "$STR_BAD" ]; then STR_BAD="${STR_BAD} and TIMEOUT=0"; else STR_BAD="TIMEOUT=0"; fi
          elif [ "$STR_TO_CLS" = nonnum ]; then
            if [ -n "$STR_BAD" ]; then STR_BAD="${STR_BAD} and TIMEOUT is not a positive integer"; else STR_BAD="TIMEOUT is not a positive integer"; fi
          fi
          add security shell_timeout_readonly "Interactive shell inactivity timeout" FAIL high \
              "${STR_BAD}; idle-shell auto-logout is disabled or unreadable" \
              "A zero, empty, or non-numeric timeout value breaks the enforced inactivity logout even when readonly is set." \
              "set TMOUT and TIMEOUT to a positive integer from 1 through 900, keep both readonly, and rerun PTxray." "cis-l2"
        else
          add security shell_timeout_readonly "Interactive shell inactivity timeout" PASS low \
              "TMOUT=${STR_TMO_VAL} and TIMEOUT=${STR_TO_VAL}, both readonly" \
              "Both timeout variables are readonly with a bounded positive value, so an idle interactive shell auto-logs out." \
              "n/a" "cis-l2"
        fi
        ;;
      *)
        add security shell_timeout_readonly "Interactive shell inactivity timeout" \
            NOT_ASSESSED low \
            "not assessed — /etc/profile TMOUT/TIMEOUT parse returned unrecognised state" \
            "The parsed TMOUT/TIMEOUT evidence from /etc/profile did not map to a known shape, so timeout enforcement is unknown." \
            "inspect /etc/profile TMOUT/TIMEOUT configuration and rerun PTxray." "cis-l2"
        ;;
    esac
  fi
}

function standalone_run {
  standalone_check
}

standalone_main "$@"
exit $?
