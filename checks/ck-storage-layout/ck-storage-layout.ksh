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

AIXRAY_TOOL=ck-storage-layout

_AIXRAY_SESSION_KEYS=""
# Emit one JSON member named "storage_layout" from fresh, replayable AIX
# captures and one explicit assessment-gap finding. The integration build owns
# the spine include plus both check and facts-emitter call sites.

function storage_layout_has_nonblank {
  printf '%s\n' "$1" | awk 'NF { found=1 } END { exit(found ? 0 : 1) }'
}

function storage_layout_emit_inventory_gap {
  typeset SL_FATAL_REASON
  SL_FATAL_REASON=$1

  printf '%s\n' "$SL_FATAL_REASON" | awk '
    function json_escape(value, result, character) {
      result = ""
      while (value != "") {
        character = substr(value, 1, 1)
        value = substr(value, 2)
        if (character == "\\") result = result "\\\\"
        else if (character == "\"") result = result "\\\""
        else if (character == "\t") result = result "\\t"
        else if (character == "\r") result = result "\\r"
        else result = result character
      }
      return result
    }
    {
      if (NR > 1) reason = reason "\\n"
      reason = reason $0
    }
    END {
      printf "\"storage_layout\":{"
      printf "\"status\":\"NOT_ASSESSED\",\"platform\":\"AIX\","
      printf "\"reason\":\"%s\",", json_escape(reason)
      printf "\"inventory_source_cmd\":\"lspv\","
      printf "\"size_source_cmd\":\"getconf DISK_SIZE /dev/<hdisk>\","
      printf "\"type_source_cmd\":\"%s\",", \
        json_escape("lsdev -Cc disk -F \"name:status:description\"")
      printf "\"path_source_cmd\":\"%s\",", \
        json_escape("lspath -F \"name parent path_id status\"")
      printf "\"capture_gaps\":[\"%s\"],\"disks\":null}", \
        json_escape(reason)
    }
  '
}

function emit_fact_storage_layout {
  typeset SL_LSPV SL_LSPV_RC SL_LSPV_ROWS SL_SHAPE_RC
  typeset SL_LSDEV SL_LSDEV_RC SL_LSDEV_ROWS SL_LSDEV_REASON
  typeset SL_LSPATH SL_LSPATH_RC SL_LSPATH_ROWS SL_LSPATH_REASON
  typeset SL_DISK SL_PVID SL_VG SL_KEY
  typeset SL_SIZE_RAW SL_SIZE_RC SL_SIZE SL_SIZE_REASON SL_SIZE_KNOWN
  typeset SL_DESC SL_DESC_REASON SL_DESC_KNOWN SL_LOOKUP_RC
  typeset SL_PATH_DATA SL_PATH_REST SL_PATH_COUNT SL_PATH_SUMMARY
  typeset SL_PATH_FAILED SL_PATH_MISSING SL_PATH_NOTE SL_PATH_REASON
  typeset SL_PATH_KNOWN

  # lspv is the inventory authority. A failed, empty, or malformed inventory
  # cannot safely supply device names for any later dynamic capture key.
  SL_LSPV=$(aix lspv lspv); SL_LSPV_RC=$?
  if [ "$SL_LSPV_RC" -ne 0 ]; then
    storage_layout_emit_inventory_gap \
      "lspv capture failed (rc=$SL_LSPV_RC)"
    return 0
  fi
  if ! storage_layout_has_nonblank "$SL_LSPV"; then
    storage_layout_emit_inventory_gap "lspv capture empty (rc=0)"
    return 0
  fi
  SL_LSPV_ROWS=$(printf '%s\n' "$SL_LSPV" | awk '
    function hdisk(value) { return value ~ /^hdisk[0-9][0-9]*$/ }
    function pvid(value) {
      return value == "none" ||
        (value ~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/ &&
         substr(value,16,1) != "" && substr(value,17,1) == "")
    }
    function vg(value) {
      return value ~ /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/
    }
    /^[ \t]*$/ { next }
    {
      rows++
      if (NF < 3 || !hdisk($1) || !pvid($2) || !vg($3) || seen[$1]++) {
        bad=1
        next
      }
      disk[rows]=$1
      disk_pvid[rows]=$2
      disk_vg[rows]=$3
    }
    END {
      if (bad || rows == 0) exit 1
      for (row=1; row<=rows; row++)
        printf "%s\t%s\t%s\n", disk[row], disk_pvid[row], disk_vg[row]
    }
  '); SL_SHAPE_RC=$?
  if [ "$SL_SHAPE_RC" -ne 0 ] || [ -z "$SL_LSPV_ROWS" ]; then
    storage_layout_emit_inventory_gap "lspv capture unparseable (rc=0)"
    return 0
  fi

  # Device descriptions are supplemental. Their capture gap must not erase
  # the lspv inventory or prevent independent size/path facts from surfacing.
  SL_LSDEV_REASON=""
  SL_LSDEV_ROWS=""
  SL_LSDEV=$(aix lsdev_disk_fields lsdev -Cc disk -F \
    "name:status:description"); SL_LSDEV_RC=$?
  if [ "$SL_LSDEV_RC" -ne 0 ]; then
    SL_LSDEV_REASON="lsdev -Cc disk -F \"name:status:description\" capture failed (rc=$SL_LSDEV_RC)"
  elif ! storage_layout_has_nonblank "$SL_LSDEV"; then
    SL_LSDEV_REASON="lsdev -Cc disk -F \"name:status:description\" capture empty (rc=0)"
  else
    SL_LSDEV_ROWS=$(printf '%s\n' "$SL_LSDEV" | awk -F ':' '
      function hdisk(value) { return value ~ /^hdisk[0-9][0-9]*$/ }
      /^[ \t]*$/ { next }
      {
        rows++
        if (NF != 3 || !hdisk($1) ||
            ($2 != "Available" && $2 != "Defined" && $2 != "Stopped") ||
            seen[$1]++) {
          bad=1
          next
        }
        description=$3
        if (description !~ /[^ \t]/) {
          bad=1
          next
        }
        disk[rows]=$1
        disk_description[rows]=description
      }
      END {
        if (bad || rows == 0) exit 1
        for (row=1; row<=rows; row++)
          printf "%s\t%s\n", disk[row], disk_description[row]
      }
    '); SL_SHAPE_RC=$?
    if [ "$SL_SHAPE_RC" -ne 0 ] || [ -z "$SL_LSDEV_ROWS" ]; then
      SL_LSDEV_ROWS=""
      SL_LSDEV_REASON="lsdev -Cc disk -F \"name:status:description\" capture unparseable (rc=0)"
    fi
  fi

  # Empty lspath is a normal non-MPIO observation, but it does not prove a
  # numeric zero for every disk. Preserve it as an explicit assessment gap.
  SL_LSPATH_REASON=""
  SL_LSPATH_ROWS=""
  SL_LSPATH=$(aix lspath_disk lspath -F "name parent path_id status")
  SL_LSPATH_RC=$?
  if [ "$SL_LSPATH_RC" -ne 0 ]; then
    SL_LSPATH_REASON="lspath -F \"name parent path_id status\" capture failed (rc=$SL_LSPATH_RC)"
  elif ! storage_layout_has_nonblank "$SL_LSPATH"; then
    SL_LSPATH_REASON="lspath -F \"name parent path_id status\" capture empty (rc=0); no MPIO paths reported"
  else
    SL_LSPATH_ROWS=$(printf '%s\n' "$SL_LSPATH" | awk '
      function hdisk(value) { return value ~ /^hdisk[0-9][0-9]*$/ }
      function token(value) {
        return value ~ /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/
      }
      /^[ \t]*$/ { next }
      {
        rows++
        key=$1 SUBSEP $2 SUBSEP $3
        if (NF < 4 || !hdisk($1) || !token($2) ||
            $3 !~ /^[0-9][0-9]*$/ || !token($4) || seen[key]++) {
          bad=1
          next
        }
        disk[rows]=$1
        parent[rows]=$2
        path_id[rows]=$3
        path_status[rows]=$4
      }
      END {
        if (bad || rows == 0) exit 1
        for (row=1; row<=rows; row++)
          printf "%s\t%s\t%s\t%s\n", disk[row], parent[row],
            path_id[row], path_status[row]
      }
    '); SL_SHAPE_RC=$?
    if [ "$SL_SHAPE_RC" -ne 0 ] || [ -z "$SL_LSPATH_ROWS" ]; then
      SL_LSPATH_ROWS=""
      SL_LSPATH_REASON="lspath -F \"name parent path_id status\" capture unparseable (rc=0)"
    fi
  fi

  {
    printf '%s\n' "$SL_LSPV_ROWS" | awk -F '\t' \
      '{ printf "I\t%s\t%s\t%s\n", $1, $2, $3 }'
    [ -n "$SL_LSDEV_REASON" ] && printf 'G\t%s\n' "$SL_LSDEV_REASON"
    [ -n "$SL_LSPATH_REASON" ] && printf 'G\t%s\n' "$SL_LSPATH_REASON"

    printf '%s\n' "$SL_LSPV_ROWS" |
      while read SL_DISK SL_PVID SL_VG; do
        # Each size is independently captured and gated. A plausible-looking
        # payload from a failed command is never used.
        SL_KEY="getconf_disk_size_$SL_DISK"
        SL_SIZE_RAW=$(aix "$SL_KEY" getconf DISK_SIZE "/dev/$SL_DISK")
        SL_SIZE_RC=$?
        SL_SIZE=""
        SL_SIZE_REASON=""
        SL_SIZE_KNOWN=0
        if [ "$SL_SIZE_RC" -ne 0 ]; then
          SL_SIZE_REASON="getconf DISK_SIZE /dev/$SL_DISK capture failed (rc=$SL_SIZE_RC)"
        elif ! storage_layout_has_nonblank "$SL_SIZE_RAW"; then
          SL_SIZE_REASON="getconf DISK_SIZE /dev/$SL_DISK capture empty (rc=0)"
        else
          SL_SIZE=$(printf '%s\n' "$SL_SIZE_RAW" | awk '
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
          '); SL_SHAPE_RC=$?
          if [ "$SL_SHAPE_RC" -eq 0 ] && [ -n "$SL_SIZE" ]; then
            SL_SIZE_KNOWN=1
          else
            SL_SIZE=""
            SL_SIZE_REASON="getconf DISK_SIZE /dev/$SL_DISK capture unparseable (rc=0)"
          fi
        fi

        SL_DESC=""
        SL_DESC_REASON=""
        SL_DESC_KNOWN=0
        if [ -n "$SL_LSDEV_REASON" ]; then
          SL_DESC_REASON=$SL_LSDEV_REASON
        else
          SL_DESC=$(printf '%s\n' "$SL_LSDEV_ROWS" | awk -F '\t' \
            -v wanted="$SL_DISK" '
              $1 == wanted { print $2; found=1; exit }
              END { if (!found) exit 1 }
            ')
          SL_LOOKUP_RC=$?
          if [ "$SL_LOOKUP_RC" -eq 0 ] && [ -n "$SL_DESC" ]; then
            SL_DESC_KNOWN=1
          else
            SL_DESC=""
            SL_DESC_REASON="lsdev -Cc disk -F \"name:status:description\" reported no description for $SL_DISK (rc=0)"
          fi
        fi

        SL_PATH_COUNT=""
        SL_PATH_SUMMARY=""
        SL_PATH_NOTE=""
        SL_PATH_REASON=""
        SL_PATH_KNOWN=0
        if [ -n "$SL_LSPATH_REASON" ]; then
          SL_PATH_REASON=$SL_LSPATH_REASON
        else
          SL_PATH_DATA=$(printf '%s\n' "$SL_LSPATH_ROWS" | awk -F '\t' \
            -v wanted="$SL_DISK" '
              $1 == wanted {
                count++
                status=$4
                if (!seen[status]++) order[++states]=status
                if (status == "Failed") failed++
                if (status == "Missing") missing++
              }
              END {
                if (count == 0) exit 1
                printf "%d:", count
                for (state=1; state<=states; state++) {
                  if (state > 1) printf ", "
                  printf "%s=%d", order[state], seen[order[state]]
                }
                printf ":%d:%d", failed+0, missing+0
              }
            ')
          SL_LOOKUP_RC=$?
          if [ "$SL_LOOKUP_RC" -eq 0 ] && [ -n "$SL_PATH_DATA" ]; then
            SL_PATH_COUNT=${SL_PATH_DATA%%:*}
            SL_PATH_REST=${SL_PATH_DATA#*:}
            SL_PATH_SUMMARY=${SL_PATH_REST%%:*}
            SL_PATH_REST=${SL_PATH_REST#*:}
            SL_PATH_FAILED=${SL_PATH_REST%%:*}
            SL_PATH_MISSING=${SL_PATH_REST#*:}
            if [ "$SL_PATH_FAILED" -gt 0 ] || [ "$SL_PATH_MISSING" -gt 0 ]; then
              SL_PATH_NOTE="Failed/Missing path state observed (Failed=$SL_PATH_FAILED, Missing=$SL_PATH_MISSING)"
            fi
            SL_PATH_KNOWN=1
          else
            SL_PATH_REASON="lspath -F \"name parent path_id status\" reported no paths for $SL_DISK (rc=0)"
          fi
        fi

        [ -n "$SL_SIZE_REASON" ] && printf 'G\t%s\n' "$SL_SIZE_REASON"
        [ -n "$SL_DESC_REASON" ] && printf 'G\t%s\n' "$SL_DESC_REASON"
        [ -n "$SL_PATH_REASON" ] && printf 'G\t%s\n' "$SL_PATH_REASON"
        printf 'D\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\tX\n' \
          "$SL_DISK" "$SL_SIZE_KNOWN" "$SL_SIZE" "$SL_SIZE_REASON" \
          "$SL_DESC_KNOWN" "$SL_DESC" "$SL_DESC_REASON" \
          "$SL_PATH_KNOWN" "$SL_PATH_COUNT" "$SL_PATH_SUMMARY" \
          "$SL_PATH_NOTE" "$SL_PATH_REASON"
      done
  } | awk -F '\t' '
    function json_escape(value, result, character) {
      result = ""
      while (value != "") {
        character = substr(value, 1, 1)
        value = substr(value, 2)
        if (character == "\\") result = result "\\\\"
        else if (character == "\"") result = result "\\\""
        else if (character == "\t") result = result "\\t"
        else if (character == "\r") result = result "\\r"
        else result = result character
      }
      return result
    }
    function add_gap(reason) {
      if (reason != "" && !gap_seen[reason]++) gap[++gap_count]=reason
    }
    function add_reason(current, reason) {
      if (reason == "") return current
      if (current == "") return reason
      if (index("; " current "; ", "; " reason "; ") > 0) return current
      return current "; " reason
    }
    $1 == "G" {
      add_gap($2)
      next
    }
    $1 == "I" {
      inventory_pvid[$2]=$3
      inventory_vg[$2]=$4
      next
    }
    $1 == "D" {
      row=++disk_count
      disk[row]=$2
      size_known[row]=$3+0
      size[row]=$4
      size_reason[row]=$5
      description_known[row]=$6+0
      description[row]=$7
      description_reason[row]=$8
      path_known[row]=$9+0
      path_count[row]=$10
      path_summary[row]=$11
      path_note[row]=$12
      path_reason[row]=$13
      next
    }
    END {
      printf "\"storage_layout\":{"
      printf "\"status\":\"%s\",", (gap_count ? "PARTIAL" : "COMPLETE")
      printf "\"platform\":\"AIX\","
      if (gap_count) printf "\"reason\":\"one or more storage-layout facts were not assessed\","
      else printf "\"reason\":null,"
      printf "\"inventory_source_cmd\":\"lspv\","
      printf "\"size_source_cmd\":\"getconf DISK_SIZE /dev/<hdisk>\","
      printf "\"type_source_cmd\":\"%s\",", \
        json_escape("lsdev -Cc disk -F \"name:status:description\"")
      printf "\"path_source_cmd\":\"%s\",", \
        json_escape("lspath -F \"name parent path_id status\"")
      printf "\"capture_gaps\":["
      for (item=1; item<=gap_count; item++) {
        if (item > 1) printf ","
        printf "\"%s\"", json_escape(gap[item])
      }
      printf "],\"disks\":["
      for (row=1; row<=disk_count; row++) {
        if (row > 1) printf ","
        assessed=size_known[row] && description_known[row] && path_known[row]
        reason=""
        if (!size_known[row]) reason=add_reason(reason, size_reason[row])
        if (!description_known[row]) reason=add_reason(reason, description_reason[row])
        if (!path_known[row]) reason=add_reason(reason, path_reason[row])

        printf "{\"hdisk\":\"%s\",", json_escape(disk[row])
        if (size_known[row]) printf "\"size_mb\":%s,", size[row]
        else printf "\"size_mb\":null,"
        printf "\"vg\":\"%s\",", json_escape(inventory_vg[disk[row]])
        printf "\"pvid\":\"%s\",", json_escape(inventory_pvid[disk[row]])
        if (description_known[row])
          printf "\"type_desc\":\"%s\",", json_escape(description[row])
        else printf "\"type_desc\":null,"
        if (path_known[row]) {
          printf "\"path_count\":%s,", path_count[row]
          printf "\"path_status_summary\":\"%s\",", \
            json_escape(path_summary[row])
          if (path_note[row] != "")
            printf "\"path_note\":\"%s\",", json_escape(path_note[row])
          else printf "\"path_note\":null,"
        } else {
          printf "\"path_count\":null,\"path_status_summary\":null,"
          printf "\"path_note\":null,"
        }
        printf "\"status\":\"%s\",", (assessed ? "OBSERVED" : "NOT_ASSESSED")
        if (assessed) printf "\"reason\":null,"
        else printf "\"reason\":\"%s\",", json_escape(reason)
        printf "\"not_assessed\":{"
        separator=""
        if (!size_known[row]) {
          printf "\"size_mb\":\"%s\"", json_escape(size_reason[row])
          separator=","
        }
        if (!description_known[row]) {
          printf "%s\"type_desc\":\"%s\"", separator, \
            json_escape(description_reason[row])
          separator=","
        }
        if (!path_known[row]) {
          printf "%s\"path_count\":\"%s\"", separator, \
            json_escape(path_reason[row])
          printf ",\"path_status_summary\":\"%s\"", \
            json_escape(path_reason[row])
        }
        printf "}}"
      }
      printf "]}"
    }
  '
}

# Storage facts describe what AIX reported. A topology finding still needs an
# approved expected-state baseline; emit the gap explicitly when that is absent.
function check_storage_layout {
  typeset SL_CHECK_OUT SL_CHECK_RC SL_CHECK_ROWS SL_CHECK_SHAPE_RC
  typeset SL_CHECK_COUNT SL_CHECK_NOUN SL_CHECK_VERB SL_CHECK_OBS
  typeset SL_CHECK_MEAN SL_CHECK_FIX

  SL_CHECK_OUT=$(aix lspv lspv); SL_CHECK_RC=$?
  if [ "$SL_CHECK_RC" -ne 0 ]; then
    SL_CHECK_OBS="not assessed — lspv storage inventory failed (rc=$SL_CHECK_RC)"
    SL_CHECK_MEAN="The physical-volume inventory source was unavailable, so storage topology, ownership, and redundancy could not be assessed."
    SL_CHECK_FIX="restore access to 'lspv', provide the approved storage topology baseline, and rerun PTxray."
  elif ! storage_layout_has_nonblank "$SL_CHECK_OUT"; then
    SL_CHECK_OBS="not assessed — lspv reported no storage inventory (rc=0)"
    SL_CHECK_MEAN="An empty physical-volume inventory cannot establish disk ownership, topology, or redundancy."
    SL_CHECK_FIX="verify the complete output of 'lspv', provide the approved storage topology baseline, and rerun PTxray."
  else
    SL_CHECK_ROWS=$(printf '%s\n' "$SL_CHECK_OUT" | awk '
      function hdisk(value) { return value ~ /^hdisk[0-9][0-9]*$/ }
      function pvid(value) {
        return value == "none" ||
          (value ~ /^[0-9A-Fa-f][0-9A-Fa-f]*$/ &&
           substr(value,16,1) != "" && substr(value,17,1) == "")
      }
      function vg(value) {
        return value ~ /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/
      }
      /^[ \t]*$/ { next }
      {
        rows++
        if (NF < 3 || !hdisk($1) || !pvid($2) || !vg($3) ||
            seen[$1]++) bad=1
      }
      END {
        if (bad || rows == 0) exit 1
        print rows
      }
    '); SL_CHECK_SHAPE_RC=$?
    if [ "$SL_CHECK_SHAPE_RC" -ne 0 ] || [ -z "$SL_CHECK_ROWS" ]; then
      SL_CHECK_OBS="not assessed — lspv storage inventory was unparseable (rc=0)"
      SL_CHECK_MEAN="The physical-volume capture did not match the expected AIX lspv structure, so topology, ownership, and redundancy could not be assessed."
      SL_CHECK_FIX="capture the complete output of 'lspv', correct the replay source if needed, provide the approved storage topology baseline, and rerun PTxray."
    else
      SL_CHECK_COUNT=$SL_CHECK_ROWS
      SL_CHECK_NOUN=disks
      SL_CHECK_VERB=were
      if [ "$SL_CHECK_COUNT" -eq 1 ]; then
        SL_CHECK_NOUN=disk
        SL_CHECK_VERB=was
      fi
      SL_CHECK_OBS="not assessed — $SL_CHECK_COUNT $SL_CHECK_NOUN $SL_CHECK_VERB inventoried from lspv, but no site-approved expected storage topology, ownership, and redundancy baseline was available"
      SL_CHECK_MEAN="Observed disks and volume groups alone cannot establish whether placement, ownership, pathing, and redundancy match the intended architecture."
      SL_CHECK_FIX="provide the site-approved expected storage topology, ownership, pathing, and redundancy baseline, compare it with this inventory, and rerun PTxray."
    fi
  fi

  add storage storage_layout "Storage layout baseline" \
    NOT_ASSESSED high "$SL_CHECK_OBS" "$SL_CHECK_MEAN" "$SL_CHECK_FIX"
}

function standalone_run {
  check_storage_layout
}

standalone_main "$@"
exit $?
