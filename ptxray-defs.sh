#!/bin/sh
# PTxray definitions downloader/verifier. This adjacent program is the only
# PTxray assessment component that can make a network request. It retrieves
# signed data; it never executes, sources, evaluates, or remediates anything.
set -u
PATH=/usr/bin:/bin
export PATH
LC_ALL=C
export LC_ALL
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy no_proxy NO_PROXY
unset CURL_HOME CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR SSLKEYLOGFILE
unset OPENSSL_CONF OPENSSL_CONF_INCLUDE OPENSSL_MODULES OPENSSL_ENGINES
unset OPENSSL_TRACE OPENSSL_MALLOC_FD OPENSSL_MALLOC_FAILURES
unset OPENSSL_MALLOC_SEED CTLOG_FILE RANDFILE
unset LIBPATH LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT SHLIB_PATH
unset LDR_PRELOAD LDR_PRELOAD64
unset DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH DYLD_INSERT_LIBRARIES
unset DYLD_FRAMEWORK_PATH DYLD_FALLBACK_FRAMEWORK_PATH
unset ENV BASH_ENV KSH_ENV ZDOTDIR
umask 077

PTXRAY_DEFS_VERSION="1.6.0"

PTXRAY_DEFS_TEST_BUILD=0
PTXRAY_DEFS_CACHE='/var/ptxray/definitions'
PTXRAY_DEFS_TRUST_DATE='2026-08-25'
PTXRAY_DEFS_CURRENT_ID='sha256:fa10579eac82937009352406152849f72aac1b7476d1025f744208c1cf3506a4'
PTXRAY_DEFS_CURRENT_PEM='-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzUvoqrcSptUoXug2y9T4
M3QTQZaMRRiqGjKPsmLJ4+DfR2btONKzHBiOxHOh4Cu9JrA7GYjxxhQR9Yc32O0e
ZQghHUhkBjqMIAazDfQtoUWSLvANgiQdF/HBin7qnTQDw+Z68SpOkLZOst5HR1TL
+80ud0d+QssDZpEiHJZWCvXUDJquxGk+IY8LZGM6LkXjWzPtAuXqtMhLI5mjVfVa
g165xk/nKgWEZwOX8/9Zlfz56rXGUHFCS6IUTg4MT+SNeegKHtBvAih1RtZK3lYZ
XkEIooO3jEBGRHDjszk3d1HyNSWBQrx1eCiIPvfaqHu1tG0wdNOs19h80ZEwDiVl
h/O6b+GF0/bVvjFdoM7H1wUO/z3iseFmMPAYNCRSayUPYktNHCNlqdI1IiCAOw5Y
dBXenpsvIvplOYniX/I5Zifp3XKW27zUkOENB3EZWVDSHoGeriq0sDfVAGcFHsgt
WHQCZ6+XF7jMIMRhGsxFcKJ2NuOxMIJsb5zZ+omqa77dAgMBAAE=
-----END PUBLIC KEY-----
'
PTXRAY_DEFS_NEXT_ID='sha256:6a3ec5444f52e3533b6761ac8b2ee456c5ae2ca6006c66816a5bc14b030cc012'
PTXRAY_DEFS_NEXT_PEM='-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAr5Zzd+j+cn4HeI1ygZh3
kN4PeR8uwYft/mcc8VaJdRYVUMwD35xQbw+oE2s6aK9EWFed7SGcD2zhNFOm3Ddq
ZL1xETNGy0kFln62tX/zlZiRVfLHW8AgI9P85ar0ZrVrVMeoh7iZ5KMyAhI+sfxo
VxQeNaI7ypBI2nkNCV8Y58rAMbkwWaCC6Wwtw6Bx0lVHASAyUWlEQm1FDAa1B8wh
TiEaiEUQ7WufQf1omwYnl1rO+3XOpJLAMU0U3llWCbBiIvGR0WBR5LlyA3f0mbCD
ttJ54X2AdC6U2mx3ZrmUy7t00If+o3A3+F8dp0VVDUQuOMEJzKw9iN1RSWh6C7/B
bN4T7pjSTol3cjE+CEtxlGSih3smdCoStIPuJM5QnKwHoYb+ZirHxo4Y3ck/jBWC
hQJ9WjEMYNjdUrLZIn9rZkJXki8QTpv4+kHPvG2Gi8lao+AmNcaadCoK/RvP2KpG
Ak/XnlGKgEbz/OJzXxhmD+9CO+8rJOEL04AZU2gT5b1TAgMBAAE=
-----END PUBLIC KEY-----
'

PTXRAY_DEFS_BUNDLE_URL='https://powertruesystems.com/ptxray/definitions/latest.ptxray-defs'
PTXRAY_DEFS_SIGNATURE_URL='https://powertruesystems.com/ptxray/definitions/latest.ptxray-defs.sig'
PTXRAY_DEFS_USER_AGENT='PTxray-definitions/1.5 (+https://powertruesystems.com/ptxray/)'
PTXRAY_DEFS_MAX_BUNDLE=52428800
PTXRAY_DEFS_SIGNATURE_BYTES=384
PTXRAY_DEFS_MAX_PAYLOAD=33554432
PTXRAY_DEFS_MAX_ENCODED=44739244
PTXRAY_DEFS_MAX_AGE_DAYS=30
PTXRAY_DEFS_WORK=
PTXRAY_DEFS_LOCK=
PTXRAY_DEFS_LOCK_HELD=0
PTXRAY_DEFS_LOCK_ID=
PTXRAY_DEFS_LOCK_OWNER_ID=
PTXRAY_DEFS_FAILURE=malformed
PTXRAY_DEFS_STRICT_MINIMUM=0
PTXRAY_DEFS_RESET_FLOOR=0
PTXRAY_DEFS_RECOVERY_POINTER=
PTXRAY_DEFS_RECOVERY_POINTER_SHA=
PTXRAY_DEFS_SNAPSHOT_DIR=
PTXRAY_DEFS_SNAPSHOT_DIR_ID=
PTXRAY_DEFS_SNAPSHOT_ACTIVE=0

ptxray_defs_fail() {
  case "$1" in
    signature|rollback|malformed|unsafe-cache|lock-contention)
      PTXRAY_DEFS_FAILURE=$1
      ;;
    *)
      PTXRAY_DEFS_FAILURE=malformed
      ;;
  esac
  return 1
}

ptxray_defs_cleanup() {
  if [ "$PTXRAY_DEFS_LOCK_HELD" -eq 1 ]; then
    case "$PTXRAY_DEFS_LOCK" in
      "$PTXRAY_DEFS_CACHE"/.publish.lock)
        if [ -n "$PTXRAY_DEFS_LOCK_ID" ] \
            && [ "$PTXRAY_DEFS_LOCK_ID" = "$(ptxray_defs_cache_dir_identity \
              "$PTXRAY_DEFS_LOCK" 2>/dev/null)" ] \
            && [ -n "$PTXRAY_DEFS_LOCK_OWNER_ID" ] \
            && [ "$PTXRAY_DEFS_LOCK_OWNER_ID" = "$(ptxray_defs_cache_file_identity \
              "$PTXRAY_DEFS_LOCK/owner" 2>/dev/null)" ]; then
          rm -f "$PTXRAY_DEFS_LOCK/owner" 2>/dev/null || :
          rmdir "$PTXRAY_DEFS_LOCK" 2>/dev/null || :
        fi
        ;;
    esac
  fi
  PTXRAY_DEFS_LOCK=
  PTXRAY_DEFS_LOCK_HELD=0
  PTXRAY_DEFS_LOCK_ID=
  PTXRAY_DEFS_LOCK_OWNER_ID=
  if [ "$PTXRAY_DEFS_SNAPSHOT_ACTIVE" -eq 1 ] \
      && [ -n "$PTXRAY_DEFS_SNAPSHOT_DIR" ] \
      && [ "$PTXRAY_DEFS_SNAPSHOT_DIR_ID" = "$(ptxray_defs_cache_dir_identity \
        "$PTXRAY_DEFS_SNAPSHOT_DIR" 2>/dev/null)" ]; then
    for PTXRAY_DEFS_SNAPSHOT_NAME in \
        cisa-kev.json cisa-kev-cves.txt ibm-apar.csv; do
      PTXRAY_DEFS_SNAPSHOT_PATH=$PTXRAY_DEFS_SNAPSHOT_DIR/$PTXRAY_DEFS_SNAPSHOT_NAME
      ptxray_defs_cache_file_identity "$PTXRAY_DEFS_SNAPSHOT_PATH" \
        >/dev/null 2>&1 \
        && rm -f "$PTXRAY_DEFS_SNAPSHOT_PATH" 2>/dev/null || :
    done
  fi
  PTXRAY_DEFS_SNAPSHOT_DIR=
  PTXRAY_DEFS_SNAPSHOT_DIR_ID=
  PTXRAY_DEFS_SNAPSHOT_ACTIVE=0
  case "$PTXRAY_DEFS_WORK" in
    "$PTXRAY_DEFS_CACHE"/.work.*)
      [ -d "$PTXRAY_DEFS_WORK" ] && [ ! -L "$PTXRAY_DEFS_WORK" ] \
        && rm -rf "$PTXRAY_DEFS_WORK"
      ;;
  esac
  PTXRAY_DEFS_WORK=
}
trap 'ptxray_defs_cleanup' 0
trap 'ptxray_defs_cleanup; trap - 0 1 2 3 15; exit 1' 1 2 3 15

ptxray_defs_error() {
  echo "ptxray-defs: $1" >&2
  return 1
}

ptxray_defs_select_openssl() {
  for PTXRAY_DEFS_OPENSSL in \
      /usr/bin/openssl \
      /opt/freeware/bin/openssl \
      /QOpenSys/pkgs/bin/openssl
  do
    PTXRAY_DEFS_OPENSSL=$(ptxray_defs_trusted_tool "$PTXRAY_DEFS_OPENSSL") \
      && { printf '%s\n' "$PTXRAY_DEFS_OPENSSL"; return 0; }
  done
  return 1
}

ptxray_defs_select_curl() {
  for PTXRAY_DEFS_CURL in \
      /usr/bin/curl \
      /opt/freeware/bin/curl \
      /opt/freeware/bin/curl_64 \
      /QOpenSys/pkgs/bin/curl
  do
    PTXRAY_DEFS_CURL=$(ptxray_defs_trusted_tool "$PTXRAY_DEFS_CURL") \
      && { printf '%s\n' "$PTXRAY_DEFS_CURL"; return 0; }
  done
  return 1
}

ptxray_defs_require_identity() {
  [ "$PTXRAY_DEFS_TEST_BUILD" -eq 0 ] || return 0
  PTXRAY_DEFS_PLATFORM=$(uname -s 2>/dev/null) || return 1
  case "$PTXRAY_DEFS_PLATFORM" in
    AIX)
      [ "$(id -u 2>/dev/null)" = 0 ] || return 1
      ;;
    OS400)
      [ -x /QOpenSys/usr/bin/qsh ] || return 1
      PTXRAY_DEFS_IDENTITY=$(/QOpenSys/usr/bin/qsh -c \
        '/usr/bin/db2 "SELECT VARCHAR(TRIM(SESSION_USER),128) CONCAT '\''|'\'' CONCAT VARCHAR(TRIM(SYSTEM_USER),128) FROM SYSIBM.SYSDUMMY1"' \
        2>/dev/null) || return 1
      printf '%s\n' "$PTXRAY_DEFS_IDENTITY" | awk '
        /\|/ && $0 !~ /RECORD/ {row=$0;gsub(/^[ \t]+|[ \t]+$/,"",row);if(row!=""){n++;split(row,v,"[|]");gsub(/^[ \t]+|[ \t]+$/,"",v[1]);gsub(/^[ \t]+|[ \t]+$/,"",v[2]);a=toupper(v[1]);b=toupper(v[2])}}
        END{exit !(n==1&&a=="QSECOFR"&&b=="QSECOFR")}' || return 1
      ;;
    *) return 1;;
  esac
  return 0
}

ptxray_defs_valid_ymd() {
  printf '%s\n' "$1" | awk -F- '
    function leap(y){return y%400==0 || (y%4==0 && y%100!=0)}
    NF==3 && $1 ~ /^[0-9][0-9][0-9][0-9]$/ \
      && $2 ~ /^[0-9][0-9]$/ && $3 ~ /^[0-9][0-9]$/ {
      y=$1+0;m=$2+0;d=$3+0
      dim=31
      if(m==4||m==6||m==9||m==11)dim=30
      else if(m==2)dim=leap(y)?29:28
      if(m>=1&&m<=12&&d>=1&&d<=dim)ok=1
    }
    END{exit ok?0:1}'
}

ptxray_defs_day_number() {
  printf '%s\n' "$1" | awk -F- '
    {y=$1+0;m=$2+0;d=$3+0;a=int((14-m)/12);y=y+4800-a;m=m+12*a-3;
     print d+int((153*m+2)/5)+365*y+int(y/4)-int(y/100)+int(y/400)-32045}'
}

ptxray_defs_timestamp_parts() {
  PTXRAY_DEFS_TS=$1
  case "$PTXRAY_DEFS_TS" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) ;;
    *) return 1;;
  esac
  PTXRAY_DEFS_TS_DATE=${PTXRAY_DEFS_TS%%T*}
  ptxray_defs_valid_ymd "$PTXRAY_DEFS_TS_DATE" || return 1
  PTXRAY_DEFS_TS_TIME=${PTXRAY_DEFS_TS#*T}; PTXRAY_DEFS_TS_TIME=${PTXRAY_DEFS_TS_TIME%Z}
  PTXRAY_DEFS_TS_H=${PTXRAY_DEFS_TS_TIME%%:*}
  PTXRAY_DEFS_TS_REST=${PTXRAY_DEFS_TS_TIME#*:}
  PTXRAY_DEFS_TS_M=${PTXRAY_DEFS_TS_REST%%:*}
  PTXRAY_DEFS_TS_S=${PTXRAY_DEFS_TS_REST#*:}
  PTXRAY_DEFS_TS_H=${PTXRAY_DEFS_TS_H#0}; PTXRAY_DEFS_TS_M=${PTXRAY_DEFS_TS_M#0}; PTXRAY_DEFS_TS_S=${PTXRAY_DEFS_TS_S#0}
  [ -n "$PTXRAY_DEFS_TS_H" ] || PTXRAY_DEFS_TS_H=0
  [ -n "$PTXRAY_DEFS_TS_M" ] || PTXRAY_DEFS_TS_M=0
  [ -n "$PTXRAY_DEFS_TS_S" ] || PTXRAY_DEFS_TS_S=0
  [ "$PTXRAY_DEFS_TS_H" -le 23 ] && [ "$PTXRAY_DEFS_TS_M" -le 59 ] \
    && [ "$PTXRAY_DEFS_TS_S" -le 59 ] || return 1
  PTXRAY_DEFS_TS_DAY=$(ptxray_defs_day_number "$PTXRAY_DEFS_TS_DATE") || return 1
  PTXRAY_DEFS_TS_SECOND=$((PTXRAY_DEFS_TS_H*3600+PTXRAY_DEFS_TS_M*60+PTXRAY_DEFS_TS_S))
}

ptxray_defs_safe_dir() {
  PTXRAY_DEFS_DIR=$1
  [ -d "$PTXRAY_DEFS_DIR" ] && [ ! -L "$PTXRAY_DEFS_DIR" ] || return 1
  PTXRAY_DEFS_LS=$(LC_ALL=C ls -ld "$PTXRAY_DEFS_DIR" 2>/dev/null) || return 1
  PTXRAY_DEFS_MODE=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $1}')
  PTXRAY_DEFS_OWNER=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $3}')
  PTXRAY_DEFS_GROUP=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $4}')
  PTXRAY_DEFS_ME=$(id -un 2>/dev/null) || return 1
  [ "$PTXRAY_DEFS_OWNER" = root ] || [ "$PTXRAY_DEFS_OWNER" = bin ] \
    || [ "$PTXRAY_DEFS_OWNER" = QSYS ] || [ "$PTXRAY_DEFS_OWNER" = QSECOFR ] \
    || [ "$PTXRAY_DEFS_OWNER" = "$PTXRAY_DEFS_ME" ] || return 1
  # World-writable directories are never trusted. Group-writable is allowed
  # only when the owner is root and the group is AIX system (gid 0) or IBM i
  # 0, matching IBM's shipped /opt/freeware 775 layout.
  [ "$(printf '%s' "$PTXRAY_DEFS_MODE" | cut -c9)" != w ] || return 1
  if [ "$(printf '%s' "$PTXRAY_DEFS_MODE" | cut -c6)" = w ]; then
    [ "$PTXRAY_DEFS_OWNER" = root ] || return 1
    [ "$PTXRAY_DEFS_GROUP" = system ] || [ "$PTXRAY_DEFS_GROUP" = 0 ] || return 1
  fi
  return 0
}

ptxray_defs_trusted_tool() {
  PTXRAY_DEFS_TOOL=$1
  if [ -L "$PTXRAY_DEFS_TOOL" ]; then
    PTXRAY_DEFS_LS=$(LC_ALL=C ls -l "$PTXRAY_DEFS_TOOL" 2>/dev/null) || return 1
    PTXRAY_DEFS_OWNER=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $3}')
    [ "$PTXRAY_DEFS_OWNER" = root ] || [ "$PTXRAY_DEFS_OWNER" = bin ] \
      || [ "$PTXRAY_DEFS_OWNER" = QSYS ] || [ "$PTXRAY_DEFS_OWNER" = QSECOFR ] \
      || return 1
    PTXRAY_DEFS_LINK_TARGET=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{
      for (i = 1; i <= NF; i++) if ($i == "->") { print $(i+1); exit }
    }')
    case "$PTXRAY_DEFS_LINK_TARGET" in
      ''|.|..|/*|*/*) return 1;;
    esac
    PTXRAY_DEFS_TOOL=$(dirname "$PTXRAY_DEFS_TOOL")/$PTXRAY_DEFS_LINK_TARGET
  fi
  [ -x "$PTXRAY_DEFS_TOOL" ] && [ -f "$PTXRAY_DEFS_TOOL" ] \
    && [ ! -L "$PTXRAY_DEFS_TOOL" ] || return 1
  PTXRAY_DEFS_LS=$(LC_ALL=C ls -ld "$PTXRAY_DEFS_TOOL" 2>/dev/null) || return 1
  PTXRAY_DEFS_MODE=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $1}')
  PTXRAY_DEFS_LINKS=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $2}')
  PTXRAY_DEFS_OWNER=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $3}')
  PTXRAY_DEFS_ME=$(id -un 2>/dev/null) || return 1
  [ "$(printf '%s' "$PTXRAY_DEFS_MODE" | cut -c1)" = - ] \
    && [ "$PTXRAY_DEFS_LINKS" = 1 ] \
    && { [ "$PTXRAY_DEFS_OWNER" = root ] || [ "$PTXRAY_DEFS_OWNER" = bin ] \
         || [ "$PTXRAY_DEFS_OWNER" = QSYS ] || [ "$PTXRAY_DEFS_OWNER" = QSECOFR ] \
         || [ "$PTXRAY_DEFS_OWNER" = "$PTXRAY_DEFS_ME" ]; } \
    && [ "$(printf '%s' "$PTXRAY_DEFS_MODE" | cut -c6)" != w ] \
    && [ "$(printf '%s' "$PTXRAY_DEFS_MODE" | cut -c9)" != w ] || return 1
  PTXRAY_DEFS_TOOL_DIR=$(CDPATH= cd -- "$(dirname "$PTXRAY_DEFS_TOOL")" \
    2>/dev/null && (pwd -P 2>/dev/null || pwd)) || return 1
  while :; do
    ptxray_defs_safe_dir "$PTXRAY_DEFS_TOOL_DIR" || return 1
    if [ "$PTXRAY_DEFS_TOOL_DIR" = / ]; then
      printf '%s\n' "$PTXRAY_DEFS_TOOL"
      return 0
    fi
    PTXRAY_DEFS_TOOL_PARENT=${PTXRAY_DEFS_TOOL_DIR%/*}
    [ -n "$PTXRAY_DEFS_TOOL_PARENT" ] || PTXRAY_DEFS_TOOL_PARENT=/
    [ "$PTXRAY_DEFS_TOOL_PARENT" != "$PTXRAY_DEFS_TOOL_DIR" ] || return 1
    PTXRAY_DEFS_TOOL_DIR=$PTXRAY_DEFS_TOOL_PARENT
  done
}

# Run snapshots may live below a sticky temporary directory. Sticky writable
# ancestors are safe for an owner-owned child because other users cannot rename
# that child; a writable non-sticky ancestor is rejected.
ptxray_defs_private_ancestry_safe() {
  PTXRAY_DEFS_ANCESTOR=$1
  case "$PTXRAY_DEFS_ANCESTOR" in /*) ;; *) return 1;; esac
  while :; do
    [ -d "$PTXRAY_DEFS_ANCESTOR" ] && [ ! -L "$PTXRAY_DEFS_ANCESTOR" ] \
      || return 1
    PTXRAY_DEFS_ANCESTOR_LS=$(LC_ALL=C ls -ld "$PTXRAY_DEFS_ANCESTOR" \
      2>/dev/null) || return 1
    PTXRAY_DEFS_ANCESTOR_MODE=$(printf '%s\n' "$PTXRAY_DEFS_ANCESTOR_LS" \
      | awk '{print $1}')
    PTXRAY_DEFS_ANCESTOR_OWNER=$(printf '%s\n' "$PTXRAY_DEFS_ANCESTOR_LS" \
      | awk '{print $3}')
    PTXRAY_DEFS_ME=$(id -un 2>/dev/null) || return 1
    [ "$PTXRAY_DEFS_ANCESTOR_OWNER" = root ] \
      || [ "$PTXRAY_DEFS_ANCESTOR_OWNER" = bin ] \
      || [ "$PTXRAY_DEFS_ANCESTOR_OWNER" = QSYS ] \
      || [ "$PTXRAY_DEFS_ANCESTOR_OWNER" = QSECOFR ] \
      || [ "$PTXRAY_DEFS_ANCESTOR_OWNER" = "$PTXRAY_DEFS_ME" ] || return 1
    PTXRAY_DEFS_ANCESTOR_GROUP=$(printf '%s' "$PTXRAY_DEFS_ANCESTOR_MODE" \
      | cut -c6)
    PTXRAY_DEFS_ANCESTOR_OTHER=$(printf '%s' "$PTXRAY_DEFS_ANCESTOR_MODE" \
      | cut -c9)
    if [ "$PTXRAY_DEFS_ANCESTOR_GROUP" = w ] \
        || [ "$PTXRAY_DEFS_ANCESTOR_OTHER" = w ]; then
      case "$(printf '%s' "$PTXRAY_DEFS_ANCESTOR_MODE" | cut -c10)" in
        t|T) ;;
        *) return 1;;
      esac
    fi
    [ "$PTXRAY_DEFS_ANCESTOR" = / ] && return 0
    PTXRAY_DEFS_ANCESTOR_PARENT=${PTXRAY_DEFS_ANCESTOR%/*}
    [ -n "$PTXRAY_DEFS_ANCESTOR_PARENT" ] || PTXRAY_DEFS_ANCESTOR_PARENT=/
    [ "$PTXRAY_DEFS_ANCESTOR_PARENT" != "$PTXRAY_DEFS_ANCESTOR" ] || return 1
    PTXRAY_DEFS_ANCESTOR=$PTXRAY_DEFS_ANCESTOR_PARENT
  done
}

# Cached trust inputs are created mode 0600 and must remain single-link regular
# files owned by the privileged caller (or root).  The identity string lets a
# caller prove that the same directory entry survived a bounded read.
ptxray_defs_cache_file_identity() {
  PTXRAY_DEFS_FILE=$1
  [ -f "$PTXRAY_DEFS_FILE" ] && [ ! -L "$PTXRAY_DEFS_FILE" ] \
    && [ -r "$PTXRAY_DEFS_FILE" ] || return 1
  PTXRAY_DEFS_LS=$(LC_ALL=C ls -ldi "$PTXRAY_DEFS_FILE" 2>/dev/null) || return 1
  PTXRAY_DEFS_INODE=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $1}')
  PTXRAY_DEFS_MODE=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $2}')
  PTXRAY_DEFS_LINKS=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $3}')
  PTXRAY_DEFS_OWNER=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $4}')
  PTXRAY_DEFS_SIZE=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $6}')
  PTXRAY_DEFS_ME=$(id -un 2>/dev/null) || return 1
  case "$PTXRAY_DEFS_INODE:$PTXRAY_DEFS_LINKS:$PTXRAY_DEFS_SIZE" in
    *[!0-9:]*|::*|*:|:) return 1;;
  esac
  [ "$(printf '%s' "$PTXRAY_DEFS_MODE" | cut -c1-10)" = '-rw-------' ] \
    && [ "$PTXRAY_DEFS_LINKS" = 1 ] \
    && { [ "$PTXRAY_DEFS_OWNER" = root ] \
         || [ "$PTXRAY_DEFS_OWNER" = "$PTXRAY_DEFS_ME" ]; } || return 1
  printf '%s|%s|%s|%s\n' "$PTXRAY_DEFS_INODE" "$PTXRAY_DEFS_SIZE" \
    "$PTXRAY_DEFS_OWNER" "$(printf '%s' "$PTXRAY_DEFS_MODE" | cut -c1-10)"
}

ptxray_defs_cache_dir_identity() {
  PTXRAY_DEFS_DIR=$1
  [ -d "$PTXRAY_DEFS_DIR" ] && [ ! -L "$PTXRAY_DEFS_DIR" ] || return 1
  PTXRAY_DEFS_LS=$(LC_ALL=C ls -ldi "$PTXRAY_DEFS_DIR" 2>/dev/null) || return 1
  PTXRAY_DEFS_INODE=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $1}')
  PTXRAY_DEFS_MODE=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $2}')
  PTXRAY_DEFS_OWNER=$(printf '%s\n' "$PTXRAY_DEFS_LS" | awk '{print $4}')
  PTXRAY_DEFS_ME=$(id -un 2>/dev/null) || return 1
  case "$PTXRAY_DEFS_INODE" in ''|*[!0-9]*) return 1;; esac
  [ "$(printf '%s' "$PTXRAY_DEFS_MODE" | cut -c1-10)" = 'drwx------' ] \
    && { [ "$PTXRAY_DEFS_OWNER" = root ] \
         || [ "$PTXRAY_DEFS_OWNER" = "$PTXRAY_DEFS_ME" ]; } || return 1
  printf '%s|%s|%s\n' "$PTXRAY_DEFS_INODE" "$PTXRAY_DEFS_OWNER" \
    "$(printf '%s' "$PTXRAY_DEFS_MODE" | cut -c1-10)"
}

ptxray_defs_prepare_cache() {
  PTXRAY_DEFS_PARENT=${PTXRAY_DEFS_CACHE%/*}
  [ -n "$PTXRAY_DEFS_PARENT" ] || PTXRAY_DEFS_PARENT=/
  if [ ! -e "$PTXRAY_DEFS_PARENT" ]; then
    PTXRAY_DEFS_GRAND=${PTXRAY_DEFS_PARENT%/*}; [ -n "$PTXRAY_DEFS_GRAND" ] || PTXRAY_DEFS_GRAND=/
    ptxray_defs_safe_dir "$PTXRAY_DEFS_GRAND" || return 1
    mkdir -m 700 "$PTXRAY_DEFS_PARENT" 2>/dev/null || return 1
  fi
  ptxray_defs_safe_dir "$PTXRAY_DEFS_PARENT" || return 1
  if [ ! -e "$PTXRAY_DEFS_CACHE" ]; then
    mkdir -m 700 "$PTXRAY_DEFS_CACHE" 2>/dev/null || return 1
  fi
  ptxray_defs_safe_dir "$PTXRAY_DEFS_CACHE" || return 1
  chmod 700 "$PTXRAY_DEFS_CACHE" 2>/dev/null || return 1
  if [ ! -e "$PTXRAY_DEFS_CACHE/generations" ]; then
    mkdir -m 700 "$PTXRAY_DEFS_CACHE/generations" 2>/dev/null || return 1
  fi
  ptxray_defs_safe_dir "$PTXRAY_DEFS_CACHE/generations" || return 1
}

ptxray_defs_make_work() {
  ptxray_defs_prepare_cache || return 1
  PTXRAY_DEFS_TRIES=0
  while [ "$PTXRAY_DEFS_TRIES" -lt 20 ]; do
    PTXRAY_DEFS_TOKEN=$(od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -dc 0-9a-f)
    [ -n "$PTXRAY_DEFS_TOKEN" ] || PTXRAY_DEFS_TOKEN="$$.$PTXRAY_DEFS_TRIES"
    PTXRAY_DEFS_WORK="$PTXRAY_DEFS_CACHE/.work.$PTXRAY_DEFS_TOKEN"
    if mkdir -m 700 "$PTXRAY_DEFS_WORK" 2>/dev/null; then return 0; fi
    PTXRAY_DEFS_TRIES=$((PTXRAY_DEFS_TRIES+1))
  done
  PTXRAY_DEFS_WORK=
  return 1
}

ptxray_defs_copy_bounded() {
  PTXRAY_DEFS_INPUT=$1; PTXRAY_DEFS_OUTPUT=$2; PTXRAY_DEFS_LIMIT=$3
  [ -f "$PTXRAY_DEFS_INPUT" ] && [ ! -L "$PTXRAY_DEFS_INPUT" ] \
    && [ -r "$PTXRAY_DEFS_INPUT" ] || return 1
  case "$PTXRAY_DEFS_LIMIT" in ''|*[!0-9]*) return 1;; esac
  [ "$PTXRAY_DEFS_LIMIT" -gt 0 ] || return 1
  if [ "$PTXRAY_DEFS_LIMIT" -le 4096 ]; then
    PTXRAY_DEFS_COPY_BS=1
    PTXRAY_DEFS_COPY_COUNT=$((PTXRAY_DEFS_LIMIT+1))
  else
    PTXRAY_DEFS_COPY_BS=1048576
    PTXRAY_DEFS_COPY_COUNT=$((PTXRAY_DEFS_LIMIT/PTXRAY_DEFS_COPY_BS+1))
  fi
  dd if="$PTXRAY_DEFS_INPUT" of="$PTXRAY_DEFS_OUTPUT" \
    bs="$PTXRAY_DEFS_COPY_BS" count="$PTXRAY_DEFS_COPY_COUNT" 2>/dev/null \
    || return 1
  PTXRAY_DEFS_SIZE=$(wc -c <"$PTXRAY_DEFS_OUTPUT" 2>/dev/null | tr -d ' ')
  case "$PTXRAY_DEFS_SIZE" in ''|*[!0-9]*) return 1;; esac
  [ "$PTXRAY_DEFS_SIZE" -gt 0 ] && [ "$PTXRAY_DEFS_SIZE" -le "$PTXRAY_DEFS_LIMIT" ]
}

ptxray_defs_sha256() {
  "$PTXRAY_DEFS_OPENSSL" dgst -sha256 -r "$1" 2>/dev/null | awk '{print $1}'
}

ptxray_defs_key_id() {
  "$PTXRAY_DEFS_OPENSSL" pkey -pubin -in "$1" -outform DER 2>/dev/null \
    | "$PTXRAY_DEFS_OPENSSL" dgst -sha256 -r 2>/dev/null \
    | awk '{print "sha256:" $1}'
}

ptxray_defs_validate_apar() {
  awk '
    function split_csv(rec,f, i,c,n,v,q){n=1;v="";q=0
      for(i=1;i<=length(rec);i++){c=substr(rec,i,1)
        if(q){if(c=="\""){if(substr(rec,i+1,1)=="\""){v=v "\"";i++}else q=0}else v=v c}
        else if(c=="\"")q=1;else if(c==","){f[n++]=v;v=""}else v=v c}
      if(q)return 0;f[n]=v;return n}
    BEGIN{header="type,product,versions,abstract,apars,fixedIn,ifixes,bulletinUrl,filesets,issued,updated,siblings,download,cvss,reboot"}
    {line=$0;sub(/\r$/, "", line);if(buf!="")buf=buf "\n" line;else buf=line
      q=0;t=buf;gsub(/\"\"/,"",t);for(i=1;i<=length(t);i++)if(substr(t,i,1)=="\"")q++
      if(q%2)next
      rec++;n=split_csv(buf,f);buf="";if(!n){bad=1;next}
      if(rec==1){if(line!=header)bad=1;next}
      if(rec==2){if(n!=2||length(f[1])>64||f[1]!~/^[A-Za-z0-9][A-Za-z0-9._+-]*$/||f[2]!~/^[0-9][0-9][0-9][0-9][.][0-9][0-9][.][0-9][0-9]$/)bad=1;else{version=f[1];asof=f[2];gsub(/[.]/,"-",asof)};next}
      if(n!=15)bad=1;else rows++}
    END{if(buf!=""||bad||rec<3||rows<1)exit 1;print version "|" asof}' "$1"
}

ptxray_defs_validate_kev() {
  awk -v cveout="$2" '
    function fail(){bad=1;exit 1}
    function realdate(v, a,y,m,d,dim,leap){
      if(v!~/^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/)return 0
      split(v,a,"-");y=a[1]+0;m=a[2]+0;d=a[3]+0
      if(m<1||m>12)return 0
      dim=31;if(m==4||m==6||m==9||m==11)dim=30
      if(m==2){leap=(y%400==0||(y%4==0&&y%100!=0));dim=leap?29:28}
      return d>=1&&d<=dim
    }
    function cve(v, tail){
      if(v!~/^CVE-[0-9][0-9][0-9][0-9]-[0-9]+$/)return 0
      tail=v;sub(/^CVE-[0-9][0-9][0-9][0-9]-/,"",tail)
      return length(tail)>=4&&length(tail)<=7
    }
    function utc(v, date,time,frac,a){
      if(v!~/^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]([.][0-9]+)?Z$/)return 0
      date=substr(v,1,10);time=substr(v,12,8);split(time,a,":")
      return realdate(date)&&a[1]+0<=23&&a[2]+0<=59&&a[3]+0<=59
    }
    function mark(k){if(seen[depth SUBSEP k]++)fail();key[depth]=k}
    function object_scalar(kind,v, k,allowed,dotted){
      k=key[depth]
      if(depth==1){
        allowed=" title catalogVersion dateReleased count vulnerabilities "
        if(index(allowed," " k " ")==0||k=="vulnerabilities")fail()
        got_top[k]=1
        if(k=="title"){if(kind!="S"||v=="")fail()}
        else if(k=="catalogVersion"){
          if(kind!="S"||v!~/^[0-9][0-9][0-9][0-9][.][0-9][0-9][.][0-9][0-9]$/)fail()
          dotted=v;gsub(/[.]/,"-",dotted);if(!realdate(dotted))fail();version=v
        } else if(k=="dateReleased"){
          if(kind!="S"||!utc(v))fail();released=substr(v,1,10)
        } else if(k=="count"){
          if(kind!="N"||v!~/^(0|[1-9][0-9]*)$/)fail();declared=v+0
        }
      } else if(vuln[depth]){
        allowed=" cveID vendorProject product vulnerabilityName dateAdded shortDescription requiredAction dueDate knownRansomwareCampaignUse notes cwes "
        if(index(allowed," " k " ")==0||k=="cwes"||kind!="S")fail()
        got[depth SUBSEP k]=1
        if(k=="cveID"){
          if(!cve(v)||cves[v]++)fail();vcve[depth]=v
        } else if(k=="dateAdded"||k=="dueDate"){
          if(!realdate(v))fail()
        } else if(k!="notes"&&v=="")fail()
      } else fail()
    }
    function scalar(kind,v){
      if(depth<1)fail()
      if(type[depth]=="O"){
        if(state[depth]!=2)fail();object_scalar(kind,v);state[depth]=3
      } else {
        if(state[depth]!=0)fail()
        if(!cwes_array[depth]||kind!="S"||v=="")fail()
        cwes_count[depth]++;state[depth]=1
      }
    }
    function begin(kind, parentkey,isv){
      isv=0
      if(depth==0){if(root_seen++||kind!="O")fail()}
      else if(type[depth]=="O"){
        if(state[depth]!=2)fail();parentkey=key[depth]
        if(depth==1){
          if(parentkey!="vulnerabilities"||kind!="A")fail()
          got_top[parentkey]=1;vuln_array_depth=depth+1
        } else if(vuln[depth]){
          if(parentkey!="cwes"||kind!="A")fail()
          got[depth SUBSEP parentkey]=1;cwes_parent=depth
        } else fail()
        state[depth]=3
      } else {
        if(state[depth]!=0)fail()
        if(depth==vuln_array_depth){if(kind!="O")fail();isv=1}
        else fail()
        state[depth]=1
      }
      depth++;type[depth]=kind;state[depth]=0
      if(isv)vuln[depth]=1
      if(cwes_parent==depth-1&&kind=="A"){cwes_array[depth]=1;cwes_parent=0}
    }
    function end_container(kind, k,required,n,a,parent){
      if(depth<1||type[depth]!=kind)fail()
      if(kind=="O"&&state[depth]!=0&&state[depth]!=3)fail()
      if(kind=="A"&&state[depth]!=0&&state[depth]!=1)fail()
      if(vuln[depth]){
        required="cveID vendorProject product vulnerabilityName dateAdded shortDescription requiredAction dueDate knownRansomwareCampaignUse notes cwes"
        n=split(required,a," ");for(k=1;k<=n;k++)if(!got[depth SUBSEP a[k]])fail()
        if(vcve[depth]=="")fail();actual++
      }
      if(depth==1){
        required="title catalogVersion dateReleased count vulnerabilities"
        n=split(required,a," ");for(k=1;k<=n;k++)if(!got_top[a[k]])fail()
      }
      for(k in seen)if(index(k,depth SUBSEP)==1)delete seen[k]
      for(k in got)if(index(k,depth SUBSEP)==1)delete got[k]
      delete type[depth];delete state[depth];delete key[depth];delete vuln[depth]
      delete vcve[depth];delete cwes_array[depth];delete cwes_count[depth]
      depth--
    }
    function emit_token(kind,v,want){
      if(kind=="{")begin("O")
      else if(kind=="[")begin("A")
      else if(kind=="}")end_container("O")
      else if(kind=="]")end_container("A")
      else if(kind==","){
        want=1;if(type[depth]=="O")want=3
        if(depth<1||state[depth]!=want)fail();state[depth]=0
      } else if(kind==":"){
        if(depth<1||type[depth]!="O"||state[depth]!=1)fail();state[depth]=2
      } else if(kind=="S"){
        if(depth>0&&type[depth]=="O"&&state[depth]==0){mark(v);state[depth]=1}
        else scalar("S",v)
      } else scalar(kind,v)
    }
    function hex4(v){return v~/^[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]$/}
    {
      data=$0 "\n";i=1
      while(i<=length(data)){
        c=substr(data,i,1)
        if(mode=="S"){
          if(esc){
            if(c=="u"){u=substr(data,i+1,4);if(length(u)!=4||!hex4(u))fail();s=s "?";i+=5;esc=0;continue}
            if(index("\"\\/bfnrt",c)==0)fail();s=s c;esc=0;i++;continue
          }
          if(c=="\\"){esc=1;i++;continue}
          if(c=="\""){mode="";emit_token("S",s);s="";i++;continue}
          if(c=="\n"||c=="\r"||c=="\t")fail()
          s=s c;i++;continue
        }
        if(mode=="N"){
          if(c~/[0-9eE+.-]/){num=num c;i++;continue}
          if(num!~/^-?(0|[1-9][0-9]*)([.][0-9]+)?([eE][+-]?[0-9]+)?$/)fail()
          mode="";emit_token("N",num);num="";continue
        }
        if(mode=="L"){
          if(c~/[A-Za-z]/){lit=lit c;i++;continue}
          if(lit!="true"&&lit!="false"&&lit!="null")fail()
          mode="";emit_token("L",lit);lit="";continue
        }
        if(c~/[ \t\r\n]/){i++;continue}
        if(c=="\""){mode="S";s="";i++;continue}
        if(c~/[-0-9]/){mode="N";num=c;i++;continue}
        if(c~/[tfn]/){mode="L";lit=c;i++;continue}
        if(index("{}[],:",c)>0){emit_token(c);i++;continue}
        fail()
      }
    }
    END{
      if(bad||mode!=""||depth!=0||!root_seen||declared!=actual||actual<1)exit 1
      for(v in cves)print v > cveout
      print version "|" released
    }' "$1"
}

ptxray_defs_parse_authenticated() {
  PTXRAY_DEFS_FILE=$1
  PTXRAY_DEFS_BAD=$(LC_ALL=C tr -d '\n\040-\176' <"$PTXRAY_DEFS_FILE" | wc -c | tr -d ' ')
  [ "$PTXRAY_DEFS_BAD" -eq 0 ] || return 1
  PTXRAY_DEFS_LAST=$(tail -c 1 "$PTXRAY_DEFS_FILE" 2>/dev/null | od -An -tx1 | tr -dc 0-9a-f)
  [ "$PTXRAY_DEFS_LAST" = 0a ] || return 1
  PTXRAY_DEFS_FOOTER=$(tail -n 1 "$PTXRAY_DEFS_FILE")
  PTXRAY_DEFS_DECLARED=$(printf '%s\n' "$PTXRAY_DEFS_FOOTER" | awk -F'|' '
    function hex64(s, i,c){if(length(s)!=64)return 0;for(i=1;i<=64;i++){c=substr(s,i,1);if(c!~/[0-9a-f]/)return 0}return 1}
    NF==3&&$1=="END-BUNDLE"&&$2=="1"&&hex64($3){print $3}')
  [ -n "$PTXRAY_DEFS_DECLARED" ] || return 1
  sed '$d' "$PTXRAY_DEFS_FILE" >"$PTXRAY_DEFS_WORK/preceding" || return 1
  [ "$(ptxray_defs_sha256 "$PTXRAY_DEFS_WORK/preceding")" = "$PTXRAY_DEFS_DECLARED" ] || return 1
  awk -F'|' -v out="$PTXRAY_DEFS_WORK" -v maxe="$PTXRAY_DEFS_MAX_ENCODED" -v maxd="$PTXRAY_DEFS_MAX_PAYLOAD" '
    function digits(s, i){if(s==""||s~/[^0-9]/)return 0;if(length(s)>1&&substr(s,1,1)=="0")return 0;return 1}
    function positive(s){return s~/^[1-9][0-9]*$/}
    function hex64(s, i,c){if(length(s)!=64)return 0;for(i=1;i<=64;i++){c=substr(s,i,1);if(c!~/[0-9a-f]/)return 0}return 1}
    function bad(){failed=1;exit 1}
    NR==1{if($0!="PTXRAY-DEFINITION-BUNDLE|1")bad();next}
    NR==2{if(NF!=2||$1!="KEY-ID"||$2!~/^sha256:/||length($2)!=71||!hex64(substr($2,8)))bad();key=$2;next}
    NR==3{if(NF!=2||$1!="SEQUENCE"||!positive($2)||length($2)>18)bad();seq=$2;next}
    NR==4{if(NF!=2||$1!="CREATED-AT")bad();created=$2;next}
    NR==5{if($0!="SOURCE-COUNT|2")bad();next}
    $1=="SOURCE"{if(block||++sources>2||NF!=7)bad();want=sources==1?"cisa-kev":"ibm-apar-csv";if($2!=want||$3==""||$4==""||!digits($5)||!digits($6)||$5+0>maxe||$6+0>maxd||!hex64($7))bad();id[sources]=$2;version[sources]=$3;asof[sources]=$4;encoded[sources]=$5;decoded[sources]=$6;digest[sources]=$7;next}
    $1=="BEGIN-PAYLOAD"{if(NF!=2||block||sources<1||$2!=id[sources])bad();block=1;linecount=0;count=0;next}
    $1=="END-PAYLOAD"{if(NF!=2||!block||$2!=id[sources]||linecount<1||count!=encoded[sources])bad();block=0;closed++;next}
    $1=="END-BUNDLE"{if(NF!=3||block||sources!=2||closed!=2||footer++)bad();next}
    {if(!block||$0!~/^[A-Za-z0-9+\/=]+$/||length($0)<1||length($0)>64||(linecount>0&&lastlen!=64))bad();print $0 >> (out "/payload-" sources ".b64");count+=length($0);lastlen=length($0);linecount++;next}
    END{if(failed||NR<12||footer!=1||block||sources!=2||closed!=2)exit 1;print key "|" seq "|" created "|" version[1] "|" asof[1] "|" encoded[1] "|" decoded[1] "|" digest[1] "|" version[2] "|" asof[2] "|" encoded[2] "|" decoded[2] "|" digest[2] > (out "/metadata")}' "$PTXRAY_DEFS_FILE" || return 1
  IFS='|' read PTXRAY_DEFS_KEY_ID PTXRAY_DEFS_SEQUENCE PTXRAY_DEFS_CREATED \
    PTXRAY_DEFS_KEV_VERSION PTXRAY_DEFS_KEV_ASOF PTXRAY_DEFS_KEV_ENCODED PTXRAY_DEFS_KEV_BYTES PTXRAY_DEFS_KEV_SHA \
    PTXRAY_DEFS_APAR_VERSION PTXRAY_DEFS_APAR_ASOF PTXRAY_DEFS_APAR_ENCODED PTXRAY_DEFS_APAR_BYTES PTXRAY_DEFS_APAR_SHA \
    <"$PTXRAY_DEFS_WORK/metadata" || return 1
  for PTXRAY_DEFS_N in 1 2; do
    tr -d '\n' <"$PTXRAY_DEFS_WORK/payload-$PTXRAY_DEFS_N.b64" \
      | "$PTXRAY_DEFS_OPENSSL" base64 -d -A \
          -out "$PTXRAY_DEFS_WORK/payload-$PTXRAY_DEFS_N" 2>/dev/null || return 1
    "$PTXRAY_DEFS_OPENSSL" base64 -A \
      -in "$PTXRAY_DEFS_WORK/payload-$PTXRAY_DEFS_N" \
      -out "$PTXRAY_DEFS_WORK/payload-$PTXRAY_DEFS_N.reencoded" 2>/dev/null || return 1
    tr -d '\n' <"$PTXRAY_DEFS_WORK/payload-$PTXRAY_DEFS_N.reencoded" \
      >"$PTXRAY_DEFS_WORK/payload-$PTXRAY_DEFS_N.reencoded.tmp" || return 1
    mv "$PTXRAY_DEFS_WORK/payload-$PTXRAY_DEFS_N.reencoded.tmp" \
      "$PTXRAY_DEFS_WORK/payload-$PTXRAY_DEFS_N.reencoded" || return 1
    tr -d '\n' <"$PTXRAY_DEFS_WORK/payload-$PTXRAY_DEFS_N.b64" \
      >"$PTXRAY_DEFS_WORK/payload-$PTXRAY_DEFS_N.canon" || return 1
    cmp -s "$PTXRAY_DEFS_WORK/payload-$PTXRAY_DEFS_N.reencoded" \
      "$PTXRAY_DEFS_WORK/payload-$PTXRAY_DEFS_N.canon" || return 1
  done
  [ "$(wc -c <"$PTXRAY_DEFS_WORK/payload-1" | tr -d ' ')" = "$PTXRAY_DEFS_KEV_BYTES" ] \
    && [ "$(ptxray_defs_sha256 "$PTXRAY_DEFS_WORK/payload-1")" = "$PTXRAY_DEFS_KEV_SHA" ] || return 1
  [ "$(wc -c <"$PTXRAY_DEFS_WORK/payload-2" | tr -d ' ')" = "$PTXRAY_DEFS_APAR_BYTES" ] \
    && [ "$(ptxray_defs_sha256 "$PTXRAY_DEFS_WORK/payload-2")" = "$PTXRAY_DEFS_APAR_SHA" ] || return 1
  for PTXRAY_DEFS_DATA in "$PTXRAY_DEFS_WORK/payload-1" "$PTXRAY_DEFS_WORK/payload-2"; do
    PTXRAY_DEFS_PREFIX=$(dd if="$PTXRAY_DEFS_DATA" bs=2 count=1 2>/dev/null)
    case "$PTXRAY_DEFS_PREFIX" in '#!'|MZ) return 1;; esac
    PTXRAY_DEFS_MAGIC=$(od -An -N4 -tx1 "$PTXRAY_DEFS_DATA" 2>/dev/null | tr -d ' \n')
    [ "$PTXRAY_DEFS_MAGIC" != 7f454c46 ] || return 1
    PTXRAY_DEFS_NUL=$(od -An -tx1 "$PTXRAY_DEFS_DATA" 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="00"){print 1;exit}}')
    [ -z "$PTXRAY_DEFS_NUL" ] || return 1
  done
  ptxray_defs_validate_kev \
    "$PTXRAY_DEFS_WORK/payload-1" \
    "$PTXRAY_DEFS_WORK/cisa-kev-cves.unsorted" \
    >"$PTXRAY_DEFS_WORK/kev-meta" || return 1
  IFS= read -r PTXRAY_DEFS_KEV_META <"$PTXRAY_DEFS_WORK/kev-meta" || return 1
  LC_ALL=C sort -u "$PTXRAY_DEFS_WORK/cisa-kev-cves.unsorted" \
    >"$PTXRAY_DEFS_WORK/cisa-kev-cves.txt" || return 1
  rm -f "$PTXRAY_DEFS_WORK/cisa-kev-cves.unsorted" || return 1
  [ -s "$PTXRAY_DEFS_WORK/cisa-kev-cves.txt" ] || return 1
  ptxray_defs_validate_apar "$PTXRAY_DEFS_WORK/payload-2" \
    >"$PTXRAY_DEFS_WORK/apar-meta" || return 1
  IFS= read -r PTXRAY_DEFS_APAR_META <"$PTXRAY_DEFS_WORK/apar-meta" || return 1
  [ "$PTXRAY_DEFS_KEV_META" = "$PTXRAY_DEFS_KEV_VERSION|$PTXRAY_DEFS_KEV_ASOF" ] || return 1
  [ "$PTXRAY_DEFS_APAR_META" = "$PTXRAY_DEFS_APAR_VERSION|$PTXRAY_DEFS_APAR_ASOF" ] || return 1
  ptxray_defs_valid_ymd "$PTXRAY_DEFS_KEV_ASOF" && ptxray_defs_valid_ymd "$PTXRAY_DEFS_APAR_ASOF"
}

ptxray_defs_verify_work() {
  PTXRAY_DEFS_MIN_SEQUENCE=${1:-}
  PTXRAY_DEFS_FAILURE=signature
  [ "$(wc -c <"$PTXRAY_DEFS_WORK/bundle.sig" | tr -d ' ')" -eq "$PTXRAY_DEFS_SIGNATURE_BYTES" ] || return 1
  printf '%s\n' "$PTXRAY_DEFS_CURRENT_PEM" >"$PTXRAY_DEFS_WORK/current.pem"
  printf '%s\n' "$PTXRAY_DEFS_NEXT_PEM" >"$PTXRAY_DEFS_WORK/next.pem"
  [ "$(ptxray_defs_key_id "$PTXRAY_DEFS_WORK/current.pem")" = "$PTXRAY_DEFS_CURRENT_ID" ] || return 1
  [ "$(ptxray_defs_key_id "$PTXRAY_DEFS_WORK/next.pem")" = "$PTXRAY_DEFS_NEXT_ID" ] || return 1
  PTXRAY_DEFS_VERIFIED_KEY=
  if "$PTXRAY_DEFS_OPENSSL" dgst -sha256 -verify "$PTXRAY_DEFS_WORK/current.pem" \
      -signature "$PTXRAY_DEFS_WORK/bundle.sig" -sigopt rsa_padding_mode:pkcs1 \
      "$PTXRAY_DEFS_WORK/bundle" >/dev/null 2>&1; then
    PTXRAY_DEFS_VERIFIED_KEY=$PTXRAY_DEFS_CURRENT_ID
  fi
  if "$PTXRAY_DEFS_OPENSSL" dgst -sha256 -verify "$PTXRAY_DEFS_WORK/next.pem" \
      -signature "$PTXRAY_DEFS_WORK/bundle.sig" -sigopt rsa_padding_mode:pkcs1 \
      "$PTXRAY_DEFS_WORK/bundle" >/dev/null 2>&1; then
    [ -z "$PTXRAY_DEFS_VERIFIED_KEY" ] || return 1
    PTXRAY_DEFS_VERIFIED_KEY=$PTXRAY_DEFS_NEXT_ID
  fi
  [ -n "$PTXRAY_DEFS_VERIFIED_KEY" ] || return 1
  PTXRAY_DEFS_FAILURE=malformed
  ptxray_defs_parse_authenticated "$PTXRAY_DEFS_WORK/bundle" || return 1
  [ "$PTXRAY_DEFS_KEY_ID" = "$PTXRAY_DEFS_VERIFIED_KEY" ] || return 1
  if [ -n "$PTXRAY_DEFS_MIN_SEQUENCE" ]; then
    case "$PTXRAY_DEFS_MIN_SEQUENCE" in ''|*[!0-9]*) return 1;; esac
    if [ "${#PTXRAY_DEFS_SEQUENCE}" -lt "${#PTXRAY_DEFS_MIN_SEQUENCE}" ] \
        || { [ "${#PTXRAY_DEFS_SEQUENCE}" -eq "${#PTXRAY_DEFS_MIN_SEQUENCE}" ] \
             && ptxray_defs_str_lt "$PTXRAY_DEFS_SEQUENCE" "$PTXRAY_DEFS_MIN_SEQUENCE"; }; then
      ptxray_defs_fail rollback
      return $?
    fi
    if [ "$PTXRAY_DEFS_STRICT_MINIMUM" -eq 1 ] \
        && [ "$PTXRAY_DEFS_SEQUENCE" = "$PTXRAY_DEFS_MIN_SEQUENCE" ]; then
      ptxray_defs_fail rollback
      return $?
    fi
  fi
  PTXRAY_DEFS_NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) || return 1
  ptxray_defs_timestamp_parts "$PTXRAY_DEFS_NOW" || return 1
  PTXRAY_DEFS_NOW_DAY=$PTXRAY_DEFS_TS_DAY; PTXRAY_DEFS_NOW_SECOND=$PTXRAY_DEFS_TS_SECOND
  ptxray_defs_timestamp_parts "${PTXRAY_DEFS_TRUST_DATE}T00:00:00Z" || return 1
  [ "$PTXRAY_DEFS_NOW_DAY" -ge "$PTXRAY_DEFS_TS_DAY" ] || return 1
  ptxray_defs_timestamp_parts "$PTXRAY_DEFS_CREATED" || return 1
  PTXRAY_DEFS_CREATED_DAY=$PTXRAY_DEFS_TS_DAY; PTXRAY_DEFS_CREATED_SECOND=$PTXRAY_DEFS_TS_SECOND
  PTXRAY_DEFS_FUTURE=$(( (PTXRAY_DEFS_CREATED_DAY-PTXRAY_DEFS_NOW_DAY)*86400 + PTXRAY_DEFS_CREATED_SECOND-PTXRAY_DEFS_NOW_SECOND ))
  [ "$PTXRAY_DEFS_FUTURE" -le 300 ] || return 1
  PTXRAY_DEFS_KEV_AGE=$((PTXRAY_DEFS_NOW_DAY-$(ptxray_defs_day_number "$PTXRAY_DEFS_KEV_ASOF")))
  PTXRAY_DEFS_APAR_AGE=$((PTXRAY_DEFS_NOW_DAY-$(ptxray_defs_day_number "$PTXRAY_DEFS_APAR_ASOF")))
  [ "$PTXRAY_DEFS_KEV_AGE" -ge 0 ] && [ "$PTXRAY_DEFS_APAR_AGE" -ge 0 ] || return 1
  PTXRAY_DEFS_AGE=$PTXRAY_DEFS_KEV_AGE
  [ "$PTXRAY_DEFS_APAR_AGE" -le "$PTXRAY_DEFS_AGE" ] \
    || PTXRAY_DEFS_AGE=$PTXRAY_DEFS_APAR_AGE
  PTXRAY_DEFS_FRESHNESS=current
  [ "$PTXRAY_DEFS_AGE" -le "$PTXRAY_DEFS_MAX_AGE_DAYS" ] || PTXRAY_DEFS_FRESHNESS=stale
  PTXRAY_DEFS_BUNDLE_SHA=$(ptxray_defs_sha256 "$PTXRAY_DEFS_WORK/bundle") || return 1
  return 0
}

ptxray_defs_verify_pair() {
  PTXRAY_DEFS_INPUT_BUNDLE=$1; PTXRAY_DEFS_INPUT_SIG=$2; PTXRAY_DEFS_INPUT_MIN=${3:-}
  ptxray_defs_make_work || { ptxray_defs_fail unsafe-cache; return $?; }
  ptxray_defs_copy_bounded "$PTXRAY_DEFS_INPUT_BUNDLE" "$PTXRAY_DEFS_WORK/bundle" "$PTXRAY_DEFS_MAX_BUNDLE" \
    || { ptxray_defs_fail malformed; return $?; }
  ptxray_defs_copy_bounded "$PTXRAY_DEFS_INPUT_SIG" "$PTXRAY_DEFS_WORK/bundle.sig" "$PTXRAY_DEFS_SIGNATURE_BYTES" \
    || { ptxray_defs_fail signature; return $?; }
  ptxray_defs_verify_work "$PTXRAY_DEFS_INPUT_MIN"
}

ptxray_defs_emit_ok() {
  if [ "$PTXRAY_DEFS_FRESHNESS" = stale ]; then
    printf 'WARNING: signed definitions are %s days old (limit %s); refresh recommended.\n' \
      "$PTXRAY_DEFS_AGE" "$PTXRAY_DEFS_MAX_AGE_DAYS" >&2
  fi
  printf 'PTXRAY-DEFS|1|ok|%s|sequence=%s|created_at=%s|age_days=%s|freshness=%s|kev_version=%s|kev_as_of=%s|kev_sha256=%s|apar_version=%s|apar_as_of=%s|apar_sha256=%s|generation=%s' \
    "$1" "$PTXRAY_DEFS_SEQUENCE" "$PTXRAY_DEFS_CREATED" "$PTXRAY_DEFS_AGE" \
    "$PTXRAY_DEFS_FRESHNESS" "$PTXRAY_DEFS_KEV_VERSION" "$PTXRAY_DEFS_KEV_ASOF" \
    "$PTXRAY_DEFS_KEV_SHA" "$PTXRAY_DEFS_APAR_VERSION" "$PTXRAY_DEFS_APAR_ASOF" \
    "$PTXRAY_DEFS_APAR_SHA" "$PTXRAY_DEFS_GENERATION"
  [ "$#" -lt 2 ] || printf '|error=%s' "$2"
  printf '\n'
}

ptxray_defs_fetch_one() {
  PTXRAY_DEFS_FETCH_URL=$1; PTXRAY_DEFS_FETCH_OUT=$2; PTXRAY_DEFS_FETCH_LIMIT=$3
  PTXRAY_DEFS_FETCH_BLOCKS=$(( (PTXRAY_DEFS_FETCH_LIMIT+511)/512 ))
  (
    # POSIX/AIX ksh file-size limits cap chunked and unknown-length bodies while
    # bytes are arriving.  If the platform cannot install the cap, no request is
    # made; post-transfer size checks remain a second boundary.
    ulimit -f "$PTXRAY_DEFS_FETCH_BLOCKS" 2>/dev/null || exit 125
    exec "$PTXRAY_DEFS_CURL" --disable \
      --fail --silent --show-error \
      --request GET \
      --proto '=https' \
      --tlsv1.2 \
      --connect-timeout 15 \
      --max-time 60 \
      --max-filesize "$PTXRAY_DEFS_FETCH_LIMIT" \
      --max-redirs 0 \
      --proxy '' \
      --noproxy '*' \
      --user-agent "$PTXRAY_DEFS_USER_AGENT" \
      --output "$PTXRAY_DEFS_FETCH_OUT" \
      "$PTXRAY_DEFS_FETCH_URL"
  )
}

ptxray_defs_fallback() {
  PTXRAY_DEFS_FAILURE=$1
  case "$PTXRAY_DEFS_FAILURE" in
    transport|size-limit|signature|rollback|malformed|unsafe-cache|lock-contention) ;;
    *) PTXRAY_DEFS_FAILURE=malformed;;
  esac
  PTXRAY_DEFS_ORIGINAL_FAILURE=$PTXRAY_DEFS_FAILURE
  ptxray_defs_cleanup
  if ptxray_defs_read_current; then
    ptxray_defs_emit_ok cache-fallback "$PTXRAY_DEFS_ORIGINAL_FAILURE"
    return 0
  fi
  PTXRAY_DEFS_CACHE_FAILURE=$PTXRAY_DEFS_FAILURE
  ptxray_defs_error "definition update failed ($PTXRAY_DEFS_ORIGINAL_FAILURE); valid cache unavailable ($PTXRAY_DEFS_CACHE_FAILURE)"
  return 3
}

# The current pointer is a privileged, owner-only rollback record even when the
# generation it names can no longer be consumed (for example, after a signing
# key retires or an extracted payload is damaged). This reads only that narrow
# record, proves the directory entry did not change, and never trusts cached
# payload bytes. A caller using this floor must require a strictly newer bundle.
ptxray_defs_read_floor() {
  PTXRAY_DEFS_FAILURE=unsafe-cache
  ptxray_defs_prepare_cache || return 1
  PTXRAY_DEFS_FLOOR_POINTER_BEFORE=$(ptxray_defs_cache_file_identity \
    "$PTXRAY_DEFS_CACHE/current") || return 1
  [ "$(wc -l <"$PTXRAY_DEFS_CACHE/current" | tr -d ' ')" -eq 1 ] || return 1
  IFS= read -r PTXRAY_DEFS_FLOOR_GENERATION \
    <"$PTXRAY_DEFS_CACHE/current" || return 1
  [ "$PTXRAY_DEFS_FLOOR_POINTER_BEFORE" = "$(ptxray_defs_cache_file_identity \
    "$PTXRAY_DEFS_CACHE/current")" ] || return 1
  ptxray_defs_valid_generation_name "$PTXRAY_DEFS_FLOOR_GENERATION" || return 1
  PTXRAY_DEFS_FLOOR_SEQUENCE=$(printf '%s\n' \
    "$PTXRAY_DEFS_FLOOR_GENERATION" | awk -F- '{print $2}')
  case "$PTXRAY_DEFS_FLOOR_SEQUENCE" in
    ''|*[!0-9]*) return 1;;
  esac
  return 0
}

ptxray_defs_generations_present() {
  for PTXRAY_DEFS_ENTRY in \
      "$PTXRAY_DEFS_CACHE"/generations/* \
      "$PTXRAY_DEFS_CACHE"/generations/.[!.]* \
      "$PTXRAY_DEFS_CACHE"/generations/..?*; do
    [ -e "$PTXRAY_DEFS_ENTRY" ] || [ -L "$PTXRAY_DEFS_ENTRY" ] || continue
    return 0
  done
  return 1
}

ptxray_defs_load_minimum() {
  PTXRAY_DEFS_MINIMUM=
  PTXRAY_DEFS_STRICT_MINIMUM=0
  if [ ! -e "$PTXRAY_DEFS_CACHE/current" ]; then
    ptxray_defs_prepare_cache || return 1
    if ptxray_defs_generations_present; then
      ptxray_defs_error "definitions generations exist without a current pointer, so no trustworthy rollback floor can be established; normal import is refused. Inspect the protected cache, then explicitly run: $0 --recover-local BUNDLE"
      return 1
    fi
    return 0
  fi
  if ptxray_defs_read_current; then
    PTXRAY_DEFS_MINIMUM=$PTXRAY_DEFS_SEQUENCE
    ptxray_defs_cleanup
    return 0
  fi
  PTXRAY_DEFS_UNUSABLE_FAILURE=$PTXRAY_DEFS_FAILURE
  ptxray_defs_cleanup
  if ptxray_defs_read_floor; then
    PTXRAY_DEFS_MINIMUM=$PTXRAY_DEFS_FLOOR_SEQUENCE
    PTXRAY_DEFS_STRICT_MINIMUM=1
    printf 'WARNING: current signed definitions are unusable (%s); preserving protected rollback floor sequence %s and accepting only a strictly newer signed bundle. Existing generations will not be deleted.\n' \
      "$PTXRAY_DEFS_UNUSABLE_FAILURE" "$PTXRAY_DEFS_MINIMUM" >&2
    return 0
  fi
  ptxray_defs_error "current definitions pointer cannot establish a trustworthy rollback floor; normal import is refused. Inspect the protected cache, then explicitly run: $0 --recover-local BUNDLE"
  return 1
}

ptxray_defs_update() {
  ptxray_defs_load_minimum || return 3
  PTXRAY_DEFS_CURL=$(ptxray_defs_select_curl) \
    || { ptxray_defs_error 'a supported fixed-path curl is unavailable'; return 3; }
  ptxray_defs_make_work \
    || { ptxray_defs_error 'secure definitions cache is unavailable (unsafe-cache)'; return 3; }
  printf '%s\n' \
    'PTxray definitions update will make two fixed public HTTPS GET requests:' \
    "  $PTXRAY_DEFS_BUNDLE_URL" \
    "  $PTXRAY_DEFS_SIGNATURE_URL" \
    "Destination: $PTXRAY_DEFS_CACHE" \
    'There is no request body or upload. PowerTrue and ordinary DNS/TLS infrastructure can observe the source IP, requested host/path, time, TLS metadata, and fixed user agent. Redirects and proxy inheritance are disabled.' >&2
  if ! ptxray_defs_fetch_one "$PTXRAY_DEFS_BUNDLE_URL" "$PTXRAY_DEFS_WORK/bundle" "$PTXRAY_DEFS_MAX_BUNDLE"; then
    ptxray_defs_fallback transport; return $?
  fi
  if ! ptxray_defs_fetch_one "$PTXRAY_DEFS_SIGNATURE_URL" "$PTXRAY_DEFS_WORK/bundle.sig" "$PTXRAY_DEFS_SIGNATURE_BYTES"; then
    ptxray_defs_fallback transport; return $?
  fi
  PTXRAY_DEFS_DOWNLOAD_SIZE=$(wc -c <"$PTXRAY_DEFS_WORK/bundle" 2>/dev/null | tr -d ' ')
  case "$PTXRAY_DEFS_DOWNLOAD_SIZE" in ''|*[!0-9]*) ptxray_defs_fallback size-limit; return $?;; esac
  [ "$PTXRAY_DEFS_DOWNLOAD_SIZE" -gt 0 ] && [ "$PTXRAY_DEFS_DOWNLOAD_SIZE" -le "$PTXRAY_DEFS_MAX_BUNDLE" ] \
    || { ptxray_defs_fallback size-limit; return $?; }
  if ! ptxray_defs_verify_work "$PTXRAY_DEFS_MINIMUM"; then
    ptxray_defs_fallback "$PTXRAY_DEFS_FAILURE"; return $?
  fi
  ptxray_defs_publish_work \
    || { ptxray_defs_fallback "$PTXRAY_DEFS_FAILURE"; return $?; }
  ptxray_defs_emit_ok update
  return 0
}

ptxray_defs_generation_name() {
  printf 'g-%s-%s\n' "$PTXRAY_DEFS_SEQUENCE" "$PTXRAY_DEFS_BUNDLE_SHA"
}

ptxray_defs_valid_generation_name() {
  printf '%s\n' "$1" | awk -F- '
    function hex64(s, i,c){if(length(s)!=64)return 0;for(i=1;i<=64;i++){c=substr(s,i,1);if(c!~/[0-9a-f]/)return 0}return 1}
    NF==3&&$1=="g"&&$2~/^[1-9][0-9]*$/&&length($2)<=18&&hex64($3){ok=1}
    END{exit ok?0:1}'
}

# ksh88 /bin/sh has no string-less test operator. Equal-length lexical less-than.
ptxray_defs_str_lt() {
  [ "$1" != "$2" ] \
    && [ "$(printf '%s\n%s\n' "$1" "$2" | LC_ALL=C sort | head -n 1)" = "$1" ]
}

ptxray_defs_sequence_less() {
  [ "${#1}" -lt "${#2}" ] \
    || { [ "${#1}" -eq "${#2}" ] && ptxray_defs_str_lt "$1" "$2"; }
}

ptxray_defs_acquire_publish_lock() {
  PTXRAY_DEFS_LOCK=$PTXRAY_DEFS_CACHE/.publish.lock
  if ! mkdir -m 700 "$PTXRAY_DEFS_LOCK" 2>/dev/null; then
    if [ -e "$PTXRAY_DEFS_LOCK" ]; then
      ptxray_defs_fail lock-contention
      ptxray_defs_error "definitions publication is locked; if no ptxray-defs.sh process is running, inspect the owner record and run: $0 --recover-lock"
    else
      ptxray_defs_fail unsafe-cache
    fi
    return 1
  fi
  PTXRAY_DEFS_LOCK_HELD=1
  PTXRAY_DEFS_LOCK_ID=$(ptxray_defs_cache_dir_identity "$PTXRAY_DEFS_LOCK") \
    || { ptxray_defs_fail unsafe-cache; return 1; }
  (set -C; umask 077; printf '%s\n' "$$" >"$PTXRAY_DEFS_LOCK/owner") \
    2>/dev/null || { ptxray_defs_fail unsafe-cache; return 1; }
  chmod 600 "$PTXRAY_DEFS_LOCK/owner" 2>/dev/null \
    || { ptxray_defs_fail unsafe-cache; return 1; }
  PTXRAY_DEFS_LOCK_OWNER_ID=$(ptxray_defs_cache_file_identity \
    "$PTXRAY_DEFS_LOCK/owner") \
    || { ptxray_defs_fail unsafe-cache; return 1; }
  [ "$(wc -l <"$PTXRAY_DEFS_LOCK/owner" | tr -d ' ')" -eq 1 ] \
    && [ "$(sed -n '1p' "$PTXRAY_DEFS_LOCK/owner")" = "$$" ] \
    && [ "$PTXRAY_DEFS_LOCK_OWNER_ID" = "$(ptxray_defs_cache_file_identity \
      "$PTXRAY_DEFS_LOCK/owner")" ] \
    && [ "$PTXRAY_DEFS_LOCK_ID" = "$(ptxray_defs_cache_dir_identity \
      "$PTXRAY_DEFS_LOCK")" ] \
    || { ptxray_defs_fail unsafe-cache; return 1; }
}

ptxray_defs_release_publish_lock() {
  [ "$PTXRAY_DEFS_LOCK_HELD" -eq 1 ] || return 1
  [ "$PTXRAY_DEFS_LOCK_ID" = "$(ptxray_defs_cache_dir_identity \
    "$PTXRAY_DEFS_LOCK")" ] || return 1
  [ "$PTXRAY_DEFS_LOCK_OWNER_ID" = "$(ptxray_defs_cache_file_identity \
    "$PTXRAY_DEFS_LOCK/owner")" ] || return 1
  rm -f "$PTXRAY_DEFS_LOCK/owner" 2>/dev/null || return 1
  rmdir "$PTXRAY_DEFS_LOCK" 2>/dev/null || return 1
  PTXRAY_DEFS_LOCK=
  PTXRAY_DEFS_LOCK_HELD=0
  PTXRAY_DEFS_LOCK_ID=
  PTXRAY_DEFS_LOCK_OWNER_ID=
}

ptxray_defs_recover_publish_lock() {
  PTXRAY_DEFS_LOCK=$PTXRAY_DEFS_CACHE/.publish.lock
  ptxray_defs_prepare_cache \
    || { ptxray_defs_error 'secure definitions cache is unavailable (unsafe-cache)'; return 3; }
  [ -e "$PTXRAY_DEFS_LOCK" ] \
    || { ptxray_defs_error 'no definitions publish lock exists; nothing was changed'; return 3; }
  PTXRAY_DEFS_RECOVER_LOCK_ID=$(ptxray_defs_cache_dir_identity \
    "$PTXRAY_DEFS_LOCK") \
    || { ptxray_defs_error 'publish lock is not a safe owner-only directory; recovery refused'; return 3; }
  PTXRAY_DEFS_RECOVER_CONTENTS=$(LC_ALL=C ls -a "$PTXRAY_DEFS_LOCK" \
    2>/dev/null | awk '$0!="."&&$0!=".."{n++;if($0=="owner")o++}END{print n+0 "|" o+0}') \
    || { ptxray_defs_error 'publish lock contents cannot be inspected; recovery refused'; return 3; }
  case "$PTXRAY_DEFS_RECOVER_CONTENTS" in
    '0|0')
      # A publisher removed in this tiny initialization window cannot proceed:
      # its mandatory owner-file creation and lock-identity recheck fail closed.
      [ "$PTXRAY_DEFS_RECOVER_LOCK_ID" = "$(ptxray_defs_cache_dir_identity \
        "$PTXRAY_DEFS_LOCK")" ] \
        && rmdir "$PTXRAY_DEFS_LOCK" 2>/dev/null \
        || { ptxray_defs_error 'incomplete publish lock changed during recovery; recovery refused'; return 3; }
      ;;
    '1|1')
      PTXRAY_DEFS_RECOVER_OWNER_ID=$(ptxray_defs_cache_file_identity \
        "$PTXRAY_DEFS_LOCK/owner") \
        || { ptxray_defs_error 'publish lock owner record is unsafe or ambiguous; recovery refused'; return 3; }
      [ "$(wc -l <"$PTXRAY_DEFS_LOCK/owner" | tr -d ' ')" -eq 1 ] \
        || { ptxray_defs_error 'publish lock owner record is malformed or ambiguous; recovery refused'; return 3; }
      IFS= read -r PTXRAY_DEFS_RECOVER_PID <"$PTXRAY_DEFS_LOCK/owner" \
        || { ptxray_defs_error 'publish lock owner record cannot be read; recovery refused'; return 3; }
      case "$PTXRAY_DEFS_RECOVER_PID" in
        ''|0|*[!0-9]*)
          ptxray_defs_error 'publish lock owner PID is malformed or ambiguous; recovery refused'
          return 3
          ;;
      esac
      [ "${#PTXRAY_DEFS_RECOVER_PID}" -le 10 ] \
        || { ptxray_defs_error 'publish lock owner PID is malformed or ambiguous; recovery refused'; return 3; }
      if kill -0 "$PTXRAY_DEFS_RECOVER_PID" 2>/dev/null; then
        ptxray_defs_error "publish lock has active owner PID $PTXRAY_DEFS_RECOVER_PID; recovery refused"
        return 3
      fi
      [ "$PTXRAY_DEFS_RECOVER_OWNER_ID" = "$(ptxray_defs_cache_file_identity \
        "$PTXRAY_DEFS_LOCK/owner")" ] \
        && [ "$PTXRAY_DEFS_RECOVER_LOCK_ID" = "$(ptxray_defs_cache_dir_identity \
          "$PTXRAY_DEFS_LOCK")" ] \
        || { ptxray_defs_error 'publish lock changed during recovery; recovery refused'; return 3; }
      rm -f "$PTXRAY_DEFS_LOCK/owner" 2>/dev/null \
        && rmdir "$PTXRAY_DEFS_LOCK" 2>/dev/null \
        || { ptxray_defs_error 'stale publish lock could not be removed safely'; return 3; }
      ;;
    *)
      ptxray_defs_error 'publish lock contains unexpected or ambiguous entries; recovery refused'
      return 3
      ;;
  esac
  PTXRAY_DEFS_LOCK=
  printf '%s\n' 'PTXRAY-DEFS|1|recovered|publish-lock'
  return 0
}

ptxray_defs_publish_locked() {
  PTXRAY_DEFS_FAILURE=unsafe-cache
  # Re-read the pointer only after exclusive publication begins.  This closes
  # the verify-N / publish-N race between concurrent updater processes.
  if [ "$PTXRAY_DEFS_RESET_FLOOR" -eq 1 ]; then
    if [ "$PTXRAY_DEFS_RECOVERY_POINTER" = absent ]; then
      [ ! -e "$PTXRAY_DEFS_CACHE/current" ] || { PTXRAY_DEFS_FAILURE=rollback; return 1; }
    else
      [ "$PTXRAY_DEFS_RECOVERY_POINTER" = "$(ptxray_defs_cache_file_identity \
        "$PTXRAY_DEFS_CACHE/current")" ] || return 1
      [ "$PTXRAY_DEFS_RECOVERY_POINTER_SHA" = "$(ptxray_defs_sha256 \
        "$PTXRAY_DEFS_CACHE/current")" ] || return 1
      [ "$PTXRAY_DEFS_RECOVERY_POINTER" = "$(ptxray_defs_cache_file_identity \
        "$PTXRAY_DEFS_CACHE/current")" ] || return 1
    fi
  elif [ -e "$PTXRAY_DEFS_CACHE/current" ]; then
    PTXRAY_DEFS_RECHECK_BEFORE=$(ptxray_defs_cache_file_identity \
      "$PTXRAY_DEFS_CACHE/current") || return 1
    [ "$(wc -l <"$PTXRAY_DEFS_CACHE/current" | tr -d ' ')" -eq 1 ] || return 1
    IFS= read -r PTXRAY_DEFS_RECHECK_GENERATION \
      <"$PTXRAY_DEFS_CACHE/current" || return 1
    [ "$PTXRAY_DEFS_RECHECK_BEFORE" = "$(ptxray_defs_cache_file_identity \
      "$PTXRAY_DEFS_CACHE/current")" ] || return 1
    ptxray_defs_valid_generation_name "$PTXRAY_DEFS_RECHECK_GENERATION" || return 1
    PTXRAY_DEFS_RECHECK_SEQUENCE=$(printf '%s\n' \
      "$PTXRAY_DEFS_RECHECK_GENERATION" | awk -F- '{print $2}')
    if ptxray_defs_sequence_less "$PTXRAY_DEFS_SEQUENCE" \
        "$PTXRAY_DEFS_RECHECK_SEQUENCE"; then
      PTXRAY_DEFS_FAILURE=rollback
      return 1
    fi
    if [ "$PTXRAY_DEFS_SEQUENCE" = "$PTXRAY_DEFS_RECHECK_SEQUENCE" ] \
        && [ "$PTXRAY_DEFS_GENERATION" != "$PTXRAY_DEFS_RECHECK_GENERATION" ]; then
      PTXRAY_DEFS_FAILURE=rollback
      return 1
    fi
  fi

  PTXRAY_DEFS_STAGE=$PTXRAY_DEFS_WORK/generation
  mkdir -m 700 "$PTXRAY_DEFS_STAGE" 2>/dev/null || return 1
  mv "$PTXRAY_DEFS_WORK/bundle" "$PTXRAY_DEFS_STAGE/bundle.ptxray-defs" || return 1
  mv "$PTXRAY_DEFS_WORK/bundle.sig" "$PTXRAY_DEFS_STAGE/bundle.ptxray-defs.sig" || return 1
  mv "$PTXRAY_DEFS_WORK/payload-1" "$PTXRAY_DEFS_STAGE/cisa-kev.json" || return 1
  mv "$PTXRAY_DEFS_WORK/payload-2" "$PTXRAY_DEFS_STAGE/ibm-apar.csv" || return 1
  mv "$PTXRAY_DEFS_WORK/cisa-kev-cves.txt" \
    "$PTXRAY_DEFS_STAGE/cisa-kev-cves.txt" || return 1
  chmod 600 "$PTXRAY_DEFS_STAGE"/* 2>/dev/null || return 1
  PTXRAY_DEFS_TARGET=$PTXRAY_DEFS_CACHE/generations/$PTXRAY_DEFS_GENERATION
  if [ -e "$PTXRAY_DEFS_TARGET" ]; then
    PTXRAY_DEFS_TARGET_DIR_BEFORE=$(ptxray_defs_cache_dir_identity \
      "$PTXRAY_DEFS_TARGET") || return 1
    for PTXRAY_DEFS_NAME in bundle.ptxray-defs bundle.ptxray-defs.sig \
        cisa-kev.json ibm-apar.csv cisa-kev-cves.txt; do
      PTXRAY_DEFS_TARGET_FILE_BEFORE=$(ptxray_defs_cache_file_identity \
        "$PTXRAY_DEFS_TARGET/$PTXRAY_DEFS_NAME") || return 1
      cmp -s "$PTXRAY_DEFS_STAGE/$PTXRAY_DEFS_NAME" \
        "$PTXRAY_DEFS_TARGET/$PTXRAY_DEFS_NAME" || return 1
      [ "$PTXRAY_DEFS_TARGET_FILE_BEFORE" = "$(ptxray_defs_cache_file_identity \
        "$PTXRAY_DEFS_TARGET/$PTXRAY_DEFS_NAME")" ] || return 1
    done
    [ "$PTXRAY_DEFS_TARGET_DIR_BEFORE" = "$(ptxray_defs_cache_dir_identity \
      "$PTXRAY_DEFS_TARGET")" ] || return 1
    rm -rf "$PTXRAY_DEFS_STAGE" || return 1
  else
    mv "$PTXRAY_DEFS_STAGE" "$PTXRAY_DEFS_TARGET" || return 1
    [ "$(ptxray_defs_cache_dir_identity "$PTXRAY_DEFS_TARGET")" != '' ] || return 1
  fi
  if [ -e "$PTXRAY_DEFS_CACHE/current" ]; then
    ptxray_defs_cache_file_identity "$PTXRAY_DEFS_CACHE/current" >/dev/null \
      || return 1
  fi
  PTXRAY_DEFS_POINTER=$PTXRAY_DEFS_CACHE/.current.$PTXRAY_DEFS_TOKEN
  (set -C; umask 077; : >"$PTXRAY_DEFS_POINTER") 2>/dev/null || return 1
  [ -f "$PTXRAY_DEFS_POINTER" ] && [ ! -L "$PTXRAY_DEFS_POINTER" ] || return 1
  printf '%s\n' "$PTXRAY_DEFS_GENERATION" >"$PTXRAY_DEFS_POINTER" || return 1
  chmod 600 "$PTXRAY_DEFS_POINTER" || return 1
  # This rename provides atomic visibility, not a claim of power-loss
  # durability: portable AIX /bin/sh exposes no per-file/directory fsync
  # primitive. Every later read re-authenticates the complete generation. If a
  # crash leaves an unusable pointer, the protected-floor or explicit recovery
  # paths above fail closed without silently deleting cached generations.
  mv -f "$PTXRAY_DEFS_POINTER" "$PTXRAY_DEFS_CACHE/current" || return 1
  ptxray_defs_cache_file_identity "$PTXRAY_DEFS_CACHE/current" >/dev/null \
    || return 1
  return 0
}

ptxray_defs_publish_work() {
  PTXRAY_DEFS_FAILURE=malformed
  PTXRAY_DEFS_GENERATION=$(ptxray_defs_generation_name) || return 1
  ptxray_defs_valid_generation_name "$PTXRAY_DEFS_GENERATION" || return 1
  ptxray_defs_acquire_publish_lock || return 1
  ptxray_defs_publish_locked
  PTXRAY_DEFS_PUBLISH_RC=$?
  if ! ptxray_defs_release_publish_lock; then
    PTXRAY_DEFS_FAILURE=unsafe-cache
    PTXRAY_DEFS_PUBLISH_RC=1
  fi
  return "$PTXRAY_DEFS_PUBLISH_RC"
}

ptxray_defs_read_current() {
  PTXRAY_DEFS_FAILURE=unsafe-cache
  ptxray_defs_prepare_cache || return 1
  PTXRAY_DEFS_CURRENT_POINTER_BEFORE=$(ptxray_defs_cache_file_identity \
    "$PTXRAY_DEFS_CACHE/current") || return 1
  [ "$(wc -l <"$PTXRAY_DEFS_CACHE/current" | tr -d ' ')" -eq 1 ] || return 1
  IFS= read -r PTXRAY_DEFS_GENERATION <"$PTXRAY_DEFS_CACHE/current" || return 1
  ptxray_defs_valid_generation_name "$PTXRAY_DEFS_GENERATION" || return 1
  PTXRAY_DEFS_CURRENT_DIR=$PTXRAY_DEFS_CACHE/generations/$PTXRAY_DEFS_GENERATION
  PTXRAY_DEFS_CURRENT_DIR_BEFORE=$(ptxray_defs_cache_dir_identity \
    "$PTXRAY_DEFS_CURRENT_DIR") || return 1
  PTXRAY_DEFS_BUNDLE_BEFORE=$(ptxray_defs_cache_file_identity \
    "$PTXRAY_DEFS_CURRENT_DIR/bundle.ptxray-defs") || return 1
  PTXRAY_DEFS_SIGNATURE_BEFORE=$(ptxray_defs_cache_file_identity \
    "$PTXRAY_DEFS_CURRENT_DIR/bundle.ptxray-defs.sig") || return 1
  PTXRAY_DEFS_POINTER_SEQUENCE=$(printf '%s\n' "$PTXRAY_DEFS_GENERATION" | awk -F- '{print $2}')
  ptxray_defs_verify_pair "$PTXRAY_DEFS_CURRENT_DIR/bundle.ptxray-defs" \
    "$PTXRAY_DEFS_CURRENT_DIR/bundle.ptxray-defs.sig" "$PTXRAY_DEFS_POINTER_SEQUENCE" \
    || return 1
  PTXRAY_DEFS_FAILURE=unsafe-cache
  [ "$PTXRAY_DEFS_BUNDLE_BEFORE" = "$(ptxray_defs_cache_file_identity \
    "$PTXRAY_DEFS_CURRENT_DIR/bundle.ptxray-defs")" ] || return 1
  [ "$PTXRAY_DEFS_SIGNATURE_BEFORE" = "$(ptxray_defs_cache_file_identity \
    "$PTXRAY_DEFS_CURRENT_DIR/bundle.ptxray-defs.sig")" ] || return 1
  [ "$(ptxray_defs_generation_name)" = "$PTXRAY_DEFS_GENERATION" ] || return 1
  for PTXRAY_DEFS_PAIR in \
      'payload-1:cisa-kev.json' \
      'payload-2:ibm-apar.csv' \
      'cisa-kev-cves.txt:cisa-kev-cves.txt'; do
    PTXRAY_DEFS_WORK_NAME=${PTXRAY_DEFS_PAIR%%:*}
    PTXRAY_DEFS_CACHE_NAME=${PTXRAY_DEFS_PAIR#*:}
    PTXRAY_DEFS_PAYLOAD_BEFORE=$(ptxray_defs_cache_file_identity \
      "$PTXRAY_DEFS_CURRENT_DIR/$PTXRAY_DEFS_CACHE_NAME") || return 1
    cmp -s "$PTXRAY_DEFS_WORK/$PTXRAY_DEFS_WORK_NAME" \
      "$PTXRAY_DEFS_CURRENT_DIR/$PTXRAY_DEFS_CACHE_NAME" || return 1
    [ "$PTXRAY_DEFS_PAYLOAD_BEFORE" = "$(ptxray_defs_cache_file_identity \
      "$PTXRAY_DEFS_CURRENT_DIR/$PTXRAY_DEFS_CACHE_NAME")" ] || return 1
  done
  [ "$PTXRAY_DEFS_CURRENT_DIR_BEFORE" = "$(ptxray_defs_cache_dir_identity \
    "$PTXRAY_DEFS_CURRENT_DIR")" ] || return 1
  [ "$PTXRAY_DEFS_CURRENT_POINTER_BEFORE" = "$(ptxray_defs_cache_file_identity \
    "$PTXRAY_DEFS_CACHE/current")" ] || return 1
  return 0
}

ptxray_defs_snapshot_copy() {
  PTXRAY_DEFS_SNAPSHOT_SOURCE=$1
  PTXRAY_DEFS_SNAPSHOT_NAME=$2
  PTXRAY_DEFS_SNAPSHOT_EXPECTED=$3
  PTXRAY_DEFS_SNAPSHOT_LIMIT=$PTXRAY_DEFS_MAX_PAYLOAD
  [ "$#" -ge 4 ] && PTXRAY_DEFS_SNAPSHOT_LIMIT=$4
  PTXRAY_DEFS_SNAPSHOT_PATH=$PTXRAY_DEFS_SNAPSHOT_DIR/$PTXRAY_DEFS_SNAPSHOT_NAME
  [ ! -e "$PTXRAY_DEFS_SNAPSHOT_PATH" ] \
    && [ ! -L "$PTXRAY_DEFS_SNAPSHOT_PATH" ] || return 1
  (set -C; umask 077; : >"$PTXRAY_DEFS_SNAPSHOT_PATH") 2>/dev/null || return 1
  ptxray_defs_copy_bounded "$PTXRAY_DEFS_SNAPSHOT_SOURCE" \
    "$PTXRAY_DEFS_SNAPSHOT_PATH" "$PTXRAY_DEFS_SNAPSHOT_LIMIT" || return 1
  chmod 600 "$PTXRAY_DEFS_SNAPSHOT_PATH" 2>/dev/null || return 1
  PTXRAY_DEFS_SNAPSHOT_FILE_ID=$(ptxray_defs_cache_file_identity \
    "$PTXRAY_DEFS_SNAPSHOT_PATH") || return 1
  [ "$(ptxray_defs_sha256 "$PTXRAY_DEFS_SNAPSHOT_PATH")" = \
      "$PTXRAY_DEFS_SNAPSHOT_EXPECTED" ] || return 1
  [ "$PTXRAY_DEFS_SNAPSHOT_FILE_ID" = "$(ptxray_defs_cache_file_identity \
    "$PTXRAY_DEFS_SNAPSHOT_PATH")" ] || return 1
}

ptxray_defs_snapshot_current() {
  PTXRAY_DEFS_SNAPSHOT_REQUESTED=$1
  PTXRAY_DEFS_SNAPSHOT_DIR=$2
  case "$PTXRAY_DEFS_SNAPSHOT_DIR" in /*) ;; *) ptxray_defs_fail unsafe-cache; return $?;; esac
  PTXRAY_DEFS_SNAPSHOT_DIR=$(CDPATH= cd -- "$PTXRAY_DEFS_SNAPSHOT_DIR" \
    2>/dev/null && (pwd -P 2>/dev/null || pwd)) \
    || { ptxray_defs_fail unsafe-cache; return $?; }
  ptxray_defs_private_ancestry_safe "$PTXRAY_DEFS_SNAPSHOT_DIR" \
    || { ptxray_defs_fail unsafe-cache; return $?; }
  PTXRAY_DEFS_SNAPSHOT_DIR_ID=$(ptxray_defs_cache_dir_identity \
    "$PTXRAY_DEFS_SNAPSHOT_DIR") \
    || { ptxray_defs_fail unsafe-cache; return $?; }
  PTXRAY_DEFS_SNAPSHOT_CONTENTS=$(LC_ALL=C ls -a "$PTXRAY_DEFS_SNAPSHOT_DIR" \
    2>/dev/null | awk '$0!="."&&$0!=".."{n++}END{print n+0}') \
    || { ptxray_defs_fail unsafe-cache; return $?; }
  [ "$PTXRAY_DEFS_SNAPSHOT_CONTENTS" -eq 0 ] \
    || { ptxray_defs_fail unsafe-cache; return $?; }
  ptxray_defs_read_current || return 1
  [ "$PTXRAY_DEFS_GENERATION" = "$PTXRAY_DEFS_SNAPSHOT_REQUESTED" ] \
    || { ptxray_defs_fail rollback; return $?; }
  PTXRAY_DEFS_SNAPSHOT_CVES_SHA=$(ptxray_defs_sha256 \
    "$PTXRAY_DEFS_WORK/cisa-kev-cves.txt") || return 1
  PTXRAY_DEFS_SNAPSHOT_ACTIVE=1
  ptxray_defs_snapshot_copy "$PTXRAY_DEFS_WORK/payload-1" \
    cisa-kev.json "$PTXRAY_DEFS_KEV_SHA" \
    && ptxray_defs_snapshot_copy "$PTXRAY_DEFS_WORK/cisa-kev-cves.txt" \
      cisa-kev-cves.txt "$PTXRAY_DEFS_SNAPSHOT_CVES_SHA" \
    && ptxray_defs_snapshot_copy "$PTXRAY_DEFS_WORK/payload-2" \
      ibm-apar.csv "$PTXRAY_DEFS_APAR_SHA" \
    && ptxray_defs_snapshot_copy "$PTXRAY_DEFS_WORK/bundle" \
      bundle.ptxray-defs "$PTXRAY_DEFS_BUNDLE_SHA" "$PTXRAY_DEFS_MAX_BUNDLE" \
    && [ "$PTXRAY_DEFS_SNAPSHOT_DIR_ID" = "$(ptxray_defs_cache_dir_identity \
      "$PTXRAY_DEFS_SNAPSHOT_DIR")" ] \
    || { ptxray_defs_fail unsafe-cache; return $?; }
  printf 'PTXRAY-DEFS|1|snapshot|generation=%s|kev_sha256=%s|cves_sha256=%s|apar_sha256=%s|bundle_sha256=%s\n' \
    "$PTXRAY_DEFS_GENERATION" "$PTXRAY_DEFS_KEV_SHA" \
    "$PTXRAY_DEFS_SNAPSHOT_CVES_SHA" "$PTXRAY_DEFS_APAR_SHA" \
    "$PTXRAY_DEFS_BUNDLE_SHA"
  PTXRAY_DEFS_SNAPSHOT_ACTIVE=0
  PTXRAY_DEFS_SNAPSHOT_DIR=
  PTXRAY_DEFS_SNAPSHOT_DIR_ID=
  return 0
}

usage() {
  echo "usage: $0 --update|--cache|--local BUNDLE|--recover-local BUNDLE|--recover-lock|--status|--payload GENERATION cisa-kev|cisa-kev-cves|ibm-apar-csv|--snapshot GENERATION DIRECTORY" >&2
  exit 2
}

[ "$#" -gt 0 ] || usage
MODE=$1
shift
LOCAL_BUNDLE=
PAYLOAD_GENERATION=
PAYLOAD_SOURCE=
case "$MODE" in
  --update|--cache|--recover-lock|--status) [ "$#" -eq 0 ] || usage;;
  --local|--recover-local) [ "$#" -eq 1 ] || usage; LOCAL_BUNDLE=$1;;
  --payload)
    [ "$#" -eq 2 ] || usage
    PAYLOAD_GENERATION=$1
    PAYLOAD_SOURCE=$2
    ptxray_defs_valid_generation_name "$PAYLOAD_GENERATION" || usage
    case "$PAYLOAD_SOURCE" in
      cisa-kev|cisa-kev-cves|ibm-apar-csv) ;;
      *) usage;;
    esac
    ;;
  --snapshot)
    [ "$#" -eq 2 ] || usage
    PAYLOAD_GENERATION=$1
    PAYLOAD_SOURCE=$2
    ptxray_defs_valid_generation_name "$PAYLOAD_GENERATION" || usage
    case "$PAYLOAD_SOURCE" in /*) ;; *) usage;; esac
    ;;
  *) usage;;
esac

ptxray_defs_require_identity \
  || { ptxray_defs_error 'AIX root or IBM i QSECOFR session/system identity is required'; exit 2; }

case "$MODE" in
  --status)
    if [ -e "$PTXRAY_DEFS_CACHE/current" ] \
        && ptxray_defs_cache_file_identity "$PTXRAY_DEFS_CACHE/current" >/dev/null; then
      printf '%s\n' 'PTXRAY-DEFS|1|status|cache-present'
    else
      printf '%s\n' 'PTXRAY-DEFS|1|status|cache-absent'
    fi
    ;;
  --recover-lock)
    ptxray_defs_recover_publish_lock
    exit $?
    ;;
  --local)
    PTXRAY_DEFS_OPENSSL=$(ptxray_defs_select_openssl) \
      || { ptxray_defs_error 'a supported fixed-path OpenSSL verifier is unavailable'; exit 3; }
    ptxray_defs_load_minimum || exit 3
    ptxray_defs_verify_pair "$LOCAL_BUNDLE" "$LOCAL_BUNDLE.sig" "$PTXRAY_DEFS_MINIMUM" \
      || { ptxray_defs_error "local signed definitions bundle rejected ($PTXRAY_DEFS_FAILURE)"; exit 2; }
    ptxray_defs_publish_work \
      || { ptxray_defs_error "verified local definitions publication failed ($PTXRAY_DEFS_FAILURE)"; exit 3; }
    ptxray_defs_emit_ok local
    ;;
  --recover-local)
    PTXRAY_DEFS_OPENSSL=$(ptxray_defs_select_openssl) \
      || { ptxray_defs_error 'a supported fixed-path OpenSSL verifier is unavailable'; exit 3; }
    ptxray_defs_prepare_cache \
      || { ptxray_defs_error 'secure definitions cache is unavailable (unsafe-cache)'; exit 3; }
    if [ -e "$PTXRAY_DEFS_CACHE/current" ]; then
      PTXRAY_DEFS_RECOVERY_POINTER=$(ptxray_defs_cache_file_identity \
        "$PTXRAY_DEFS_CACHE/current") \
        || { ptxray_defs_error 'current pointer is not a safe owner-only regular file; recovery refused pending operator inspection'; exit 3; }
      PTXRAY_DEFS_RECOVERY_POINTER_SIZE=$(printf '%s\n' \
        "$PTXRAY_DEFS_RECOVERY_POINTER" | awk -F'|' '{print $2}')
      case "$PTXRAY_DEFS_RECOVERY_POINTER_SIZE" in
        ''|*[!0-9]*) ptxray_defs_error 'current pointer size is untrustworthy; recovery refused'; exit 3;;
      esac
      [ "$PTXRAY_DEFS_RECOVERY_POINTER_SIZE" -le 256 ] \
        || { ptxray_defs_error 'current pointer is oversized; recovery refused pending operator inspection'; exit 3; }
      if ptxray_defs_read_floor; then
        ptxray_defs_error "trustworthy rollback floor exists at sequence $PTXRAY_DEFS_FLOOR_SEQUENCE; use normal --local so rollback protection remains active"
        exit 3
      fi
      PTXRAY_DEFS_RECOVERY_POINTER_SHA=$(ptxray_defs_sha256 \
        "$PTXRAY_DEFS_CACHE/current") \
        || { ptxray_defs_error 'current pointer could not be fingerprinted; recovery refused'; exit 3; }
      [ "$PTXRAY_DEFS_RECOVERY_POINTER" = "$(ptxray_defs_cache_file_identity \
        "$PTXRAY_DEFS_CACHE/current")" ] \
        || { ptxray_defs_error 'current pointer changed during recovery inspection; recovery refused'; exit 3; }
    elif ! ptxray_defs_generations_present; then
      ptxray_defs_error 'cache has no prior generation to recover; use normal --local'
      exit 3
    else
      PTXRAY_DEFS_RECOVERY_POINTER=absent
    fi
    PTXRAY_DEFS_STRICT_MINIMUM=0
    ptxray_defs_verify_pair "$LOCAL_BUNDLE" "$LOCAL_BUNDLE.sig" '' \
      || { ptxray_defs_error "explicit recovery bundle rejected ($PTXRAY_DEFS_FAILURE)"; exit 2; }
    PTXRAY_DEFS_RESET_FLOOR=1
    ptxray_defs_publish_work \
      || { ptxray_defs_error "explicit current-pointer recovery failed ($PTXRAY_DEFS_FAILURE)"; exit 3; }
    printf 'WARNING: rollback floor was explicitly reset to authenticated sequence %s; existing cache generations were retained.\n' \
      "$PTXRAY_DEFS_SEQUENCE" >&2
    ptxray_defs_emit_ok recover-local
    ;;
  --cache)
    PTXRAY_DEFS_OPENSSL=$(ptxray_defs_select_openssl) \
      || { ptxray_defs_error 'a supported fixed-path OpenSSL verifier is unavailable'; exit 3; }
    ptxray_defs_read_current \
      || { ptxray_defs_error "signed definitions cache unavailable ($PTXRAY_DEFS_FAILURE)"; exit 3; }
    ptxray_defs_emit_ok cache
    ;;
  --payload)
    PTXRAY_DEFS_OPENSSL=$(ptxray_defs_select_openssl) \
      || { ptxray_defs_error 'a supported fixed-path OpenSSL verifier is unavailable'; exit 3; }
    ptxray_defs_read_current \
      || { ptxray_defs_error "signed definitions cache unavailable ($PTXRAY_DEFS_FAILURE)"; exit 3; }
    [ "$PTXRAY_DEFS_GENERATION" = "$PAYLOAD_GENERATION" ] \
      || { ptxray_defs_error 'selected definitions generation is no longer current (rollback)'; exit 3; }
    case "$PAYLOAD_SOURCE" in
      cisa-kev) cat "$PTXRAY_DEFS_WORK/payload-1";;
      cisa-kev-cves) cat "$PTXRAY_DEFS_WORK/cisa-kev-cves.txt";;
      ibm-apar-csv) cat "$PTXRAY_DEFS_WORK/payload-2";;
    esac || { ptxray_defs_error 'verified definitions payload could not be emitted'; exit 3; }
    ;;
  --snapshot)
    PTXRAY_DEFS_OPENSSL=$(ptxray_defs_select_openssl) \
      || { ptxray_defs_error 'a supported fixed-path OpenSSL verifier is unavailable'; exit 3; }
    ptxray_defs_snapshot_current "$PAYLOAD_GENERATION" "$PAYLOAD_SOURCE" \
      || { ptxray_defs_error "verified definitions snapshot failed ($PTXRAY_DEFS_FAILURE)"; exit 3; }
    ;;
  --update)
    PTXRAY_DEFS_OPENSSL=$(ptxray_defs_select_openssl) \
      || { ptxray_defs_error 'a supported fixed-path OpenSSL verifier is unavailable'; exit 3; }
    ptxray_defs_update
    exit $?
    ;;
  *)
    echo "ptxray-defs: signed definition verification is unavailable" >&2
    exit 3
    ;;
esac
