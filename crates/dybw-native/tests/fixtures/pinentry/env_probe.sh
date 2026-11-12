#!/bin/sh
# @file env_probe.sh
# @brief A pinentry that answers GETPIN with its own process facts.
# @description CARGO_MANIFEST_DIR as it sees it, then its pid and process group id. No PATH: ps by absolute path.
echo "OK scripted pinentry"
while IFS= read -r l; do
  case "$l" in
    GETPIN*)
      pg=$(/bin/ps -o pgid= -p $$)
      set -- $pg
      echo "D CARGO_MANIFEST_DIR=${CARGO_MANIFEST_DIR-absent} $$ $1"
      echo OK
      ;;
    BYE*) echo OK; exit 0 ;;
    *) echo OK ;;
  esac
done
