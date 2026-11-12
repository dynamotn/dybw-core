#!/bin/sh
# @file env_probe.sh
# @brief A pinentry that answers GETPIN with its own process facts.
# @description HOME as it sees it, then its pid and process group id.
echo "OK scripted pinentry"
while IFS= read -r l; do
  case "$l" in
    GETPIN*)
      echo "D ${HOME-absent} $$ $(ps -o pgid= -p $$ | tr -d ' ')"
      echo OK
      ;;
    BYE*) echo OK; exit 0 ;;
    *) echo OK ;;
  esac
done
