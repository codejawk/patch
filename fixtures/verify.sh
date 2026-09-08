#!/usr/bin/env bash
# Runs every patch against a throwaway copy of src/ under escalating
# tolerance levels and reports where each one first succeeds.
# This is the ground truth the merger's tier logic must reproduce.
#
#   T1  git apply       strict: exact context
#   T2  patch -F0       exact context, offsets may slide
#   T3  patch -F2 -l    fuzzy context + whitespace-insensitive
#   T4  git merge-file  three-way against vendor_base/
#
# Strip level differs by vendor dialect - working that out is part of the job.
set -u
cd "$(dirname "$0")"

G=$'\033[32m'; R=$'\033[31m'; O=$'\033[0m'

strip_for() {
  case "$1" in
    *qcom*) echo 1 ;;   # git-style a/ b/ prefixes
    *)      echo 0 ;;   # MTK / LSI dialects carry bare paths
  esac
}

reset_work() { rm -rf .work && cp -r src .work; }

report() {
  if [ "$2" -eq 0 ]; then
    printf '    %-18s %sPASS%s  %s\n' "$1" "$G" "$O" "${4:-}"
  else
    printf '    %-18s %sfail%s  %s\n' "$1" "$R" "$O" \
      "$(printf '%s' "$3" | grep -viE '^[[:space:]]*$' | head -2 | tr '\n' ' ')"
  fi
}

for p in patches/*.patch; do
  base=$(basename "$p"); id=${base%%-*}; P=$(strip_for "$base")
  echo
  echo "=== $base   (-p$P)"

  reset_work
  out=$(cd .work && git init -q . && git add -A \
        && git -c user.email=t@t -c user.name=t commit -qm base \
        && git apply -p$P --check "../$p" 2>&1); rc=$?
  report "T1 strict" $rc "$out"

  reset_work
  out=$(cd .work && patch -p$P -F0 --dry-run -s -i "../$p" </dev/null 2>&1); rc=$?
  report "T2 offset-tolerant" $rc "$out"

  reset_work
  out=$(cd .work && patch -p$P -F2 -l --dry-run -i "../$p" </dev/null 2>&1); rc=$?
  note=$(printf '%s' "$out" | grep -o 'fuzz [0-9]* (offset [-0-9]* lines*)' | head -1)
  report "T3 fuzzy+ws" $rc "$out" "$note"

  if [ -d "vendor_base/$id" ]; then
    rm -rf .theirs && cp -r "vendor_base/$id" .theirs
    tout=$(cd .theirs && patch -p$P -F0 -s -i "../$p" </dev/null 2>&1); trc=$?
    if [ $trc -ne 0 ]; then
      report "T4 three-way" 1 "baseline apply failed: $tout"
    else
      any=0; conflict=0
      while IFS= read -r f; do
        rel=${f#.theirs/}
        ours="src/$rel"
        [ -f "$ours" ] || ours=$(find src -name "$(basename "$rel")" | head -1)
        [ -n "$ours" ] && [ -f "$ours" ] || continue
        any=1
        git merge-file -p --quiet "$ours" "vendor_base/$id/$rel" "$f" \
          >/dev/null 2>&1 || conflict=1
      done < <(find .theirs -type f)
      if [ $any -eq 0 ]; then report "T4 three-way" 1 "no matching file in src/"
      elif [ $conflict -eq 0 ]; then report "T4 three-way" 0 ""
      else report "T4 three-way" 1 "merge conflict - needs assisted rebase"; fi
    fi
  else
    printf '    %-18s (none - no vendor baseline shipped)\n' "T4 three-way"
  fi
done

rm -rf .work .theirs
echo
