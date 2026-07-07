#!/bin/bash
# Fast check: which communitytools skills are truly new

# Build a normalized set of existing skill names
declare -A EXISTING
for f in /c/Users/PC/Desktop/彦/skills/*/; do
  name=$(basename "$f" | tr '[:upper:]' '[:lower:]' | tr -d '_-')
  EXISTING["$name"]=1
done

for s in "$@"; do
  sn=$(basename "$s" | tr '[:upper:]' '[:lower:]' | tr -d '_-')
  found=0
  for key in "${!EXISTING[@]}"; do
    if [[ "$key" == *"$sn"* || "$sn" == *"$key"* ]]; then
      found=1
      break
    fi
  done
  [ $found -eq 1 ] && echo "EXISTS: $s" || echo "NEW:    $s"
done
