#!/bin/bash
# PreToolUse Hook — aimy 工具调用安全前检
CMD="$1"

if ! echo "$CMD" | grep -qE "main\.py|python.*aimy"; then
    exit 0
fi

RATE=$(echo "$CMD" | grep -oP '\-\-rate\s+\K[\d.]+')
if [ -n "$RATE" ] && awk "BEGIN{exit !($RATE > 1.0)}"; then
    echo '{"decision":"block","reason":"[SAFETY] --rate 超过 1.0 req/s"}'; exit 1
fi

CONCUR=$(echo "$CMD" | grep -oP '\-\-max-concur\s+\K\d+')
if [ -n "$CONCUR" ] && [ "$CONCUR" -gt 5 ]; then
    echo '{"decision":"block","reason":"[SAFETY] --max-concur 超过 5"}'; exit 1
fi

ROWS=$(echo "$CMD" | grep -oP '\-\-max-rows\s+\K\d+')
if [ -n "$ROWS" ] && [ "$ROWS" -gt 20 ]; then
    echo '{"decision":"block","reason":"[SAFETY] --max-rows 超过 20"}'; exit 1
fi

exit 0
