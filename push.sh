#!/bin/bash
set -e
DIR="C:\Users\PC\Desktop\AIMY"
TOKEN="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"

git -C "$DIR" add -A
git -C "$DIR" commit -m "telemetry: safe default (one-click URL, no builtin token)" 2>&1 || echo "(nothing new)"
git -C "$DIR" push https://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@github.com/shiyue416/AIMY.git master:main 2>&1
rm -f /tmp/git_askpass.sh
echo "DONE"
