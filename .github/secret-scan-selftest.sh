#!/usr/bin/env bash
# Self-test for .gitleaks.toml. Builds tiny throwaway git repos with FAKE
# secrets (assembled at runtime so no literal fake secret lives in this repo)
# and checks that gitleaks reports exactly what we expect.
set -euo pipefail
GL="$1"; CFG="$2"; fail=0
AWS="AKIA""Z7Q4M2X3K3W6P5R4"          # fake, never valid
PW="Hunt""er2Fake99"                    # fake password
CF_TOKEN="6c9ccb901a8f4640908332a12889055a"  # public beacon token (allowlisted)
BEACON="<script defer src='https://static.cloudflareinsights.com/beacon.min.js' data-cf-beacon='{\"token\": \"${CF_TOKEN}\"}'></script>"

new_repo() { d=$(mktemp -d); git -C "$d" init -q; git -C "$d" config user.email t@t; git -C "$d" config user.name t; echo "$d"; }
commit() { git -C "$1" add -A; git -C "$1" commit -qm "$2"; }
# expect <name> <repo> <rule ids that must all be reported, or "-" for none>
expect() {
  local name="$1" repo="$2" want="$3" rep; rep=$(mktemp)
  "$GL" git "$repo" --config "$CFG" --redact --no-banner --log-level error \
    --exit-code 0 --report-format json --report-path "$rep"
  got=$(jq -r '[.[].RuleID] | unique | join(" ")' "$rep"); [ -z "$got" ] && got="-"
  ok=1
  if [ "$want" = "-" ]; then [ "$got" = "-" ] || ok=0
  else for id in $want; do [[ " $got " == *" $id "* ]] || ok=0; done; fi
  if [ $ok = 1 ]; then echo "PASS $name -> $got"; else echo "FAIL $name: want [$want] got [$got]"; fail=1; fi
}

r=$(new_repo); echo "$BEACON" > "$r/index.html"; commit "$r" beacon
expect "public CF beacon token alone is ignored" "$r" "-"

r=$(new_repo); echo "$BEACON <!-- ${AWS} -->" > "$r/index.html"; commit "$r" mixed
expect "other secret on the CF beacon line is still caught" "$r" "aws-access-token"

r=$(new_repo); mkdir -p "$r/.claude"
printf '{"permissions":{"allow":["Bash(mysql -u root -p%s app)"]}}\n' "$PW" > "$r/.claude/settings.local.json"; commit "$r" settings
expect "committed settings.local.json + inline DB password" "$r" "claude-local-settings-committed cli-inline-db-password"

r=$(new_repo); printf 'curl -H "Authorization: Bearer %s" https://api.example\n' "tok_${PW}abcdef" > "$r/deploy.sh"; commit "$r" add
rm "$r/deploy.sh"; commit "$r" remove
expect "secret added then deleted is still found in history" "$r" "cli-auth-header"

r=$(new_repo); printf 'API_TOKEN=%s npm run deploy\nuse "$API_TOKEN" from env\n' "${PW}xyz" > "$r/notes.md"; commit "$r" env
expect "inline env assignment caught, \$VAR reference not" "$r" "inline-env-secret"

r=$(new_repo); echo "hello" > "$r/README.md"; commit "$r" clean
expect "clean repo has no findings" "$r" "-"

exit $fail
