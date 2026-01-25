#!/usr/bin/env bash

set -euo pipefail

# obtener mensaje del commit
commit_msg=""
if [[ -n "${1:-}" && -f "$1" ]]; then
  commit_msg="$(head -n 1 "$1" | tr -d '\r\n')"
fi

if [[ -z "$commit_msg" && -n "${LEFTHOOK_COMMIT_MSG:-}" ]]; then
  commit_msg="$(printf '%s' "$LEFTHOOK_COMMIT_MSG" | head -n 1 | tr -d '\r\n')"
fi

if [[ -z "$commit_msg" && -f .git/COMMIT_EDITMSG ]]; then
  commit_msg="$(head -n 1 .git/COMMIT_EDITMSG | tr -d '\r\n')"
fi

# mensaje vacio o comentario
if [[ -z "$commit_msg" ]] || printf '%s' "$commit_msg" | grep -qE '^#'; then
  printf '[warn] mensaje vacio, me salto el chequeo.\n'
  exit 0
fi

printf '[check] revisando commit: "%s"\n' "$commit_msg"

# patron Conventional Commits
if ! printf '%s' "$commit_msg" | grep -qE '^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test|git)(\([^)]+\))?: .{1,72}$'; then
  printf '[fail] formato raro, spec: \n'
  printf 'usa: <tipo>(scope opcional): descripcion corta\n'
  printf 'tipos validos: build, chore, ci, docs, feat, fix, perf, refactor, revert, style, test, git\n'
  printf 'tu mensaje: "%s"\n' "$commit_msg"
  exit 1
fi

# largo maximo 128 chars
if (( ${#commit_msg} > 128 )); then
  printf '[fail] muy largo, max 128 chars.\n'
  printf 'largo actual: %d\n' ${#commit_msg}
  printf 'tu mensaje: "%s"\n' "$commit_msg"
  exit 1
fi

# descripción en imperativo (opcional)
description="$(printf '%s' "$commit_msg" | sed -E 's/^[a-z]+(\([^)]+\))?: //')"
if printf '%s' "$description" | grep -qE '^(add|fix|update|change|remove|create)'; then
  printf '[warn] buen estilo en imperativo: add, fix, update, etc.\n'
  printf 'tu mensaje: "%s"\n' "$commit_msg"
fi

printf '[ok] commit cumple con Conventional Commits.\n'
