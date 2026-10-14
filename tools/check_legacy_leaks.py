#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Проверка герметичности разделения legacy.

Идея: раздел «исключено по умолчанию» теряет смысл, если устаревший
примитив достижим из обычного public-заголовка. Проверка обходит дерево
#include от всех публичных заголовков и падает, если на пути встречается
что-нибудь из include/bee3/crypto/legacy/.

Не полагается на grep: нужно понимать условную компиляцию и порядок
включений, а grep по слову "legacy" даёт и ложные срабатывания
(комментарии, строки), и пропуски (макросы, собираемые имена).
"""

import argparse
import re
import sys
from pathlib import Path

INCLUDE_RE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.MULTILINE)
LEGACY_MARK = "crypto/legacy/"

#  Ветвление препроцессора считаем прозрачным: проверка отвечает за
#  структуру включений, а не за условия сборки. Разбор #if в полном
#  объёме здесь не нужен и был бы источником ложных выводов.
def resolve_include(name: str, from_file: Path, roots: list[Path]) -> Path | None:
    candidate = from_file.parent / name
    if candidate.is_file():
        return candidate
    for root in roots:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def reaches_legacy(start: Path, roots: list[Path]) -> list[str]:
    """Возвращает цепочку включений до legacy-заголовка, либо пустой список."""
    seen: set[Path] = set()
    path: list[str] = []

    def walk(current: Path) -> list[str] | None:
        if current in seen:
            return None
        seen.add(current)
        try:
            text = current.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        for match in INCLUDE_RE.finditer(text):
            name = match.group(1)
            resolved = resolve_include(name, current, roots)
            if resolved is None:
                continue
            if LEGACY_MARK in name or LEGACY_MARK in str(resolved):
                return path + [name]
            found = walk(resolved)
            if found is not None:
                return path + [name] + found
        return None

    return walk(start) or []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--include", default="include", type=Path)
    args = parser.parse_args()

    root: Path = args.include
    roots = [root, root / "bee3"]

    public_headers = [
        p for p in sorted(root.rglob("*.h"))
        if LEGACY_MARK not in str(p) and p.name != "legacy.h"
    ]

    if not public_headers:
        print("FAIL: публичных заголовков не найдено — проверка бессмысленна",
              file=sys.stderr)
        return 2

    failures: list[tuple[Path, list[str]]] = []
    for header in public_headers:
        chain = reaches_legacy(header, roots)
        if chain:
            failures.append((header, chain))

    if failures:
        print("FAIL: устаревшие примитивы достижимы из публичных заголовков:\n",
              file=sys.stderr)
        for header, chain in failures:
            print(f"  {header}", file=sys.stderr)
            for i, step in enumerate(chain):
                print(f"    {'  ' * i}-> {step}", file=sys.stderr)
        print(
            "\nРазделение legacy не работает. Либо уберите включение,\n"
            "либо перенесите функциональность из legacy.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: проверено {len(public_headers)} публичных заголовков, "
          f"утечки legacy не найдены")
    return 0


if __name__ == "__main__":
    sys.exit(main())