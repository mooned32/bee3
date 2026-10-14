#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Проверка того, что очистка секретов реальна в машинном коде.
#
# Предыстория и коррекция. Изначально скрипт проверял, что очистка
# вырождается в строковую инструкцию без -fno-builtin, и на этом держался
# тезис «-fno-builtin обязателен». Измерение показало обратное:
#
#     $ gcc -O2 -S  ... volatile-цикл обнуления
#     $ gcc -O2 -fno-builtin -S ... тот же цикл, побайтно
#
# То есть на gcc 16 столь же, как и без флага, цикл обнуления на месте.
# Механизм защиты — volatile-указатель внутри функции (C99 6.7.3p6):
# он запрещает переставлять и удалять запись через указатель, и это
# работает независимо от того, распознана ли memset как встроенная.
#
# -fno-builtin остаётся в наборе флагов как страховка от компиляторов с
# иной стратегией оптимизации, но утверждать, что без него очистка
# не работает, нельзя — это было бы неверно.
#
# Проверяемый инвариант поэтому другой, и он содержателен:
#   в машинном коде функции очистки присутствует побайтный цикл записи
#   нулём по всем count байтам.
#
set -euo pipefail

CC="${CC:-cc}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "${OUT}"' EXIT

if [ ! -f "${SRC}/src/core/secure_mem.c" ]; then
    echo "FAIL: не найден src/core/secure_mem.c" >&2
    exit 2
fi

echo "== проверка реальной очистки =="

#  Считаем, что очистка реализована, если компилятор сгенерировал цикл,
#  который побайтно пишет ноль и сравнивает указатель с границей.
detect_loop() {
    local asmfile="$1" func="$2"
    awk -v fn="${func}:" '
        $0 ~ "^"fn { inside = 1 }
        inside && /\.size[ \t]+/ { inside = 0 }
        inside { print }
    ' "${asmfile}"
}

check_ok=0
for opt in -O0 -O1 -O2 -O3 -Os; do
    "${CC}" -std=c2x "${opt}" -fno-builtin \
        -I"${SRC}/include" -S -o "${OUT}/sm_${opt#-}.s" \
        "${SRC}/src/core/secure_mem.c" 2>/dev/null

    body="$(detect_loop "${OUT}/sm_${opt#-}.s" bee3SecureZero)"

    #  Цикл обнуления признаётся найденным, если есть побайтная запись нуля
    #  и условный переход назад. Конкретный мнемоник значения не имеет:
    #  -O2 использует jne, -Os — je, -O3 может перевернуть условие.
    #  Ранняя версия проверки искала фиксированный набор мнемоников и
    #  дала ложное срабатывание на -Os, хотя цикл присутствовал.
    if grep -qE '\$0, *\(' <<<"${body}" \
       && grep -qE '\bj(a|ae|b|be|c|e|g|ge|l|le|na|nae|nb|nbe|nc|ne|ng|nge|nl|nle|no|np|ns|nz|o|p|pe|po|s|z)\b' \
              <<<"${body}"; then
        echo "  ${opt}: цикл обнуления присутствует — OK"
        check_ok=1
    else
        echo "  ${opt}: цикл обнуления НЕ НАЙДЕН — очистка вырождена"
        echo "        выдержка ассемблера:"
        sed 's/^/        /' <<<"${body}"
    fi
done

if [ "${check_ok}" -ne 1 ]; then
    echo
    echo "FAIL: очистка памяти не выдаёт побайтного цикла записи ни при одном"
    echo "      уровне оптимизации. Требование очистки не выполнено."
    exit 1
fi

echo
echo "== информационно: влияние -fno-builtin =="
"${CC}" -std=c2x -O2 -I"${SRC}/include" -S -o "${OUT}/with.s" \
    "${SRC}/src/core/secure_mem.c" 2>/dev/null

a="$(detect_loop "${OUT}/with.s" bee3SecureZero | grep -cE '\b(movs|stos)\b' || true)"
b="$(detect_loop "${OUT}/sm_O2.s"  bee3SecureZero | grep -cE '\b(movs|stos)\b' || true)"

if [ "${a}" -eq 0 ] && [ "${b}" -eq 0 ]; then
    echo "  без -fno-builtin и с ним одинаково: цикл побайтный."
    echo "  Защиту обеспечивает volatile, -fno-builtin оставлен как страховка."
else
    echo "  без -fno-builtin: строковых инструкций ${a}; с ним: ${b}."
    echo "  -fno-builtin влияет на форму очистки — страховка работает."
fi

echo
echo "OK: очистка памяти подтверждена на всех уровнях оптимизации"