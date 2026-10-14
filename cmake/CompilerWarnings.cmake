# SPDX-License-Identifier: Apache-2.0
#
# Строгие наборы флагов для Bee3.
#
# Принцип: флаги, влияющие на корректность криптографии, включаются всегда.
# Флаги, влияющие на оптимизацию, выбираются пресетом и не «добавляются
# на всякий случай».

# ─────────────────────────────────────────────────────────────────────────────
# Языковой режим: расширения компилятора — ошибка
#
# -pedantic-errors превращает в ошибку любое расширение: __attribute__ без
# оформления, GNU-оператор ?: , typeof как ключевое слово, анонимные
# структуры, VLA и прочее. Это означает, что код, собранный здесь,
# соберётся и компилятором другой вендорной линии.
# ─────────────────────────────────────────────────────────────────────────────

set(BEE3_STRICT_LANGUAGE
    -pedantic-errors
    -fno-common
    -fno-strict-aliasing
)

# ─────────────────────────────────────────────────────────────────────────────
# Предупреждения
#
# -Wconversion / -Wsign-conversion дают тысячи срабатываний в коде с битовыми
# операциями. Это ожидаемо и правильно: цель флага — заставить указать
# тип явно в каждом месте, где ширина или знаковость неочевидна.
#
# -Wswitch-enum (а не -Wswitch) требует обработать каждое значение
# перечисления явно: добавление нового состояния не должно молча
# проваливаться в ветку по умолчанию.
# ─────────────────────────────────────────────────────────────────────────────

set(BEE3_STRICT_WARNINGS
    -Wall
    -Wextra
    -Werror

    # Целочисленные типы и переполнение.
    -Wconversion
    -Wsign-conversion
    -Wsign-compare
    -Wuseless-cast
    -Wdouble-promotion
    -Wfloat-equal

    # Указатели и типы.
    -Wcast-align=strict
    -Wcast-qual
    -Wpointer-arith
    -Wwrite-strings
    -Wold-style-definition
    -Wstrict-prototypes
    -Wmissing-prototypes
    -Wmissing-declarations
    -Wredundant-decls
    -Wshadow
    -Wundef
    -Wnull-dereference
    -Winit-self

    # Логика.
    -Wswitch-enum
    -Wswitch-default
    -Wimplicit-fallthrough
    -Wuninitialized
    -Wmaybe-uninitialized
    -Warray-bounds
    -Wvla

    # Диагностика.
    -Wformat=2
    -Wformat-security
    -Wmissing-include-dirs

    # Динамическое связывание.
    -Wmissing-declarations
)

# ─────────────────────────────────────────────────────────────────────────────
# Устаревшие и небезопасные API
#
# Соответствует механизму маркировки из include/bee3/defs.h. Использование
# функции, помеченной BEE3_DEPRECATED_SECURITY, обязано ломать сборку.
# ─────────────────────────────────────────────────────────────────────────────

set(BEE3_DEPRECATION_FLAGS
    -Wdeprecated-declarations
    -Werror=deprecated-declarations
)

# ─────────────────────────────────────────────────────────────────────────────
# Категорически запрещено
#
# Обоснования:
#
#  -ffast-math и друзья   — переупорядочивают вещественные операции.
#                           В крипто вещественная арифметика не используется
#                           по построению, но флаг действует глобально на
#                           единицу трансляции и может повлиять на код,
#                           который её включает.
#
#  -fwrapv                — определённое переполнение. Алгоритм от этого
#                           работает неправильно, даже если компилятор
#                           не может заметить. Правильный инструмент —
#                           ckd_add/ckd_sub/ckd_mul из <stdckdint.h>.
#
#  -march=native          — в поставляемых сборках делает артефакт
#                           несовместимым с большинством машин. Допустим
#                           только в локальных пресетах для разработки.
# ─────────────────────────────────────────────────────────────────────────────

set(BEE3_FORBIDDEN_FLAGS
    -ffast-math
    -funsafe-math-optimizations
    -fassociative-math
    -fno-signed-zeros
    -ffinite-math-only
    -fwrapv
    -Ofast
)

# ─────────────────────────────────────────────────────────────────────────────
# Укрепление
#
# -fno-builtin в модулях с secure_zero(). Уточнение после измерения:
# на gcc 16 цикл обнуления на volatile-указателе присутствует и с этим
# флагом, и без него — защиту обеспечивает именно volatile (C99 6.7.3p6).
# Флаг остаётся как страховка от компиляторов с иной стратегией
# оптимизации и потому, что его стоимость для этой единицы трансляции
# нулевая. Инвариант «очистка реальна в машинном коде» проверяется
# отдельно: tools/check_nobuiltin.sh.
#
# -fno-builtin конфликтует с оптимизацией memcpy/memset во всём модуле,
# поэтому применяется только к перечисленным файлам, а не ко всей
# библиотеке.
#
# _FORTIFY_SOURCE требует включённой оптимизации: без неё glibc выдаёт
# предупреждение, которое при -Werror ломает сборку. Флаг включается
# ТОЛЬКО при оптимизации, а факт его отключения сообщается явно — молча
# терять меру защиты нельзя.
# ─────────────────────────────────────────────────────────────────────────────

set(BEE3_HARDENING
    -fstack-protector-strong
    -fvisibility=hidden
)

#  Оптимизация включена, если в наборе флагов есть -O1..-O3, -Os или -Og.
function(bee3_have_optimization out_var)
    set(_opt OFF)
    foreach(flag IN LISTS CMAKE_C_FLAGS "CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE}")
        if(flag MATCHES "^-O([1-9sz]|g)$")
            set(_opt ON)
        endif()
    endforeach()
    set(${out_var} ${_opt} PARENT_SCOPE)
endfunction()

function(bee3_apply_hardening target)
    bee3_have_optimization(_optimized)
    target_compile_options(${target} PRIVATE ${BEE3_HARDENING})
    if(_optimized)
        target_compile_definitions(${target} PRIVATE _FORTIFY_SOURCE=3)
    else()
        message(STATUS
            "Bee3: ${CMAKE_BUILD_TYPE}: оптимизация выключена, "
            "_FORTIFY_SOURCE отключён (требует -O). В сборках, поставляемых "
            "заказчику, оптимизация обязательна.")
    endif()
endfunction()

set(BEE3_LINK_FLAGS
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    -Wl,--as-needed
)

# ─────────────────────────────────────────────────────────────────────────────
# Применение к цели
#
# bee3_apply_strict_flags(<target>
#     [NO_BUILTIN]      добавить -fno-builtin (для secure_zero)
#     [POSITION_INDEP]  добавить -fPIE (для исполняемых модулей/утилит)
# ─────────────────────────────────────────────────────────────────────────────

function(bee3_apply_strict_flags target)
    set(options NO_BUILTIN POSITION_INDEP)
    cmake_parse_arguments(ARG "${options}" "" "" ${ARGN})

    target_compile_options(${target} PRIVATE
        ${BEE3_STRICT_LANGUAGE}
        ${BEE3_STRICT_WARNINGS}
        ${BEE3_DEPRECATION_FLAGS}
        ${BEE3_HARDENING}
    )

    if(ARG_NO_BUILTIN)
        # Строка очистки секретов.
        target_compile_options(${target} PRIVATE -fno-builtin)
        # -fno-builtin конфликтует с оптимизацией memcpy/memset во всём
        # модуле, поэтому применяется только к узкому списку файлов,
        # перечисленному вызывающей стороной.
        set_source_files_properties(${BEE3_SECURE_MEM_SOURCES}
            PROPERTIES COMPILE_OPTIONS "-fno-builtin")
    endif()

    if(ARG_POSITION_INDEP)
        target_compile_options(${target} PRIVATE -fPIE)
        target_link_options(${target} PRIVATE -pie ${BEE3_LINK_FLAGS})
    endif()
endfunction()

# ─────────────────────────────────────────────────────────────────────────────
# Проверка поддержки
#
# Отсутствие флага должно приводить к ошибке конфигурации на этапе
# конфигурации, а не к молчаливому упрощению набора.
# ─────────────────────────────────────────────────────────────────────────────

include(CheckCCompilerFlag)
function(bee3_require_flag flag var)
    string(MAKE_C_IDENTIFIER "HAVE${flag}" cache_var)
    check_c_compiler_flag("${flag}" ${cache_var})
    if(NOT ${cache_var})
        message(FATAL_ERROR
            "Bee3: требуемый флаг ${flag} не поддерживается компилятором.")
    endif()
    set(${var} ${cache_var} PARENT_SCOPE)
endfunction()

foreach(flag IN LISTS BEE3_STRICT_LANGUAGE BEE3_DEPRECATION_FLAGS)
    if(NOT flag MATCHES "^-W")
        bee3_require_flag(${flag} _unused)
    endif()
endforeach()