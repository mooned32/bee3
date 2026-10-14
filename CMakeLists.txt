# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.25)

project(bee3
    VERSION       0.1.0
    DESCRIPTION   "Криптографическая библиотека Bee3 — преемник Bee2"
    LANGUAGES     C
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
# Расширения — ошибка, а не предупреждение.
set(CMAKE_C_EXTENSIONS OFF)

include(GNUInstallDirs)
include(CompilerWarnings)

# ─────────────────────────────────────────────────────────────────────────────
# Параметры конфигурации
# ─────────────────────────────────────────────────────────────────────────────

option(BEE3_STRICT
    "Строгая сборка: устаревшее API не компилируется"
    ON)

option(BEE3_ENABLE_LEGACY
    "Собрать устаревшие примитивы (несовместимо с BEE3_STRICT)"
    OFF)

option(BEE3_BUILD_TESTS  "Собрать тесты"      ON)
option(BEE3_BUILD_TOOLS  "Собрать утилиты"    ON)

# Оптимизация задаётся пресетом, а не флагом по умолчанию:
# библиотека криптографии не имеет права навязывать оптимизацию сборке,
# которая её использует.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "" FORCE)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Проверка согласованности конфигурации
# ─────────────────────────────────────────────────────────────────────────────

if(BEE3_STRICT AND BEE3_ENABLE_LEGACY)
    message(FATAL_ERROR
        "Bee3: BEE3_STRICT=ON несовместим с BEE3_ENABLE_LEGACY=ON.\n"
        "  BEE3_STRICT     — ошибка при использовании устаревшего API.\n"
        "  BEE3_ENABLE_LEGACY — собрать устаревшие примитивы.\n"
        "Выберите что-то одно. Основания: docs/LEGACY.md")
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Целевая библиотека
# ─────────────────────────────────────────────────────────────────────────────

add_library(bee3 STATIC
    src/core/secure_mem.c
    src/crypto/belt/belt_block.c
    src/crypto/belt/belt_compr.c
    src/crypto/belt/belt_hash.c
    src/crypto/bash/bash_f.c
    src/crypto/bash/bash_hash.c
    src/crypto/bash/bash_prg.c
    src/crypto/brng/brng_hmac.c
    src/crypto/brng/brng_ctr.c
)

#  src/crypto/belt/belt_slice.c в сборку НЕ включён.
#
#  Константно-временный срез не проходит проверку на соответствие
#  эталонной реализации и потому не выпускается. Проверены по отдельности
#  и признаны корректными: bee3BeltHslice (на всех 256 входах),
#  bee3BeltSlicePack/Unpack, арифметика над дорожками (50000 пар),
#  gslice для r = 5, 13, 21 (20000 входов), slRound (один такт).
#  Не сходится сборка тактов — расхождение не локализовано.
#
#  Включение возможно только вместе с падающим тестом:
if(BEE3_BUILD_SLICE)
    message(FATAL_ERROR
        "BEE3_BUILD_SLICE: срез не соответствует эталону. "
        "См. docs/notes/001-belt-h.md.")
endif()

add_library(bee3::bee3 ALIAS bee3)

target_include_directories(bee3
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(bee3 PROPERTIES
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
)

if(BEE3_STRICT)
    target_compile_definitions(bee3 PUBLIC BEE3_STRICT)
endif()

# Очистка секретов: файл обязан собираться без распознавания встроенных
# функций, иначе memset компилятор удалит.
set(BEE3_SECURE_MEM_SOURCES src/core/secure_mem.c)
bee3_apply_strict_flags(bee3 NO_BUILTIN)

# ─────────────────────────────────────────────────────────────────────────────
# Ассемблерные модули (bit-sliced Belt, варианты bash)
#
# Собираются с -Wa,--noexecstack: стек исполняемым быть не должен ни при
# каких условиях.
# ─────────────────────────────────────────────────────────────────────────────

enable_language(ASM)

# ─────────────────────────────────────────────────────────────────────────────
# Утилиты
# ─────────────────────────────────────────────────────────────────────────────

if(BEE3_BUILD_TOOLS)
    add_executable(bee3_selftest tools/selftest.c)
    target_link_libraries(bee3_selftest PRIVATE bee3::bee3)
    bee3_apply_strict_flags(bee3_selftest POSITION_INDEP)

    add_executable(bee3_belt_test test/belt_test.c)
    target_link_libraries(bee3_belt_test PRIVATE bee3::bee3)
    bee3_apply_strict_flags(bee3_belt_test POSITION_INDEP)

    add_executable(bee3_bash_test test/bash_test.c)
    target_link_libraries(bee3_bash_test PRIVATE bee3::bee3)
    target_include_directories(bee3_bash_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/test)
    bee3_apply_strict_flags(bee3_bash_test POSITION_INDEP)

    add_executable(bee3_bash_prg_test test/bash_prg_test.c)
    target_link_libraries(bee3_bash_prg_test PRIVATE bee3::bee3)
    target_include_directories(bee3_bash_prg_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/test)
    bee3_apply_strict_flags(bee3_bash_prg_test POSITION_INDEP)

    add_executable(bee3_brng_test test/brng_test.c)
    target_link_libraries(bee3_brng_test PRIVATE bee3::bee3)
    target_include_directories(bee3_brng_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/test)
    bee3_apply_strict_flags(bee3_brng_test POSITION_INDEP)

    #  Генератор проверочных данных. Разовый инструмент: собирается
    #  отдельно, в состав библиотеки и её тестов не входит.
    add_executable(bee3_gen_brng_kat EXCLUDE_FROM_ALL tools/gen_brng_kat.c)
    target_link_libraries(bee3_gen_brng_kat PRIVATE bee3::bee3)
    bee3_apply_strict_flags(bee3_gen_brng_kat POSITION_INDEP)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Тесты
# ─────────────────────────────────────────────────────────────────────────────

if(BEE3_BUILD_TESTS)
    enable_testing()
    add_test(NAME selftest     COMMAND bee3_selftest)
    add_test(NAME belt_block   COMMAND bee3_belt_test)
    add_test(NAME bash         COMMAND bee3_bash_test)
    add_test(NAME bash_prg     COMMAND bee3_bash_prg_test)
    add_test(NAME brng         COMMAND bee3_brng_test)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Установка
# ─────────────────────────────────────────────────────────────────────────────

install(TARGETS bee3
        EXPORT bee3Targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})