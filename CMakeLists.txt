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

#  clang-tidy. По умолчанию выключен: инструмент дорог и требует отдельной
#  установки. Конфигурация лежит в .clang-tidy и включается одним ключом:
#      cmake --preset rel -DBEE3_CLANG_TIDY=ON
#  Без этой опции файл .clang-tidy не читается ничем, и его содержание
#  остаётся декларацией. Включение требует clang-tidy в PATH.
option(BEE3_CLANG_TIDY  "Анализ clang-tidy"   OFF)

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
    src/core/selftest.c
    src/crypto/belt/belt_block.c
    src/crypto/belt/belt_slice.c
    src/crypto/belt/belt_compr.c
    src/crypto/belt/belt_hash.c
    src/crypto/bash/bash_f.c
    src/crypto/bash/bash_hash.c
    src/crypto/bash/bash_prg.c
    src/crypto/brng/brng_hmac.c
    src/crypto/brng/brng_ctr.c
    src/crypto/brng/brng_otp.c
)

#  Константно-временный срез РАЗРЕШЁН к сборке. До 2026 г. он был
#  исключён, потому что не совпадал с табличной версией; расхождение
#  локализовано и устранено (docs/notes/005-belt-slice.md):
#
#  перестановка указателей не выполнялась после последнего такта.
#  Тактов восемь, перестановок должно быть тоже восемь: перестановка
#  имеет период 4, и без восьмой дорожки возвращаются не в исходный
#  порядок, а в повернутый на три позиции. Все восемь тактов при этом
#  совпадали с эталоном побайтово — расходился только выход.
#
#  Срез проверен на 64 ключах по 32 блока в обе стороны.
#
#  Оговорка остаётся: константно-временность среза доказана по
#  построению (нет обращений к памяти по индексу, зависящему от данных),
#  а не измерением, см. docs/notes/001-belt-h.md.

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

if(BEE3_CLANG_TIDY)
    find_program(BEE3_CLANG_TIDY_EXE NAMES clang-tidy REQUIRED)
    set_target_properties(bee3 PROPERTIES
        C_CLANG_TIDY "${BEE3_CLANG_TIDY_EXE}")
    message(STATUS "Bee3: clang-tidy — ${BEE3_CLANG_TIDY_EXE}")
else()
    message(STATUS
        "Bee3: clang-tidy выключен. Включить: -DBEE3_CLANG_TIDY=ON")
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

    #  Проверочные данные лежат в src/crypto/kat: они нужны и библиотеке,
    #  и тестам, поэтому в include каталог src/crypto, а не test.
    set(BEE3_TEST_SRC
        "bee3_belt_test:test/belt_test.c"
        "bee3_bash_test:test/bash_test.c"
        "bee3_bash_prg_test:test/bash_prg_test.c"
        "bee3_brng_test:test/brng_test.c")

    foreach(entry IN LISTS BEE3_TEST_SRC)
        string(REPLACE ":" ";" parts "${entry}")
        list(GET parts 0 TGT_NAME)
        list(GET parts 1 TGT_SRC)
        add_executable(${TGT_NAME} ${TGT_SRC})
        target_link_libraries(${TGT_NAME} PRIVATE bee3::bee3)
        target_include_directories(${TGT_NAME} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/crypto)
        bee3_apply_strict_flags(${TGT_NAME} POSITION_INDEP)
    endforeach()

    add_test(NAME belt_block   COMMAND bee3_belt_test)
    add_test(NAME bash         COMMAND bee3_bash_test)
    add_test(NAME bash_prg     COMMAND bee3_bash_prg_test)
    add_test(NAME brng         COMMAND bee3_brng_test)

    #  Проверка конфигурации сборки собирается вместе с утилитами, и её
    #  тест регистрируется только если утилиты собраны.
    if(BEE3_BUILD_TOOLS)
        add_test(NAME selftest COMMAND bee3_selftest)
    endif()
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Установка
# ─────────────────────────────────────────────────────────────────────────────

install(TARGETS bee3
        EXPORT bee3Targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})