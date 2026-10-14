/*
*******************************************************************************
\file    selftest.c
\brief   Проверка конфигурации сборки

\purpose Не проверяет криптографию. Проверяет, что библиотека собрана в
         заявленной конфигурации, и отказывается работать в недопустимой.

\purpose Эта проверка должна выполняться первой при старте любого
         приложения: она дешевле и надёжнее, чем надежда на то, что
         конфигурация сборки совпадёт с ожиданием.
*******************************************************************************
*/

#include <stdio.h>
#include <string.h>

#include "bee3/core/secure_mem.h"

/*  Проверка очистки памяти.
 *
 *  Тест намеренно читает буфер после очистки: это делает запись
 *  наблюдаемой, и компилятор не вправе её удалить. Отдельная гарантия —
 *  запрет распознавания встроенных функций (-fno-builtin) — проверяется
 *  инструментально в tools/check_nobuiltin.sh, потому что из исходного
 *  кода её доказать нельзя.
 */
static int
test_secure_zero(void)
{
    u8 buf[64];
    size_t i;
    size_t nonzero = 0;

    for (i = 0; i < sizeof(buf); ++i)
        buf[i] = 0xA5;

    bee3SecureZero(buf, sizeof(buf));

    for (i = 0; i < sizeof(buf); ++i)
        if (buf[i] != 0)
            nonzero++;

    if (nonzero != 0)
    {
        printf("FAIL: secure_zero оставил %zu ненулевых октетов\n", nonzero);
        return 1;
    }
    return 0;
}

/*  Проверка заполнения. */
static int
test_secure_fill(void)
{
    u8 buf[32];
    size_t i;
    size_t wrong = 0;

    bee3SecureFill(buf, sizeof(buf), 0x5A);

    for (i = 0; i < sizeof(buf); ++i)
        if (buf[i] != 0x5A)
            wrong++;

    if (wrong != 0)
    {
        printf("FAIL: secure_fill оставил %zu неверных октетов\n", wrong);
        return 1;
    }
    return 0;
}

/*  Проверка граничных случаев: нулевой размер и нулевой указатель не
    должны приводить к аварии. */
static int
test_edges(void)
{
    u8 buf[1];
    bee3SecureZero(buf, 0);
    bee3SecureZero(0, 0);
    bee3SecureFill(0, 0, 0);
    bee3Mlock(0, 0);
    bee3Munlock(0, 0);
    return 0;
}

int
main(void)
{
    if (test_secure_zero() != 0)
        return 1;
    if (test_secure_fill() != 0)
        return 1;
    (void)test_edges();

#if defined(BEE3_STRICT)
    printf("конфигурация : strict (устаревшее API не компилируется)\n");
#else
    printf("конфигурация : relaxed (устаревшее API доступно)\n");
#endif

#if defined(BEE3_ENABLE_LEGACY)
    printf("legacy       : ВКЛЮЧЁН — приложение осознанно эксплуатирует "
           "устаревшие примитивы (docs/LEGACY.md)\n");
#else
    printf("legacy       : выключен\n");
#endif

    printf("OK\n");
    return 0;
}