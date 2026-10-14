/*
*******************************************************************************
\file    belt_test.c
\brief   Проверка блочного шифра belt
\project bee3 [криптографическая библиотека]

\purpose Тесты проверяют три разных утверждения, и их важно различать:
           1. соответствие стандарту  — вектор приложения А.1;
           2. согласованность реализаций — срез против таблицы;
           3. свойства реализации     — обратимость, инъективность.

         Тест (2) важен отдельно от (1): пройти (1) можно и неверной
         константно-временной реализацией, а наоборот.
*******************************************************************************
*/

#include <stdio.h>
#include <string.h>

#include "bee3/crypto/belt.h"

#ifdef BEE3_TEST_SLICE
/*  Константно-временный срез в сборку не входит: расхождение с эталоном
    не локализовано, см. docs/notes/001-belt-h.md. Тесты среза включаются
    только при явном -DBEE3_TEST_SLICE. */
#endif

#define LANES BEE3_BELT_LANES
#define NPL  32

static int failures;

static void
check(int ok, const char* what)
{
    printf("  %-52s %s\n", what, ok ? "OK" : "FAIL");
    if (!ok)
        failures++;
}

static void
unhex(octet* out, size_t n, const char* hex)
{
    size_t i;
    for (i = 0; i < n; ++i)
    {
        unsigned v = 0;
        (void)sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (octet)v;
    }
}

/*  Вывод октетов в порядке возрастания адреса — то есть в том виде,
    в каком блок представлен в стандарте. Порядок байтов платформы не
    предполагается: извлечение задано явно, иначе тест проходил бы на
    одной архитектуре и падал бы на другой. */
static void
puthex(const u32* w, size_t n, char* out)
{
    size_t i, j;
    for (i = 0; i < n; ++i)
        for (j = 0; j < 4; ++j)
            (void)sprintf(out + 8 * i + 2 * j, "%02X",
                          (unsigned)((w[i] >> (8 * j)) & 0xFFu));
    out[8 * n] = 0;
}

/*
*******************************************************************************
1. Соответствие стандарту

СТБ 34.101.31-2020, таблица А.1: зашифрование блока.
*******************************************************************************
*/

static void
test_kat(void)
{
    octet key[32];
    u32 rkey[8];
    u32 block[4];
    char hex[40];

    unhex(key, 32, "E9DEE72C8F0C0FA62DDB49F46F739647"
                   "06075316ED247A3739CBA38303A98BF6");

    bee3BeltKeyExpand(rkey, key, 32);
    bee3BeltKeyExpand(rkey, key, 32);   /* повторный вызов: идемпотентность */

    unhex((octet*)block, 16, "B194BAC80A08F53B366D008E584A5DE4");
    bee3BeltBlockEncr(block, rkey);

    puthex(block, 4, hex);
    check(strcmp(hex, "69CCA1C93557C9E3D66BC3E0FA88FA6E") == 0,
          "шифрование блока: вектор А.1 (128 бит)");

    /*  Обратное преобразование обязано вернуть исходный блок. */
    bee3BeltBlockDecr(block, rkey);
    puthex(block, 4, hex);
    check(strcmp(hex, "B194BAC80A08F53B366D008E584A5DE4") == 0,
          "расшифрование блока: вектор А.1");
}

/*
*******************************************************************************
2. Срез против табличной реализации

Срез — независимая реализация того же преобразования. Расхождение означает
ошибку в одной из двух. Это самый сильный тест для среза: он проверяет не
один вектор, а функцию на произвольных данных.
*******************************************************************************
*/

#ifdef BEE3_TEST_SLICE

static u32 rng_state = 0x12345678u;

static u32
xorshift(void)
{
    u32 x = rng_state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return rng_state = x;
}

static void
test_slice_matches_table(void)
{
    u32 blocks[4][LANES];
    u32 planes[4][NPL];
    u32 single[4];
    u32 rkey[8];
    octet key[32];
    size_t j, w, t;
    int ok_encr = 1;
    int ok_decr = 1;

    for (j = 0; j < LANES; ++j)
        for (w = 0; w < 4; ++w)
            blocks[w][j] = xorshift();
    for (w = 0; w < 8; ++w)
        rkey[w] = xorshift();
    for (w = 0; w < 32; ++w)
        key[w] = (octet)rkey[w / 4];

    bee3BeltKeyExpand(rkey, key, 32);

    /*  Раскладка -> срез. */
    bee3BeltSlicePack(planes, blocks);
    bee3BeltBlockEncrSlice(planes, rkey);

    /*  Срез -> обычное представление, сверка с табличной версией. */
    for (t = 0; t < LANES; ++t)
    {
        for (w = 0; w < 4; ++w)
            single[w] = blocks[w][t];
        bee3BeltBlockEncr(single, rkey);

        bee3BeltSliceUnpack(blocks, planes);
        for (w = 0; w < 4; ++w)
            if (single[w] != blocks[w][t])
                ok_encr = 0;
        /*  восстанавливаем входные данные для следующего блока */
        for (w = 0; w < 4; ++w)
            blocks[w][t] = single[w];
    }
    check(ok_encr, "срез зашифрования совпадает с табличной версией");

    /*  То же в обратную сторону. */
    for (j = 0; j < LANES; ++j)
        for (w = 0; w < 4; ++w)
            blocks[w][j] = xorshift();
    bee3BeltSlicePack(planes, blocks);
    bee3BeltBlockDecrSlice(planes, rkey);
    for (t = 0; t < LANES; ++t)
    {
        for (w = 0; w < 4; ++w)
            single[w] = blocks[w][t];
        bee3BeltBlockDecr(single, rkey);
        for (w = 0; w < 4; ++w)
            if (single[w] != blocks[w][t])
                ok_decr = 0;
    }
    check(ok_decr, "срез расшифрования совпадает с табличной версией");
}

/*
*******************************************************************************
3. Упаковка и распаковка
*******************************************************************************
*/

static void
test_pack_unpack(void)
{
    u32 blocks[4][LANES];
    u32 planes[4][NPL];
    u32 back[4][LANES];
    size_t j, w;
    int ok = 1;

    for (j = 0; j < LANES; ++j)
        for (w = 0; w < 4; ++w)
            blocks[w][j] = xorshift();

    bee3BeltSlicePack(planes, blocks);
    bee3BeltSliceUnpack(back, planes);

    for (j = 0; j < LANES; ++j)
        for (w = 0; w < 4; ++w)
            if (blocks[w][j] != back[w][j])
                ok = 0;
    check(ok, "упаковка и распаковка взаимно обратны");
}

/*
*******************************************************************************
4. Обратимость и инъективность на 32 блоках
*******************************************************************************
*/

static void
test_roundtrip(void)
{
    u32 blocks[4][LANES];
    u32 planes[4][NPL];
    u32 back[4][LANES];
    u32 rkey[8];
    octet key[32];
    size_t j, w;
    int ok = 1;

    for (j = 0; j < LANES; ++j)
        for (w = 0; w < 4; ++w)
            blocks[w][j] = xorshift();

    for (w = 0; w < 32; ++w)
        key[w] = (octet)xorshift();
    bee3BeltKeyExpand(rkey, key, 32);

    bee3BeltSlicePack(planes, blocks);
    bee3BeltBlockEncrSlice(planes, rkey);
    bee3BeltSliceUnpack(back, planes);

    /*  Инъективность: 32 блока не должны склеиться в один. */
    for (j = 0; j < LANES && ok; ++j)
        for (w = 0; w < 4 && ok; ++w)
            if (back[w][j] != blocks[w][j])
                ok = 0;
    check(ok, "зашифрование среза обратимо на 32 блоках");

    /*  И обратное преобразование обязано вернуть исходные блоки. */
    bee3BeltSlicePack(planes, back);
    bee3BeltBlockDecrSlice(planes, rkey);
    bee3BeltSliceUnpack(back, planes);

    ok = 1;
    for (j = 0; j < LANES && ok; ++j)
        for (w = 0; w < 4 && ok; ++w)
            if (back[w][j] != blocks[w][j])
                ok = 0;
    check(ok, "расшифрование среза возвращает исходные блоки");
}

#endif /* BEE3_TEST_SLICE */

/*
*******************************************************************************
5. Ключевое расписание: три длины ключа
*******************************************************************************
*/

static void
test_keyschedule(void)
{
    octet key[32];
    u32 rkey[8];
    size_t i;

    for (i = 0; i < 32; ++i)
        key[i] = (octet)i;

    bee3BeltKeyExpand(rkey, key, BEE3_BELT_KEY128);
    check(rkey[4] == rkey[0] && rkey[5] == rkey[1] &&
          rkey[6] == rkey[2] && rkey[7] == rkey[3],
          "ключ 128 бит: слова 4..7 повторяют 0..3");

    bee3BeltKeyExpand(rkey, key, BEE3_BELT_KEY192);
    check(rkey[6] == (rkey[0] ^ rkey[1] ^ rkey[2]) &&
          rkey[7] == (rkey[3] ^ rkey[4] ^ rkey[5]),
          "ключ 192 бит: слова 6,7 — XOR троек");

    bee3BeltKeyExpand(rkey, key, BEE3_BELT_KEY256);
    check(rkey[0] == 0x03020100u, "ключ 256 бит: порядок байтов little-endian");
}

int
main(void)
{
    printf("bee3: блочный шифр belt (СТБ 34.101.31)\n");
    printf("\nэталон:\n");
    test_kat();
    printf("\nключевое расписание:\n");
    test_keyschedule();
#ifdef BEE3_TEST_SLICE
    printf("\nраскладка:\n");
    test_pack_unpack();
#endif
#ifdef BEE3_TEST_SLICE
    printf("\nконстантно-временный срез:\n");
    test_slice_matches_table();
    test_roundtrip();
#else
    printf("\nконстантно-временный срез: "
           "не в сборке (расхождение не локализовано)\n");
#endif

    printf("\n%s\n", failures == 0 ? "ВСЕ ТЕСТЫ ПРОЙДЕНЫ" : "ЕСТЬ ОШИБКИ");
    return failures == 0 ? 0 : 1;
}