/*
*******************************************************************************
\file    belt_compr.c
\brief   Сжатие belt-compress (СТБ 34.101.31-2020, п. 6.3)
\project bee3 [cryptographic library]

\note    Проверено по таблице А.8: S и Y воспроизводятся побайтово.
        См. docs/notes/004-belt-compress.md.

\note    Определение приведено буквально по тексту стандарта:
            (X1, X2, X3, X4) = Split(X, 128)
            S  <- belt-block(X3 xor X4, X1 || X2) xor X3 xor X4
            Y1 <- belt-block(X1, S || X4) xor X1
            Y2 <- belt-block(X2, (S xor 1^128) || X3) xor X2

        Число 1^128 — это 128 единиц, то есть КАЖДЫЙ октет равен 0xFF.
        Замена его на 0x80 неверна и внешне неотличима.
*******************************************************************************
*/

#include <string.h>

#include "bee3/core/secure_mem.h"
#include "bee3/crypto/belt.h"

/*  Загрузка октетов в 32-битные слова.

    Стандарт записывает октеты от младшего к старшему, то есть октет 0 —
    младший байт первого слова. Приведение указателей не используется:
    запись через octet* в объект типа u32[] нарушает строгие псевдонимы,
    и компилятор на -O2 подставляет вместо данных значения длины. */
static void
load32(
    u32 w[4],
    const octet b[16]
)
{
    size_t i;

    w[0] = w[1] = w[2] = w[3] = 0;
    for (i = 0; i < 16; ++i)
        w[i / 4] |= (u32)b[i] << (8 * (i % 4));
}

static void
store32(
    octet b[16],
    const u32 w[4]
)
{
    size_t i;

    for (i = 0; i < 16; ++i)
        b[i] = (octet)(w[i / 4] >> (8 * (i % 4)));
}

/*  belt-block: блок 128 бит, ключ 256 бит. Раундовый ключ для длины
    256 бит получается раскладкой исходного ключа без преобразования
    (bee3BeltKeyExpand), поэтому вызывается штатная функция. */
static void
blk(
    octet out[16],
    const octet in[16],
    const octet key[32]
)
{
    u32 b[4], k[8];

    load32(b, in);
    bee3BeltKeyExpand(k, key, BEE3_BELT_KEY256);
    bee3BeltBlockEncr(b, k);
    store32(out, b);
}

void
bee3BeltCompr(
    octet s[16],
    octet y[32],
    const octet x[64]
)
{
    octet key[32], acc[16], y1[16], y2[16];
    size_t i;

    /*  X1 = x[0..15], X2 = x[16..31], X3 = x[32..47], X4 = x[48..63] */

    /*  2. S <- belt-block(X3 xor X4, X1 || X2) xor X3 xor X4 */
    for (i = 0; i < 16; ++i)
        acc[i] = (octet)(x[32 + i] ^ x[48 + i]);
    memcpy(key, x, 32);
    blk(acc, acc, key);
    for (i = 0; i < 16; ++i)
        acc[i] = (octet)(acc[i] ^ x[32 + i] ^ x[48 + i]);

    /*  3. Y1 <- belt-block(X1, S || X4) xor X1 */
    memcpy(key, acc, 16);
    for (i = 0; i < 16; ++i)
        key[16 + i] = x[48 + i];
    blk(y1, x, key);
    for (i = 0; i < 16; ++i)
        y1[i] = (octet)(y1[i] ^ x[i]);

    /*  4. Y2 <- belt-block(X2, (S xor 1^128) || X3) xor X2
        1^128 — 128 единиц: каждый октет равен 0xFF. */
    for (i = 0; i < 16; ++i)
        key[i] = (octet)(acc[i] ^ 0xFF);
    for (i = 0; i < 16; ++i)
        key[16 + i] = x[32 + i];
    blk(y2, x + 16, key);
    for (i = 0; i < 16; ++i)
        y2[i] = (octet)(y2[i] ^ x[16 + i]);

    /*  5. вернуть (S, Y), где Y = Y1 || Y2 */
    memcpy(s, acc, 16);
    memcpy(y, y1, 16);
    memcpy(y + 16, y2, 16);

    bee3SecureZero(key, sizeof key);
    bee3SecureZero(acc, sizeof acc);
    bee3SecureZero(y1, sizeof y1);
    bee3SecureZero(y2, sizeof y2);
}