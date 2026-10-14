/*
*******************************************************************************
\file    belt_hash.c
\brief   Хэширование belt-hash (СТБ 34.101.31-2020, п. 7.8)
\project bee3 [cryptographic library]

\note    Проверено по эталонной реализации на 41 длине сообщения от 0 до
        40 октетов подряд, включая все неполные блоки.
        См. docs/notes/004-belt-compress.md.

\note    Три ошибки, найденные при переносе, зафиксированы в коде, и каждая
        из них давала правдоподобный результат:
          1. число блоков считалось целочисленным делением, и хвост
             сообщения терялся — стандарт требует дополнения нулями;
          2. начальное состояние было transкрибировано с ошибкой в одном
             октете (0x16 вместо 0x36);
          3. длина записывалась сдвигом на ширину типа — это неопределённое
             поведение, и компилятор записывал значение дважды.

        Третья ошибка особенно неприятна: -Wall -Wextra о ней молчит.
*******************************************************************************
*/

#include <string.h>

#include "bee3/core/secure_mem.h"
#include "bee3/crypto/belt.h"

/*  Начальное состояние h, п. 7.8.3 шаг 2.3. Первые две строки
    таблицы 2 стандарта. */
static const octet BEE3_BELT_HASH_IV[32] = {
    0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B,
    0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
    0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC,
    0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D };

void
bee3BeltHash(
    octet y[32],
    const octet* x,
    size_t len
)
{
    octet r[16], s[16], h[32], in[64], t[16];
    size_t i, n, off;

    /*  Шаг 1: (X1..Xn) = Split(X, 256).
        Шаг 2.4: последний блок дополняется нулями, поэтому число блоков
        равно ПОТОЛКУ от деления, а не частному. При частном хвост
        сообщения не обрабатывался вовсе. */
    n = (len + 31) / 32;

    /*  Шаг 2.1: r <- <|X|>128, длина в битах.

        Сдвиг на ширину типа — НЕОПРЕДЕЛЁННОЕ ПОВЕДЕНИЕ. При i = 8
        выражение bits >> 64 выходит за границы size_t, и компилятор на
        -O2 подставлял значение повторно: длина оказывалась записанной
        дважды, а хэш пустого сообщения оставался верным. Поэтому сдвиг
        выполняется ТОЛЬКО в пределах ширины типа. */
    memset(r, 0, sizeof r);
    {
        const u64 bits = (u64)len * 8;
        for (i = 0; i < sizeof bits; ++i)
            r[i] = (octet)((bits >> (8 * i)) & 0xFF);
    }

    /*  Шаг 2.2: s <- 0^128 */
    memset(s, 0, sizeof s);

    /*  Шаг 2.3: h <- IV */
    memcpy(h, BEE3_BELT_HASH_IV, 32);

    /*  Шаг 3: для i = 1..n: (t, h) <- belt-compress(Xi || h); s <- s xor t */
    for (i = 0; i < n; ++i)
    {
        off = i * 32;
        memset(in, 0, sizeof in);
        if (off < len)
        {
            const size_t take = (len - off < 32) ? len - off : 32;
            memcpy(in, x + off, take);
        }
        memcpy(in + 32, h, 32);
        bee3BeltCompr(t, h, in);
        for (off = 0; off < 16; ++off)
            s[off] = (octet)(s[off] ^ t[off]);
    }

    /*  Шаг 4: (⊥, Y) <- belt-compress(r || s || h) */
    memset(in, 0, sizeof in);
    memcpy(in, r, 16);
    memcpy(in + 16, s, 16);
    memcpy(in + 32, h, 32);
    bee3BeltCompr(t, y, in);

    bee3SecureZero(r, sizeof r);
    bee3SecureZero(s, sizeof s);
    bee3SecureZero(h, sizeof h);
    bee3SecureZero(in, sizeof in);
    bee3SecureZero(t, sizeof t);
}