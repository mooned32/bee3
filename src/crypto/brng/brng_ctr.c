/*
*******************************************************************************
\file    brng_ctr.c
\brief   Генерация псевдослучайных чисел в режиме счётчика,
         brng-ctr-hbelt (СТБ 34.101.47-2017, п. 6.2)
\project bee3 [cryptographic library]

\note    Проверено по таблице В.2 стандарта: все три слова при n = 3
        воспроизводятся побайтово.

\remark Сложение s <- s (+) <1> есть сложение 256-БИТНЫХ ЧИСЕЛ, а не
        прибавление единицы к каждому октету. Различие даёт правдоподобный
        вывод и не видно ни в одном тесте, кроме проверочного примера.
*******************************************************************************
*/

#include <stdlib.h>
#include <string.h>

#include "bee3/core/secure_mem.h"
#include "bee3/crypto/brng.h"
#include "bee3/crypto/belt.h"

void
bee3BrngCtr(
    octet* y,
    size_t n,
    const octet key[BEE3_BRNG_VALUE],
    const octet sync[BEE3_BRNG_VALUE],
    const octet* x,
    size_t xLen
)
{
    octet s[BEE3_BRNG_VALUE], r[BEE3_BRNG_VALUE];
    octet in[4 * BEE3_BRNG_VALUE];
    size_t i, j;

    /*  Шаг 1: s <- S */
    memcpy(s, sync, BEE3_BRNG_VALUE);

    /*  Шаг 2: r <- S xor 1^2л, то есть каждый октет инвертирован */
    for (i = 0; i < BEE3_BRNG_VALUE; ++i)
        r[i] = (octet)(sync[i] ^ 0xFF);

    /*  Шаг 3: для i = 1..n */
    for (i = 0; i < n; ++i)
    {
        /*  Шаг 3.1: Yi <- h(K || s || Xi || r) */
        memcpy(in, key, BEE3_BRNG_VALUE);
        memcpy(in + BEE3_BRNG_VALUE, s, BEE3_BRNG_VALUE);
        memset(in + 2 * BEE3_BRNG_VALUE, 0, BEE3_BRNG_VALUE);
        if (x != 0 && xLen >= (i + 1) * BEE3_BRNG_VALUE)
            memcpy(in + 2 * BEE3_BRNG_VALUE, x + i * BEE3_BRNG_VALUE,
                BEE3_BRNG_VALUE);
        memcpy(in + 3 * BEE3_BRNG_VALUE, r, BEE3_BRNG_VALUE);
        bee3BeltHash(y + i * BEE3_BRNG_VALUE, in, sizeof in);

        /*  Шаг 3.2: s <- s (+) <1>. Октет 0 — младший, перенос идёт
            в сторону старших октетов. Прибавление единицы к каждому
            октету раздельно — другая операция и другой стандарт. */
        for (j = 0; j < BEE3_BRNG_VALUE; ++j)
        {
            s[j] = (octet)(s[j] + 1);
            if (s[j] != 0)
                break;
        }

        /*  Шаг 3.3: r <- r xor Yi */
        for (j = 0; j < BEE3_BRNG_VALUE; ++j)
            r[j] = (octet)(r[j] ^ y[i * BEE3_BRNG_VALUE + j]);
    }

    bee3SecureZero(s, sizeof s);
    bee3SecureZero(r, sizeof r);
    bee3SecureZero(in, sizeof in);
}
/*  Генерация в режиме HMAC (СТБ 34.101.47-2017, п. 6.3).

    Функция h применяется косвенно, как элемент hmac[h]. Порядок шагов
    существенен: Y_i вычисляется ДО обновления r. Перестановка даёт
    другой, но столь же правдоподобный результат. */
void
bee3BrngHmacCtr(
    octet* y,
    size_t n,
    const octet* key,
    size_t keyLen,
    const octet* sync,
    size_t syncLen
)
{
    octet r[BEE3_BRNG_VALUE], prev[BEE3_BRNG_VALUE];
    octet* msg;
    size_t i;

    /*  Шаг 1: r <- hmac[h](K, S) */
    bee3BrngHmac(r, key, keyLen, sync, syncLen);

    msg = (octet*)malloc(syncLen + BEE3_BRNG_VALUE);
    if (msg == 0)
        return;

    /*  Шаг 2: для i = 1..n */
    for (i = 0; i < n; ++i)
    {
        /*  Шаг 2.1: Yi <- hmac[h](K, r || S) */
        memcpy(msg, r, BEE3_BRNG_VALUE);
        memcpy(msg + BEE3_BRNG_VALUE, sync, syncLen);
        bee3BrngHmac(y + i * BEE3_BRNG_VALUE, key, keyLen, msg,
            BEE3_BRNG_VALUE + syncLen);

        /*  Шаг 2.2: r <- hmac[h](K, r) */
        memcpy(prev, r, BEE3_BRNG_VALUE);
        bee3BrngHmac(r, key, keyLen, prev, BEE3_BRNG_VALUE);
    }

    bee3SecureZero(msg, syncLen + BEE3_BRNG_VALUE);
    free(msg);
    bee3SecureZero(r, sizeof r);
    bee3SecureZero(prev, sizeof prev);
}
