/*
*******************************************************************************
\file    brng_hmac.c
\brief   Имитовставка в режиме HMAC, hmac[hbelt] (СТБ 34.101.47-2017, п. 6.1)
\project bee3 [cryptographic library]

\note    Проверено по таблице В.1 стандарта.

\remark Отличие HMAC от «использовать хеш как контрольную сумму с секретным
        ключём» — не в соглашении, а в конструкции: ключ добавляется к
        сообщению под двумя разными словами (ipad и opad) с разными
        значениями октета. Именно это не позволяет вычислить внутреннее
        состояние хеша наKnown сообщении.
*******************************************************************************
*/

#include <stdlib.h>
#include <string.h>

#include "bee3/core/secure_mem.h"
#include "bee3/crypto/brng.h"
#include "bee3/crypto/belt.h"

/*  П. 6.1.3: ipad и opad — слова длиной b, составленные из повторений
    октетов 0x36 и 0x5C. При b = 256 это по 32 октета. */
static void
padWord(
    octet out[BEE3_BRNG_BLOCK],
    octet fill
)
{
    memset(out, fill, BEE3_BRNG_BLOCK);
}

void
bee3BrngHmac(
    octet y[BEE3_BRNG_VALUE],
    const octet* key,
    size_t keyLen,
    const octet* msg,
    size_t msgLen
)
{
    octet t[BEE3_BRNG_BLOCK], ipad[BEE3_BRNG_BLOCK], opad[BEE3_BRNG_BLOCK];
    octet* buf;
    /*  ДЛИНА ВХОДА шага 2 и РАЗМЕР БУФЕРА — разные вещи, и их нельзя
        отождествлять. Шаг 2 хэширует ровно b + |X| октетов. Шаг 3
        хэширует b + 2л = 64 октета независимо от |X|. Буфер должен
        вмещать оба: при |X| < 32 прежний размер оказывался меньше
        нужного, и шаг 3 писал за его пределы. */
    const size_t inSize = BEE3_BRNG_BLOCK + msgLen;
    const size_t bufSize = (inSize > BEE3_BRNG_BLOCK + BEE3_BRNG_VALUE)
        ? inSize
        : (size_t)(BEE3_BRNG_BLOCK + BEE3_BRNG_VALUE);
    size_t i;

    /*  Шаг 1: если |K| <= b, то t <- K || 0^(b-|K|), иначе
        t <- h(K) || 0^(b-2л).

        Второй случай требует хэширования ключа, а освободившуюся часть
        дополнять нужно нулём до b - 2л = 0 октетов, то есть ничего. */
    if (keyLen <= BEE3_BRNG_BLOCK)
    {
        memcpy(t, key, keyLen);
        memset(t + keyLen, 0, BEE3_BRNG_BLOCK - keyLen);
    }
    else
    {
        bee3BeltHash(t, key, keyLen);
    }

    padWord(ipad, 0x36);
    padWord(opad, 0x5C);
    for (i = 0; i < BEE3_BRNG_BLOCK; ++i)
    {
        ipad[i] = (octet)(ipad[i] ^ t[i]);
        opad[i] = (octet)(opad[i] ^ t[i]);
    }

    /*  Буфер выделяется один раз и вмещает оба шага. */
    buf = (octet*)malloc(bufSize);
    if (buf == 0)
    {
        bee3SecureZero(t, sizeof t);
        bee3SecureZero(ipad, sizeof ipad);
        bee3SecureZero(opad, sizeof opad);
        return;
    }

    /*  Шаг 2: Y <- h((t xor ipad) || X) */
    memcpy(buf, ipad, BEE3_BRNG_BLOCK);
    memcpy(buf + BEE3_BRNG_BLOCK, msg, msgLen);
    bee3BeltHash(y, buf, inSize);

    /*  Шаг 3: Y <- h((t xor opad) || Y) */
    memcpy(buf, opad, BEE3_BRNG_BLOCK);
    memcpy(buf + BEE3_BRNG_BLOCK, y, BEE3_BRNG_VALUE);
    bee3BeltHash(y, buf, BEE3_BRNG_BLOCK + BEE3_BRNG_VALUE);

    bee3SecureZero(buf, bufSize);
    free(buf);
    bee3SecureZero(t, sizeof t);
    bee3SecureZero(ipad, sizeof ipad);
    bee3SecureZero(opad, sizeof opad);
}