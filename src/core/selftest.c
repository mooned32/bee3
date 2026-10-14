/*
*******************************************************************************
\file    selftest.c
\brief   Самотестирование криптографических алгоритмов
\project bee3 [cryptographic library]

\purpose Требование СТ.3 СТБ 34.101.27-2022: «каждый криптографический
         алгоритм должен быть автоматически протестирован перед первым
         использованием». Функция даёт прикладной системе готовый блок
         самопроверки; решение о состоянии блокировки по требованию СТ.5
         остаётся за системой.

\note    Проверяются тестами известного ответа. Входы и выходы взяты из
        проверочных примеров стандартов и являются открытыми объектами,
        как того требует СТ.4.

\remark Функция не выделяет памяти и не обращается к изменяемому
        глобальному состоянию: только статические контрольные данные.
*******************************************************************************
*/

#include <string.h>

#include "bee3/core/secure_mem.h"
#include "bee3/core/selftest.h"
#include "bee3/crypto/bash.h"
#include "bee3/crypto/bash_prg.h"
#include "bee3/crypto/belt.h"
#include "bee3/crypto/brng.h"

#include "crypto/kat/kat_brng.h"
#include "crypto/kat/prg_kat.h"
#include "crypto/kat/vectors.h"

/*  Октеты состояния таблицы А.2 стандарта. Значения хранятся как числа,
    поэтому порядок октетов — от младшего к старшему, как в тексте
    стандарта. */
static void
putOctets(
    octet dst[BEE3_BASH_SIZE],
    const u64 src[24]
)
{
    size_t i;

    for (i = 0; i < BEE3_BASH_SIZE; ++i)
        dst[i] = (octet)(src[i / 8] >> (8 * (i % 8)));
}

static u32
loadWord(
    const octet* b
)
{
    return (u32)b[0] | ((u32)b[1] << 8) | ((u32)b[2] << 16) |
        ((u32)b[3] << 24);
}

/*  Простой воспроизводимый генератор: значения в самотесте не должны
    зависеть от состояния системы. */
static u32
nextRand(
    u32* st
)
{
    *st = *st * 1664525u + 1013904223u;
    return *st;
}

/*  1. Блочный шифр belt: вектор приложения А.1 и обратимость. */
static int
testBelt(
    void
)
{
    static const octet key[32] = {
        0xE9,0xDE,0xE7,0x2C,0x8F,0x0C,0x0F,0xA6, 0x2D,0xDB,0x49,0xF4,0x6F,0x73,0x96,0x47,
        0x06,0x07,0x53,0x16,0xED,0x24,0x7A,0x37, 0x39,0xCB,0xA3,0x83,0x03,0xA9,0x8B,0xF6 };
    static const octet plain[16] = {
        0xB1,0x94,0xBA,0xC8,0x0A,0x08,0xF5,0x3B, 0x36,0x6D,0x00,0x8E,0x58,0x4A,0x5D,0xE4 };
    static const octet ciph[16] = {
        0x69,0xCC,0xA1,0xC9,0x35,0x57,0xC9,0xE3, 0xD6,0x6B,0xC3,0xE0,0xFA,0x88,0xFA,0x6E };
    u32 blk[4], back[4], k[8];
    int ok;

    bee3BeltKeyExpand(k, key, BEE3_BELT_KEY256);
    blk[0] = loadWord(plain);
    blk[1] = loadWord(plain + 4);
    blk[2] = loadWord(plain + 8);
    blk[3] = loadWord(plain + 12);

    bee3BeltBlockEncr(blk, k);
    ok = (blk[0] == loadWord(ciph)) && (blk[1] == loadWord(ciph + 4)) &&
        (blk[2] == loadWord(ciph + 8)) && (blk[3] == loadWord(ciph + 12));

    memcpy(back, blk, sizeof back);
    bee3BeltBlockDecr(back, k);
    ok &= (back[0] == loadWord(plain)) && (back[1] == loadWord(plain + 4)) &&
        (back[2] == loadWord(plain + 8)) && (back[3] == loadWord(plain + 12));

    bee3SecureZero(blk, sizeof blk);
    bee3SecureZero(back, sizeof back);
    bee3SecureZero(k, sizeof k);
    return ok;
}

/*  2. Сжатие и хэширование belt: таблица А.8 и контрольные значения
    на границах блоков. */
static int
testBeltHash(
    void
)
{
    static const octet* const exp[8] = {
        belt_hash_msg_l0, belt_hash_msg_l1, belt_hash_msg_l31,
        belt_hash_msg_l32, belt_hash_msg_l33, belt_hash_msg_l39,
        belt_hash_msg_l40, belt_hash_msg_l64 };
    octet s[16], y[32], h[32];
    size_t i;
    int ok;

    bee3BeltCompr(s, y, belt_compr_a8_in);
    ok = bee3SecureEq(s, belt_compr_a8_s, 16) &&
        bee3SecureEq(y, belt_compr_a8_y, 32);

    for (i = 0; i < sizeof belt_hash_lens / sizeof belt_hash_lens[0]; ++i)
    {
        bee3BeltHash(h, belt_hash_msg, belt_hash_lens[i]);
        ok &= bee3SecureEq(h, exp[i], 32);
    }

    bee3SecureZero(h, sizeof h);
    return ok;
}

/*  3. Константно-временный срез обязан давать тот же результат, что и
    табличная версия. Это самая сильная проверка среза: сравниваются
    функции на произвольных данных, а не один вектор. */
static int
testBeltSlice(
    void
)
{
    u32 blk[4][BEE3_BELT_LANES];
    u32 planes[4][BEE3_BELT_NPL];
    u32 back[4][BEE3_BELT_LANES];
    u32 one[4], rkey[8];
    octet key[32];
    size_t i, j;
    int ok = 1;
    u32 st = 0x2468ACE0u;

    for (i = 0; i < 32; ++i)
        key[i] = (octet)(nextRand(&st) >> 24);
    bee3BeltKeyExpand(rkey, key, BEE3_BELT_KEY256);

    for (j = 0; j < BEE3_BELT_LANES; ++j)
        for (i = 0; i < 4; ++i)
            blk[i][j] = nextRand(&st);

    bee3BeltSlicePack(planes, blk);
    bee3BeltBlockEncrSlice(planes, rkey);
    bee3BeltSliceUnpack(back, planes);

    for (j = 0; j < BEE3_BELT_LANES && ok; ++j)
    {
        one[0] = blk[0][j];
        one[1] = blk[1][j];
        one[2] = blk[2][j];
        one[3] = blk[3][j];
        bee3BeltBlockEncr(one, rkey);
        for (i = 0; i < 4; ++i)
            if (one[i] != back[i][j])
                ok = 0;
    }

    /*  И обратное преобразование обязано вернуть исходные блоки. */
    bee3BeltBlockDecrSlice(planes, rkey);
    bee3BeltSliceUnpack(back, planes);
    for (j = 0; j < BEE3_BELT_LANES && ok; ++j)
        for (i = 0; i < 4; ++i)
            if (back[i][j] != blk[i][j])
                ok = 0;

    bee3SecureZero(rkey, sizeof rkey);
    bee3SecureZero(blk, sizeof blk);
    return ok;
}

/*  4. Sponge-функция bash и её хэширование: таблицы А.1 и А.3.

    Таблица А.1 — не снимки состояния, а пошаговая трассировка операций
    такта над тремя 64-битными словами. Поэтому проверяется трассировка, а
    не последовательность вызовов bee3BashF(). */
static u64
rotHi(
    u64 w,
    unsigned n
)
{
    return n == 0 ? w : ((w << n) | (w >> (64 - n)));
}

static int
testBash(void)
{
    octet msg[BEE3_BASH_SIZE], hash[64];
    u64 w0, w1, w2, t0, t1, t2;
    size_t i;
    int ok = 1;

    w0 = a1_in[0];
    w1 = a1_in[1];
    w2 = a1_in[2];

    t0 = rotHi(w0, 8);
    ok &= (t0 == a1_step[0]);
    w0 ^= w1 ^ w2;
    ok &= (w0 == a1_step[1]);
    t1 = w1 ^ rotHi(w0, 53);
    ok &= (t1 == a1_step[2]);
    w1 = t0 ^ t1;
    ok &= (w1 == a1_step[3]);
    w2 ^= rotHi(w2, 14) ^ rotHi(t1, 1);
    ok &= (w2 == a1_step[4]);
    t0 = ~w2;
    ok &= (t0 == a1_step[5]);
    t1 = w0 | w2;
    ok &= (t1 == a1_step[6]);
    t2 = w0 & w1;
    ok &= (t2 == a1_step[7]);
    t0 |= w1;
    ok &= (t0 == a1_step[8]);
    w1 ^= t1;
    ok &= (w1 == a1_step[9]);
    w2 ^= t2;
    ok &= (w2 == a1_step[10]);
    w0 ^= t0;
    ok &= (w0 == a1_step[11]);

    putOctets(msg, a2_in);
    for (i = 0; i < sizeof a3 / sizeof a3[0]; ++i)
    {
        bee3BashHash(hash, a3[i].hashLen, msg, a3[i].len);
        ok &= (memcmp(hash, a3[i].hash, a3[i].hashLen) == 0);
    }

    bee3SecureZero(msg, sizeof msg);
    bee3SecureZero(hash, sizeof hash);
    return ok;
}

/*  5. Программируемые алгоритмы bash-prg: аутентифицированное шифрование. */
static int
testBashPrg(void)
{
    octet msg[300], mac[32], ciph[256], out[256];
    size_t i;
    int ok = 1;

    putOctets(msg, a2_in);
    for (i = 0; i < sizeof msg - BEE3_BASH_SIZE; ++i)
        msg[BEE3_BASH_SIZE + i] = msg[i];

    for (i = 0; i < sizeof prg_kat / sizeof prg_kat[0]; ++i)
    {
        bee3BashPrgAeadEncr(mac, ciph, msg, prg_kat[i].annLen,
            msg, prg_kat[i].msgLen, msg, prg_kat[i].adLen,
            msg + 200, prg_kat[i].keyLen, prg_kat[i].l, prg_kat[i].d);
        ok &= bee3SecureEq(mac, prg_kat[i].mac, prg_kat[i].l / 8);
        ok &= bee3SecureEq(ciph, prg_kat[i].ciph, prg_kat[i].msgLen);

        ok &= (bee3BashPrgAeadDecr(out, mac, ciph, prg_kat[i].msgLen,
            msg, prg_kat[i].annLen, msg, prg_kat[i].adLen,
            msg + 200, prg_kat[i].keyLen, prg_kat[i].l, prg_kat[i].d) != 0);
        ok &= bee3SecureEq(out, msg, prg_kat[i].msgLen);
    }

    bee3SecureZero(msg, sizeof msg);
    bee3SecureZero(out, sizeof out);
    return ok;
}

/*  6. Генератор псевдослучайных чисел и одноразовые пароли:
    таблицы В.1 — В.6. */
static int
testBrng(void)
{
    static const octet* const exp[5] = {
        brng_short_mac_l0, brng_short_mac_l1, brng_short_mac_l31,
        brng_short_mac_l32, brng_short_mac_l33 };
    octet y[96], mac[32];
    size_t i;
    int ok;

    bee3BrngHmac(mac, brng_b1_key, sizeof brng_b1_key,
        brng_b1_msg, sizeof brng_b1_msg);
    ok = bee3SecureEq(mac, brng_b1_mac, 32);

    for (i = 0; i < 5; ++i)
    {
        bee3BrngHmac(mac, brng_b1_key, sizeof brng_b1_key,
            brng_short_msg, brng_short_lens[i]);
        ok &= bee3SecureEq(mac, exp[i], 32);
    }

    bee3BrngCtr(y, 3, brng_b2_key, brng_b2_sync, brng_b2_x, sizeof brng_b2_x);
    ok &= bee3SecureEq(y, brng_b2_y, 96);

    bee3BrngHmacCtr(y, 3, brng_b2_key, 32, brng_b2_sync, 32);
    ok &= bee3SecureEq(y, brng_c3_y, 96);

    for (i = 0; i < 3; ++i)
        ok &= (bee3OtpHotp(8, brng_b1_key, sizeof brng_b1_key,
            brng_hotp_cnt[i]) == brng_hotp_res[i]);
    for (i = 0; i < 3; ++i)
        ok &= (bee3OtpTotp(8, brng_b1_key, sizeof brng_b1_key,
            brng_totp_time[i], 0, 60) == brng_totp_res[i]);

    bee3SecureZero(y, sizeof y);
    bee3SecureZero(mac, sizeof mac);
    return ok;
}

int
bee3SelfTest(
    void
)
{
    /*  Группы проверяются независимо: первая непройденная возвращается
        немедленно, чтобы не смешивать признаки разных отказов в один. */
    if (!testBelt())
        return 1;
    if (!testBeltHash())
        return 2;
    if (!testBeltSlice())
        return 3;
    if (!testBash())
        return 4;
    if (!testBashPrg())
        return 5;
    if (!testBrng())
        return 6;
    return 0;
}