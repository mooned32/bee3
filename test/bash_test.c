/*
*******************************************************************************
\file    bash_test.c
\brief   Проверочный тест sponge-функции bash и хэширования bash-hash
         (СТБ 34.101.77-2020)

\note    Тест построен так, чтобы утверждение «реализация верна» не опиралось
        на рассуждение. В нём есть независимая реализация, составленная
        буквально по тексту стандарта: она выполняет перестановку явно, по
        таблице, на каждом такте, и вычисляет тактовые константы по формуле
        стандарта, а не читает их из массива. Сверка с ней проверяет свёрнутые
        индексы времени компиляции в bee3BashF(), которые иначе нечем проверить.
*******************************************************************************
*/

#include <stdio.h>
#include <string.h>

#include "bee3/crypto/bash.h"
#include "kat/vectors.h"

/*
*******************************************************************************
Эталонная реализация по тексту стандарта

Намеренно написана «неправильно» с точки зрения скорости: перестановка
выполняется явно через промежуточный массив, константы вычисляются заново на
каждом такте. Именно эта неэффективность и делает её пригодной для проверки.
*******************************************************************************
*/

static u64
refRotHi(
    u64 w,
    unsigned n
)
{
    return n == 0 ? w : ((w << n) | (w >> (64 - n)));
}

/*  СТБ 34.101.77-2020, п. 6.1.3, все 12 шагов. */
static void
refBashS(
    u64* w0,
    u64* w1,
    u64* w2,
    u64 m1,
    u64 n1,
    u64 m2,
    u64 n2
)
{
    u64 t0 = refRotHi(*w0, (unsigned)m1);
    u64 t1;
    u64 t2;

    *w0 ^= *w1 ^ *w2;                                  /* 2 */
    t1 = *w1 ^ refRotHi(*w0, (unsigned)n1);            /* 3 */
    *w1 = t0 ^ t1;                                     /* 4 */
    *w2 ^= refRotHi(*w2, (unsigned)m2) ^ refRotHi(t1, (unsigned)n2);  /* 5 */
    t0 = ~*w2;                                         /* 6 */
    t1 = *w0 | *w2;                                    /* 7 */
    t2 = *w0 & *w1;                                    /* 8 */
    t0 |= *w1;                                         /* 9 */
    *w1 ^= t1;                                         /* 10 */
    *w2 ^= t2;                                         /* 11 */
    *w0 ^= t0;                                         /* 12 */
}

/*  СТБ 34.101.77-2020, п. 6.2, шаг 2 — такт целиком. */
static void
refRound(
    u64 s[24]
)
{
    u64 m1 = 8, n1 = 53, m2 = 14, n2 = 1;
    size_t j;

    for (j = 0; j < 8; ++j)
    {
        refBashS(&s[j], &s[8 + j], &s[16 + j], m1, n1, m2, n2);
        m1 = (7 * m1) % 64;
        n1 = (7 * n1) % 64;
        m2 = (7 * m2) % 64;
        n2 = (7 * n2) % 64;
    }
}

/*  СТБ 34.101.77-2020, п. 6.2: 24 такта, перестановка и константа.
    Константы вычисляются по правилу стандарта, а не берутся из массива. */
static void
refBashF(
    u64 s[24]
)
{
    /*  Числовое значение слова, напечатанного в стандарте как «B194BAC8
        0A08F53B». Октеты в стандарте идут от младшего к старшему. */
    const u64 c0 = 0x3BF5080AC8BA94B1ULL;
    const u64 a = 0xDC2BE1997FE0D8AEULL;
    const octet* p = bee3BashPerm();
    u64 c = c0;
    size_t t;

    for (t = 0; t < BEE3_BASH_ROUNDS; ++t)
    {
        u64 tmp[24];
        size_t i;

        refRound(s);

        for (i = 0; i < 24; ++i)
            tmp[i] = s[p[i]];
        memcpy(s, tmp, sizeof tmp);
        s[23] ^= c;

        c = (c >> 1) ^ ((c & 1) ? a : 0);
    }
}

/*
*******************************************************************************
Вспомогательное
*******************************************************************************
*/

static int failed = 0;

static void
check(
    const char* what,
    int ok
)
{
    printf("  %-46s %s\n", what, ok ? "OK" : "РАСХОЖДЕНИЕ");
    if (!ok)
        failed = 1;
}

static int
eqWords(
    const u64 a[24],
    const u64 b[24]
)
{
    size_t i;
    for (i = 0; i < 24; ++i)
        if (a[i] != b[i])
            return 0;
    return 1;
}

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

static u32 rngState = 0x13579BDFu;

static u32
rng(
    void
)
{
    rngState ^= rngState << 13;
    rngState ^= rngState >> 17;
    rngState ^= rngState << 5;
    return rngState;
}

/*
*******************************************************************************
Проверки
*******************************************************************************
*/

/*  Таблица А.1: пошаговая сверка bash-s с опубликованными значениями.
    Это единственная проверка, которая подтверждает, что эталонная реализация
    в этом файле записана верно: без неё сверка с ней ничего не доказывала бы. */
static void
testBashS(
    void
)
{
    u64 w[3];
    u64 t0, t1, t2;
    size_t step = 0;
    int ok = 1;

    w[0] = a1_in[0];
    w[1] = a1_in[1];
    w[2] = a1_in[2];

    t0 = refRotHi(w[0], 8);
    ok &= (t0 == a1_step[0]);                                             ++step;
    w[0] ^= w[1] ^ w[2];
    ok &= (w[0] == a1_step[1]);                                           ++step;
    t1 = w[1] ^ refRotHi(w[0], 53);
    ok &= (t1 == a1_step[2]);                                             ++step;
    w[1] = t0 ^ t1;
    ok &= (w[1] == a1_step[3]);                                           ++step;
    w[2] ^= refRotHi(w[2], 14) ^ refRotHi(t1, 1);
    ok &= (w[2] == a1_step[4]);                                           ++step;
    t0 = ~w[2];
    ok &= (t0 == a1_step[5]);                                             ++step;
    t1 = w[0] | w[2];
    ok &= (t1 == a1_step[6]);                                             ++step;
    t2 = w[0] & w[1];
    ok &= (t2 == a1_step[7]);                                             ++step;
    t0 |= w[1];
    ok &= (t0 == a1_step[8]);                                             ++step;
    w[1] ^= t1;
    ok &= (w[1] == a1_step[9]);                                           ++step;
    w[2] ^= t2;
    ok &= (w[2] == a1_step[10]);                                          ++step;
    w[0] ^= t0;
    ok &= (w[0] == a1_step[11]);                                          ++step;

    check("таблица А.1: 12 шагов bash-s", ok && step == 12);
}

/*  Перестановка P: таблица должна совпадать с текстом п. 6.2, шаг 3 в). */
static void
testPerm(
    void
)
{
    static const octet expect[24] = {
        15, 10,  9, 12, 11, 14, 13,  8,
        17, 16, 19, 18, 21, 20, 23, 22,
         6,  3,  0,  5,  2,  7,  4,  1
    };
    const octet* p = bee3BashPerm();
    size_t i;
    int ok = 1;

    for (i = 0; i < 24; ++i)
        ok &= (p[i] == expect[i]);

    /*  Порядок перестановки равен 6 — на этом построена раскладка тактов. */
    for (i = 0; i < 24; ++i)
    {
        size_t x = i;
        size_t k;
        for (k = 0; k < 6; ++k)
            x = p[x];
        ok &= (x == i);
    }

    check("перестановка P и её порядок 6", ok);
}

/*  Таблица А.2: вход и выход bash-f. */
static void
testBashF(
    void
)
{
    u64 s[24];
    size_t i;

    /*  Эталон должен совпадать со стандартом сам по себе: иначе сверка с ним
        ничего не доказывала бы. */
    memcpy(s, a2_in, sizeof s);
    refBashF(s);
    check("таблица А.2: эталон по тексту стандарта", eqWords(s, a2_out));

    memcpy(s, a2_in, sizeof s);
    bee3BashF(s);
    check("таблица А.2: bash-f(S)", eqWords(s, a2_out));

    /*  В каждом такте восемь троек должны адресовать все 24 слова ровно по
        одному разу. Иначе слово обрабатывается дважды или пропускается, и
        результат зависит от порядка, который стандарт не задаёт.

        Отдельно отмечается то, что часто предполагают по ошибке: bash-f НЕ
        является инволюцией. Раскладка P^24 действительно тождественная, но в
        алгоритме есть тактовые константы, поэтому повторное применение
        перестановки не возвращает исходное состояние. Проверять это нечем. */

    /*  Свёрка со свёрнутой по времени компиляции реализацией. */
    {
        int ok = 1;
        for (i = 0; i < 500; ++i)
        {
            u64 x[24];
            size_t k;

            for (k = 0; k < 24; ++k)
                x[k] = ((u64)rng() << 32) ^ rng();

            memcpy(s, x, sizeof s);
            bee3BashF(s);
            refBashF(x);
            if (!eqWords(s, x))
            {
                ok = 0;
                break;
            }
        }
        check("500 случайных состояний против эталона", ok);
    }
}

/*  Адресация внутри такта. */
static void
testRoundCover(
    void
)
{
    const octet* p = bee3BashPerm();
    size_t t;
    int ok = 1;

    for (t = 0; t < 24; ++t)
    {
        unsigned seen[24] = { 0 };
        size_t j;

        for (j = 0; j < 24; ++j)
        {
            /*  физическая ячейка, из которой такт r читает логическое слово j */
            int x = (int)j;
            size_t k;
            for (k = 0; k < t; ++k)
                x = p[x];
            if (++seen[x] != 1)
                ok = 0;
        }
    }
    check("каждый такт адресует все 24 слова ровно раз", ok);
}

/*  Преобразование представления. */
static void
testPack(
    void
)
{
    octet buf[BEE3_BASH_SIZE];
    octet ref[BEE3_BASH_SIZE];
    u64 s[24];

    putOctets(buf, a2_in);
    bee3BashPack(s, buf);
    check("bee3BashPack восстанавливает состояние", eqWords(s, a2_in));

    bee3BashUnpack(buf, a2_in);
    putOctets(ref, a2_in);
    check("bee3BashUnpack даёт октеты от младшего",
        memcmp(buf, ref, BEE3_BASH_SIZE) == 0);
}

/*  Таблица А.3: все опубликованные значения хэширования. */
static void
testHash(
    void
)
{
    octet msg[BEE3_BASH_SIZE];
    octet hash[64];
    size_t i;
    int ok = 1;
    int n = 0;

    putOctets(msg, a2_in);

    for (i = 0; i < sizeof a3 / sizeof a3[0]; ++i)
    {
        bee3BashHash(hash, a3[i].hashLen, msg, a3[i].len);
        ok &= (memcmp(hash, a3[i].hash, a3[i].hashLen) == 0);
        ++n;
    }
    check("таблица А.3: все значения bash-hash", ok);
    printf("      проверено значений: %d\n", n);
}

/*  Построчный интерфейс обязан совпадать с однократным. */
static void
testStreaming(
    void
)
{
    octet msg[BEE3_BASH_SIZE];
    octet h1[64];
    octet h2[64];
    size_t hashLen;
    size_t len;
    int ok = 1;

    putOctets(msg, a2_in);

    for (hashLen = 32; hashLen <= 64; hashLen += 16)
    {
        for (len = 0; len <= BEE3_BASH_SIZE; ++len)
        {
            bee3BashState st;
            size_t chunk;

            bee3BashHash(h1, hashLen, msg, len);

            bee3BashInit(&st, hashLen);
            for (chunk = 0; chunk < len; chunk += 7)
            {
                const size_t take = (len - chunk < 7) ? len - chunk : 7;
                bee3BashUpdate(&st, msg + chunk, take);
            }
            bee3BashFinal(&st, h2, hashLen);
            bee3BashClean(&st);

            ok &= (memcmp(h1, h2, hashLen) == 0);
        }
    }
    check("построчный интерфейс == однократный", ok);
}

/*  Отличие соседних сообщений должно затрагивать весь хэш: проверка на
    «диффузность» конкретного экземпляра, а не доказательство стойкости. */
static void
testAvalanche(
    void
)
{
    octet msg[BEE3_BASH_SIZE];
    octet h1[64];
    octet h2[64];
    size_t bits = 0;
    size_t i;
    size_t j;

    putOctets(msg, a2_in);
    bee3BashHash(h1, 32, msg, 64);
    msg[0] ^= 1;
    bee3BashHash(h2, 32, msg, 64);

    for (i = 0; i < 32; ++i)
    {
        octet d = (octet)(h1[i] ^ h2[i]);
        for (j = 0; j < 8; ++j)
            if ((d >> j) & 1)
                ++bits;
    }
    printf("      изменившихся битов: %zu из 256\n", bits);
    check("диффузность разумна (100..156 бит)", bits >= 100 && bits <= 156);
}

int
main(
    void
)
{
    printf("bee3: sponge-функция bash и хэширование (СТБ 34.101.77)\n\n");

    printf("промежуточные проверки:\n");
    testPerm();
    testRoundCover();
    testBashS();
    printf("\n");
    printf("эталон:\n");
    testBashF();
    testPack();
    printf("\n");
    printf("хэширование:\n");
    testHash();
    testStreaming();
    testAvalanche();

    printf("\n");
    if (failed)
    {
        printf("ЕСТЬ РАСХОЖДЕНИЯ\n");
        return 1;
    }
    printf("ВСЕ ТЕСТЫ ПРОЙДЕНЫ\n");
    return 0;
}