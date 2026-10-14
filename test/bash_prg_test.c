/*
*******************************************************************************
\file    bash_prg_test.c
\brief   Проверочный тест программируемых алгоритмов bash
         (СТБ 34.101.77-2020, раздел 8)

\remark Опора проверки тройная. Первая — опубликованное значение таблицы А.5,
        воспроизведённое побайтово. Вторая — контрольные значения
        аутентифицированного шифрования, полученные дифференциальным
        сравнением с эталонной реализацией Bee2 на 240 операциях. Третья —
        свойства, которые следуют из текста стандарта и должны выполняться
        при любой корректной реализации: размеры буфера, неразделимость
        сообщений, очистка открытого текста при неверной имитовставке.
*******************************************************************************
*/

#include <stdio.h>
#include <string.h>

#include "bee3/core/secure_mem.h"
#include "bee3/crypto/bash.h"
#include "bee3/crypto/bash_prg.h"

#include "kat/prg_kat.h"
#include "kat/vectors.h"

static int failed = 0;

static void
check(
    const char* what,
    int ok
)
{
    printf("  %-48s %s\n", what, ok ? "OK" : "РАСХОЖДЕНИЕ");
    if (!ok)
        failed = 1;
}

/*  Данные для всех проверок берутся из состояния таблицы А.2: так они
    определены в примерах стандарта, и их не нужно отдельно хранить.

    Буфер вдвое больше состояния: контрольные значения используют сообщения
    и ассоциированные данные длиннее 192 октетов. */
#define MSG_SIZE  300

static octet msg[MSG_SIZE];

static void
putMsg(
    void
)
{
    size_t i;
    for (i = 0; i < MSG_SIZE; ++i)
        msg[i] = (octet)(a2_in[(i % BEE3_BASH_SIZE) / 8] >>
                         (8 * ((i % BEE3_BASH_SIZE) % 8)));
}

/*
*******************************************************************************
Таблица А.5: первое опубликованное значение

CTB 34.101.77-2020, таблица А.5, пара (ℓ, d) = (128, 2), сообщение пустое,
анонс пустой, n = 2ℓ.

\remark Остальные шесть значений таблицы А.5 из имеющегося текста стандарта
        не воспроизводятся: извлечение PDF повреждено так же, как это показано
        в docs/notes/002-bash.md для таблицы А.3. Привязка к стандарту здесь
        одна, но она настоящая и побайтовая.
*******************************************************************************
*/

static void
testAnchA5(
    void
)
{
    static const octet expect[32] = {
        0x36, 0xFA, 0x07, 0x5E, 0xC1, 0x57, 0x21, 0xF2,
        0x50, 0xB9, 0xA6, 0x41, 0xA8, 0xCB, 0x99, 0xA3,
        0x33, 0xA9, 0xEE, 0x7B, 0xA8, 0x58, 0x6D, 0x06,
        0x46, 0xCB, 0xAC, 0x36, 0x86, 0xC0, 0x3D, 0xF3,
    };
    octet hash[32];

    bee3BashPrgHash(hash, sizeof hash, 0, 0, msg, 0, 128, 2);
    check("таблица А.5: (128,2), пустое сообщение",
        memcmp(hash, expect, sizeof expect) == 0);
}

/*
*******************************************************************************
Размеры буфера

CTB 34.101.77-2020, п. 8.2: r ← 1536 − ℓ − dℓ/2 в ключевом режиме и
r ← 1536 − 2dℓ в бесключевом. Значение r определяет, какая часть состояния
является буфером, и потому ошибка здесь меняет весь результат, а не часть.
*******************************************************************************
*/

static void
testBufLen(
    void
)
{
    static const struct {
        size_t l, d, keyed, keyless;
    } tab[] = {
        {128, 1, 168, 160}, {128, 2, 160, 128},
        {192, 1, 156, 144}, {192, 2, 144,  96},
        {256, 1, 144, 128}, {256, 2, 128,  64}
    };
    static const octet key[64] = { 0 };
    size_t i;
    int ok = 1;

    for (i = 0; i < sizeof tab / sizeof tab[0]; ++i)
    {
        bee3BashPrg k;
        bee3BashPrg p;

        bee3BashPrgStart(&k, tab[i].l, tab[i].d, 0, 0, key, tab[i].l / 8);
        bee3BashPrgStart(&p, tab[i].l, tab[i].d, 0, 0, 0, 0);
        ok &= (k.bufLen == tab[i].keyed) && (p.bufLen == tab[i].keyless);
        ok &= (bee3BashPrgIsKeyed(&k) != 0);
        ok &= (bee3BashPrgIsKeyed(&p) == 0);
    }
    check("размеры буфера для всех шести пар (ℓ, d)", ok);
}

/*
*******************************************************************************
Контрольные значения аутентифицированного шифрования
*******************************************************************************
*/

static void
testAeadKat(
    void
)
{
    size_t i;
    int ok = 1;

    for (i = 0; i < sizeof prg_kat / sizeof prg_kat[0]; ++i)
    {
        octet mac[32];
        octet ciph[256];
        octet out[256];

        bee3BashPrgAeadEncr(mac, ciph, msg, prg_kat[i].annLen,
            msg, prg_kat[i].msgLen, msg, prg_kat[i].adLen,
            msg + 200, prg_kat[i].keyLen, prg_kat[i].l, prg_kat[i].d);

        ok &= (memcmp(mac, prg_kat[i].mac, prg_kat[i].l / 8) == 0);
        ok &= (memcmp(ciph, prg_kat[i].ciph, prg_kat[i].msgLen) == 0);

        ok &= (bee3BashPrgAeadDecr(out, mac, ciph, prg_kat[i].msgLen,
            msg, prg_kat[i].annLen, msg, prg_kat[i].adLen,
            msg + 200, prg_kat[i].keyLen, prg_kat[i].l, prg_kat[i].d) != 0);
        ok &= (memcmp(out, msg, prg_kat[i].msgLen) == 0);
    }
    check("контрольные значения bash-prg-ae и снятие защиты", ok);
    printf("      операций: %d\n", (int)(sizeof prg_kat / sizeof prg_kat[0]));
}

/*
*******************************************************************************
Отказ при подмене

Обязательное свойство: подмена в любой точке должна приводить к отказу.
Проверяются все три вида подмены, а также подмена в первом и последнем октете
имитовставки — последнее отдельно потому, что именно там ошибка сравнения
с ранним выходом дала бы наибольшую утечку.
*******************************************************************************
*/

static void
testTamper(
    void
)
{
    static const octet key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17, 0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    octet mac[32];
    octet ciph[64];
    octet out[64];
    octet mac2[32];
    octet ciph2[64];
    octet ad2[16];
    size_t len = 40;
    int ok = 1;
    BEE3_BOOL r;

    bee3BashPrgAeadEncr(mac, ciph, msg, 8, msg, len, msg, 16,
        key, sizeof key, 256, 2);

    memcpy(mac2, mac, sizeof mac2);
    memcpy(ciph2, ciph, sizeof ciph2);
    memcpy(ad2, msg, sizeof ad2);

    r = bee3BashPrgAeadDecr(out, mac2, ciph2, len, msg, 8, ad2,
        sizeof ad2, key, sizeof key, 256, 2);
    ok &= (r != 0);
    ok &= (memcmp(out, msg, len) == 0);

    /*  подмена первого октета имитовставки */
    mac2[0] ^= 0x80;
    r = bee3BashPrgAeadDecr(out, mac2, ciph2, len, msg, 8, ad2,
        sizeof ad2, key, sizeof key, 256, 2);
    ok &= (r == 0);
    mac2[0] = mac[0];

    /*  подмена последнего октета имитовставки */
    mac2[31] ^= 1;
    r = bee3BashPrgAeadDecr(out, mac2, ciph2, len, msg, 8, ad2,
        sizeof ad2, key, sizeof key, 256, 2);
    ok &= (r == 0);
    mac2[31] = mac[31];

    /*  подмена шифротекста, ассоциированных данных, анонса, ключа */
    ciph2[0] ^= 1;
    ok &= (bee3BashPrgAeadDecr(out, mac2, ciph2, len, msg, 8, ad2,
        sizeof ad2, key, sizeof key, 256, 2) == 0);
    ciph2[0] = ciph[0];

    ad2[3] ^= 1;
    ok &= (bee3BashPrgAeadDecr(out, mac2, ciph2, len, msg, 8, ad2,
        sizeof ad2, key, sizeof key, 256, 2) == 0);
    ad2[3] = msg[3];

    ok &= (bee3BashPrgAeadDecr(out, mac2, ciph2, len, msg, 4, ad2,
        sizeof ad2, key, sizeof key, 256, 2) == 0);
    ok &= (bee3BashPrgAeadDecr(out, mac2, ciph2, len, msg, 8, ad2,
        sizeof ad2, msg, 32, 256, 2) == 0);

    check("подмена в любой точке приводит к отказу", ok);
}

/*
*******************************************************************************
Очистка открытого текста при отказе

П. 5.11 стандарта: при неверной имитовставке расшифрованное сообщение
недействительно и подлежит очистке. Без этого неавторизованный вызывающий
получил бы открытый текст, не имея права его видеть.
*******************************************************************************
*/

static void
testWipe(
    void
)
{
    static const octet key[32] = { 0 };
    octet mac[32];
    octet ciph[64];
    octet out[64];
    size_t i;
    int zero = 1;

    bee3BashPrgAeadEncr(mac, ciph, msg, 0, msg, 64, msg, 0,
        key, sizeof key, 256, 2);
    mac[7] ^= 0x40;

    if (bee3BashPrgAeadDecr(out, mac, ciph, 64, msg, 0, msg, 0,
        key, sizeof key, 256, 2) != 0)
    {
        check("подмена имитовставки обнаружена", 0);
        return;
    }
    for (i = 0; i < sizeof out; ++i)
        if (out[i] != 0)
            zero = 0;
    check("открытый текст очищен при отказе", zero);
}

/*
*******************************************************************************
Константно-временное сравнение
*******************************************************************************
*/

static void
testSecureEq(
    void
)
{
    octet a[32];
    octet b[32];
    size_t i;
    int ok = 1;

    for (i = 0; i < sizeof a; ++i)
        a[i] = b[i] = (octet)i;

    ok &= (bee3SecureEq(a, b, sizeof a) != 0);

    b[0] ^= 1;
    ok &= (bee3SecureEq(a, b, sizeof a) == 0);
    ok &= (bee3SecureEq(b, a, sizeof a) == 0);

    b[0] = a[0];
    b[sizeof a - 1] ^= 1;
    ok &= (bee3SecureEq(a, b, sizeof a) == 0);

    b[sizeof a - 1] = a[sizeof a - 1];
    ok &= (bee3SecureEq(a, b, 0) != 0);
    ok &= (bee3SecureEq(a, b, 1) != 0);

    b[0] ^= 1;
    ok &= (bee3SecureEq(a, b, 1) == 0);

    check("bee3SecureEq на равных и разных областях", ok);
}

/*
*******************************************************************************
Неразделимость сообщений

Хэш-функция обязана различать сообщения, отличающиеся длиной. Если бы
дополнение не содержало маркера, «A» и «A||0» получили бы один хэш.
*******************************************************************************
*/

static void
testDistinguish(
    void
)
{
    octet a[MSG_SIZE];
    octet h1[32];
    octet h2[32];
    size_t i;
    int ok = 1;

    for (i = 0; i < sizeof a; ++i)
        a[i] = 0x5A;
    for (i = 0; i < sizeof a; ++i)
    {
        bee3BashPrgHash(h1, sizeof h1, 0, 0, a, i, 256, 2);
        bee3BashPrgHash(h2, sizeof h2, 0, 0, a, i + 1, 256, 2);
        ok &= (memcmp(h1, h2, sizeof h1) != 0);
    }
    check("сообщения разной длины дают разные хэши", ok);
}

int
main(
    void
)
{
    printf("bee3: программируемые алгоритмы bash (СТБ 34.101.77, раздел 8)\n\n");

    putMsg();

    printf("привязка к стандарту:\n");
    testAnchA5();
    testBufLen();
    printf("\n");
    printf("хэширование и шифрование:\n");
    testAeadKat();
    testTamper();
    testWipe();
    testDistinguish();
    printf("\n");
    printf("криптографические свойства:\n");
    testSecureEq();

    printf("\n");
    if (failed)
    {
        printf("ЕСТЬ РАСХОЖДЕНИЯ\n");
        return 1;
    }
    printf("ВСЕ ТЕСТЫ ПРОЙДЕНЫ\n");
    return 0;
}