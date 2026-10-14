/*
*******************************************************************************
\file    brng_test.c
\brief   Проверка сжатия, хэширования и генератора псевдослучайных чисел
\project bee3 [cryptographic library]

\purpose Проверяются четыре разных утверждения:

           1. соответствие стандарту  — таблицы А.8, В.1 и В.2;
           2. границы блоков          — belt-hash на длинах, не кратных 32,
              включая 0, 1, 31, 33, 39;
           3. свойства алгоритма      — зависимость выхода от синхропосылки
              и от ключа, различие при изменении одного октета;
           4. отсутствие повтора      — разные синхропосылки дают разные
              выходы, иначе режим счётчика бесполезен.

         Утверждение (2) выделено отдельно, потому что именно на нём
         поймалась ошибка с целочисленным делением: тест (1) на одном
         векторе длины 32 её не видел.

\see     docs/notes/004-belt-compress.md
*******************************************************************************
*/

#include <stdio.h>
#include <string.h>

#include "bee3/core/secure_mem.h"
#include "bee3/crypto/brng.h"
#include "bee3/crypto/belt.h"

#include "kat_brng.h"

static int failures;

static void
check(
    int ok,
    const char* what
)
{
    printf("  %-56s %s\n", what, ok ? "OK" : "FAIL");
    if (!ok)
        failures++;
}

static void
section(
    const char* name
)
{
    printf("\n%s\n", name);
}

int
main(void)
{
    octet y[96], mac[32];
    size_t i;

    /* ── 1. Соответствие стандарту ───────────────────────────────────── */

    section("Таблица А.8 СТБ 34.101.31-2020 — belt-compress");
    {
        octet s[16];
        bee3BeltCompr(s, y, belt_compr_a8_in);
        check(bee3SecureEq(s, belt_compr_a8_s, 16), "промежуточное S");
        check(bee3SecureEq(y, belt_compr_a8_y, 32), "результат Y");
    }

    section("Таблица В.1 СТБ 34.101.47-2017 — hmac[hbelt]");
    bee3BrngHmac(mac, brng_b1_key, sizeof brng_b1_key,
        brng_b1_msg, sizeof brng_b1_msg);
    check(bee3SecureEq(mac, brng_b1_mac, 32), "имитовставка");

    section("Таблица В.2 СТБ 34.101.47-2017 — brng-ctr-hbelt, n = 3");
    bee3BrngCtr(y, 3, brng_b2_key, brng_b2_sync, brng_b2_x,
        sizeof brng_b2_x);
    check(bee3SecureEq(y, brng_b2_y, 96), "96 октетов подряд");

    /* ── 2. Границы блоков ───────────────────────────────────────────── */

    section("belt-hash на границах блоков (b = 256 бит)");
    for (i = 0; i < sizeof belt_hash_lens / sizeof belt_hash_lens[0]; ++i)
    {
        static const octet* const exp[8] = {
            belt_hash_msg_l0, belt_hash_msg_l1, belt_hash_msg_l31,
            belt_hash_msg_l32, belt_hash_msg_l33, belt_hash_msg_l39,
            belt_hash_msg_l40, belt_hash_msg_l64 };
        char name[64];
        bee3BeltHash(y, belt_hash_msg, belt_hash_lens[i]);
        (void)snprintf(name, sizeof name, "сообщение длиной %zu октетов",
            belt_hash_lens[i]);
        check(bee3SecureEq(y, exp[i], 32), name);
    }

    /*  Хвост сообщения не должен теряться: если последний блок не
        обрабатывается, результаты для 31 и 33 октетов совпадут. */
    {
        octet a[32], b[32];
        bee3BeltHash(a, belt_hash_msg, 31);
        bee3BeltHash(b, belt_hash_msg, 33);
        check(!bee3SecureEq(a, b, 32),
            "длины 31 и 33 дают разные хэши");
    }

    /* ── 3. Свойства алгоритма ──────────────────────────────────────── */

    section("Свойства режима счётчика");
    {
        octet key[32], sync[32], y2[96];
        int same;

        /*  Смена синхропосылки на один бит меняет весь выход. */
        memcpy(key, brng_b2_key, 32);
        memcpy(sync, brng_b2_sync, 32);
        bee3BrngCtr(y, 3, key, sync, 0, 0);
        sync[0] ^= 1;
        bee3BrngCtr(y2, 3, key, sync, 0, 0);
        check(!bee3SecureEq(y, y2, 96),
            "смена одного бита синхропосылки меняет выход");

        /*  Смена ключа на один бит меняет весь выход. */
        memcpy(sync, brng_b2_sync, 32);
        key[0] ^= 1;
        bee3BrngCtr(y2, 3, key, sync, 0, 0);
        check(!bee3SecureEq(y, y2, 96),
            "смена одного бита ключа меняет выход");

        /*  Слова внутри одного вызова не совпадают: счётчик работает. */
        same = bee3SecureEq(y, y + 32, 32) || bee3SecureEq(y, y + 64, 32) ||
               bee3SecureEq(y + 32, y + 64, 32);
        check(!same, "три слова внутри вызова попарно различны");

        /*  Повторный вызов с той же синхропосылкой даёт тот же выход:
            это и есть причина требования уникальности (п. 5.4). */
        memcpy(key, brng_b2_key, 32);
        memcpy(sync, brng_b2_sync, 32);
        bee3BrngCtr(y, 3, key, sync, 0, 0);
        bee3BrngCtr(y2, 3, key, sync, 0, 0);
        check(bee3SecureEq(y, y2, 96),
            "повтор с той же синхропосылкой даёт тот же выход");

        /*  Отсутствие x равнозначно нулевому x (п. 6.2.2). */
        bee3BrngCtr(y, 3, key, sync, brng_b2_x, 96);
        bee3BrngCtr(y2, 3, key, sync, 0, 0);
        check(!bee3SecureEq(y, y2, 96),
            "заданный x отличается от отсутствующего");
    }

    section("Свойства имитовставки");
    {
        octet m2[32], msg[32];
        memcpy(msg, brng_b1_msg, sizeof msg);
        bee3BrngHmac(mac, brng_b1_key, sizeof brng_b1_key,
            msg, sizeof msg);
        msg[0] ^= 1;
        bee3BrngHmac(m2, brng_b1_key, sizeof brng_b1_key,
            msg, sizeof msg);
        check(!bee3SecureEq(mac, m2, 32),
            "смена одного бита сообщения меняет имитовставку");

        /*  Ключ длиннее b хэшируется (п. 6.1.4 шаг 1). Этот путь не
            проверяется таблицей В.1 и обязан работать. */
        {
            octet longKey[64];
            bee3BrngHmac(mac, brng_b1_key, sizeof brng_b1_key,
                brng_b1_msg, sizeof brng_b1_msg);
            memcpy(longKey, brng_b1_key, 32);
            memset(longKey + 32, 0, 32);
            bee3BrngHmac(m2, longKey, sizeof longKey,
                brng_b1_msg, sizeof brng_b1_msg);
            /*  Длинный ключ ХЭШИРУЕТСЯ, а не дополняется нулями, поэтому
                ключ длины 2b даёт результат, отличный от ключа длины b.
                Считать их равными — ошибка: это разные ключи. */
            check(!bee3SecureEq(mac, m2, 32),
                "ключ длины 2b отличается от ключа длины b");
            longKey[32] = 1;
            bee3BrngHmac(m2, longKey, sizeof longKey,
                brng_b1_msg, sizeof brng_b1_msg);
            check(!bee3SecureEq(mac, m2, 32),
                "ключ длиннее b учитывается целиком");
        }
    }

    section("Имитовставка на коротких сообщениях (регрессия переполнения)");
    {
        static const octet* const exp[5] = {
            brng_short_mac_l0, brng_short_mac_l1, brng_short_mac_l31,
            brng_short_mac_l32, brng_short_mac_l33 };
        for (i = 0; i < 5; ++i)
        {
            char name[64];
            bee3BrngHmac(mac, brng_b1_key, sizeof brng_b1_key,
                brng_short_msg, brng_short_lens[i]);
            (void)snprintf(name, sizeof name, "сообщение длиной %zu октетов",
                brng_short_lens[i]);
            check(bee3SecureEq(mac, exp[i], 32), name);
        }
    }

    section("Режим HMAC для генерации (п. 6.3)");
    bee3BrngHmacCtr(y, 3, brng_b2_key, 32, brng_b2_sync, 32);
    check(bee3SecureEq(y, brng_c3_y, 96), "96 октетов, n = 3");
    {
        octet s2[32], y2[96];
        memcpy(s2, brng_b2_sync, 32);
        s2[0] ^= 1;
        bee3BrngHmacCtr(y2, 3, brng_b2_key, 32, s2, 32);
        check(!bee3SecureEq(y, y2, 96),
            "смена одного бита синхропосылки меняет выход");
        check(!bee3SecureEq(y, y + 32, 32) && !bee3SecureEq(y, y + 64, 32) &&
              !bee3SecureEq(y + 32, y + 64, 32),
            "три слова внутри вызова попарно различны");
    }

    section("Одноразовые пароли: таблицы В.5 и В.6");
    for (i = 0; i < 3; ++i)
    {
        char name[64];
        (void) snprintf(name, sizeof name, "HOTP, счётчик %zu", i);
        check(bee3OtpHotp(8, brng_b1_key, sizeof brng_b1_key,
            brng_hotp_cnt[i]) == brng_hotp_res[i], name);
    }
    for (i = 0; i < 3; ++i)
    {
        char name[64];
        (void) snprintf(name, sizeof name, "TOTP, отметка %llu",
            (unsigned long long) brng_totp_time[i]);
        check(bee3OtpTotp(8, brng_b1_key, sizeof brng_b1_key,
            brng_totp_time[i], 0, 60) == brng_totp_res[i], name);
    }
    {
        /*  Пароль при увеличении счётчика обязан меняться: иначе
            счётчик не выполняет своей функции. */
        u32 a = bee3OtpHotp(8, brng_b1_key, sizeof brng_b1_key,
            brng_hotp_cnt[0]);
        u32 b = bee3OtpHotp(8, brng_b1_key, sizeof brng_b1_key,
            brng_hotp_cnt[0] + 1);
        check(a != b, "соседние значения счётчика дают разные пароли");
        check(a == bee3OtpHotp(8, brng_b1_key, sizeof brng_b1_key,
            brng_hotp_cnt[0]), "повтор с тем же счётчиком даёт тот же пароль");
        /*  Разные числа цифр дают разные пароли. */
        check(bee3OtpHotp(6, brng_b1_key, sizeof brng_b1_key, brng_hotp_cnt[0])
              == bee3OtpHotp(6, brng_b1_key, sizeof brng_b1_key, brng_hotp_cnt[0]),
            "6 цифр: повтор стабилен");
        check(bee3OtpHotp(8, brng_b1_key, sizeof brng_b1_key, brng_hotp_cnt[0])
              != bee3OtpHotp(6, brng_b1_key, sizeof brng_b1_key, brng_hotp_cnt[0]),
            "8 цифр и 6 цифр дают разные пароли");
    }

    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "ВСЕ ТЕСТЫ ПРОЙДЕНЫ");
    return failures ? 1 : 0;
}