/*
*******************************************************************************
\file    brng_otp.c
\brief   Одноразовые пароли: otp-dt, HOTP и TOTP
         (СТБ 34.101.47-2017, приложение А, п. А.6 — А.8)
\project bee3 [cryptographic library]

\note    Проверено по таблицам В.5 (HOTP) и В.6 (TOTP) стандарта.

\note    Режим OCRA (п. А.9) не реализован: он использует разбор строки
        запроса, и перенос по памяти означал бы перенос грамматики без
        первоисточника под рукой. Основание для отказа то же, что и для
        любой другой непроверенной части стандарта.

\remark Отображение «имитовставка -> пароль» (otp-dt) усекает имитовставку
        до 31 бита и берёт остаток по модулю 10^d. Обе операции осознанно
        ослабляют стойкость: это не имитовставка и ею не является,
        применять её для проверки целостности нельзя.
*******************************************************************************
*/

#include <string.h>

#include "bee3/core/secure_mem.h"
#include "bee3/crypto/brng.h"

/*  Степени десяти до 10^9; 10^9 помещается в 32 бита, а 10^10 — нет. */
static const u32 BEE3_OTP_POW10[10] = {
    1u, 10u, 100u, 1000u, 10000u, 100000u, 1000000u, 10000000u,
    100000000u, 1000000000u };

u32
bee3OtpDt(
    unsigned d,
    const octet y[BEE3_BRNG_VALUE]
)
{
    u32 r;
    unsigned t;
    size_t n = BEE3_BRNG_VALUE;   /*  n = |Y| / 8 октетов */

    if (d >= sizeof BEE3_OTP_POW10 / sizeof BEE3_OTP_POW10[0])
        d = (unsigned)(sizeof BEE3_OTP_POW10 / sizeof BEE3_OTP_POW10[0]) - 1;

    /*  Шаг 1: t <- Y_(n-1) mod 16 — младшая тетрада ПОСЛЕДНЕГО октета,
        как в HOTP по RFC 4226. */
    t = (unsigned)(y[n - 1] & 0x0F);

    /*  Шаг 2: r <- Y_t 2^24 + Y_(t+1) 2^16 + Y_(t+2) 2^8 + Y_(t+3).
        Сдвиг на ширину u32 при t = 29 и более недопустим; при n = 32
        максимум t = 15, но проверка остаётся: она защищает от выхода
        за границу при изменении размера имитовставки. */
    if (t + 4 > n)
        return 0;
    r = ((u32) y[t] << 24) | ((u32) y[t + 1] << 16) |
        ((u32) y[t + 2] << 8) | (u32) y[t + 3];

    /*  Шаг 3: r <- r mod 2^31 */
    r &= 0x7FFFFFFFu;

    /*  Шаг 4: R <- r mod 10^d */
    return r % BEE3_OTP_POW10[d];
}

/*  Шаг 1 п. А.7.3: W <- <C>_64, разбитая на 8 октетов, и сообщение
    записывается в порядке W7, W6, ... W0 — то есть счётчик старшими
    октетами вперёд. */
static void
counterToMsg(
    octet msg[8],
    u64 c
)
{
    size_t i;

    for (i = 0; i < 8; ++i)
        msg[i] = (octet)(c >> (8 * (7 - i)));
}

u32
bee3OtpHotp(
    unsigned d,
    const octet* key,
    size_t keyLen,
    u64 c
)
{
    octet msg[8], mac[BEE3_BRNG_VALUE];

    counterToMsg(msg, c);
    bee3BrngHmac(mac, key, keyLen, msg, sizeof msg);
    bee3SecureZero(msg, sizeof msg);

    /*  Очистка имитовставки — ПОСЛЕ построения пароля. Прежний порядок
        давал нулевой пароль при верной имитовставке, то есть правдоподобный
        результат, отличный от правильного. */
    {
        const u32 r = bee3OtpDt(d, mac);
        bee3SecureZero(mac, sizeof mac);
        return r;
    }
}

u32
bee3OtpTotp(
    unsigned d,
    const octet* key,
    size_t keyLen,
    u64 t,
    u64 t0,
    u64 ts
)
{
    u64 rounded;

    /*  Округление: T <- floor((t - T0) / Ts), при T0 <= t. */
    if (ts == 0 || t < t0)
        return 0;
    rounded = (t - t0) / ts;
    return bee3OtpHotp(d, key, keyLen, rounded);
}