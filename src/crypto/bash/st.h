/*
*******************************************************************************
\file    st.h
\brief   Доступ к отдельным октетам состояния sponge-функции

\note    Приватный заголовок модуля. Состояние хранится в 24 словах типа u64,
        а стандарт оперирует октетами. Приведение указателя u64* к octet*
        запрещено флагом -Wcast-align=strict, включённым в сборку, поэтому
        доступ выполняется через сдвиги и маску.

\remark Здесь различаются ЗАМЕНА и НАЛОЖЕНИЕ октета. Это не стилистическое
        различие, а разные операции стандарта:

          bash-hash, п. 7.3, шаг 4.1 — блок ЗАМЕНЯет первые 1536 − 4ℓ бит
              состояния. После вызова bash-f содержимое тактовой области
              произвольно, поэтому наложение вместо замены дало бы другой
              результат начиная со второго блока.

          bash-prg, п. 8.6 и 8.8 — absorb НАЛАГАЕТ данные на состояние.

        Смешение двух операций здесь невозможно, потому что они названы
        разными именами.
*******************************************************************************
*/

#ifndef __BEE3_BASH_ST_H
#define __BEE3_BASH_ST_H

#include "bee3/defs.h"

/*  Приведение октета к 64-битному слову с заданным сдвигом. */
#define BEE3_ST_BYTE(v, sh)  ((u64)(v) << (sh))

/*  Маска октета по его началу в слове. */
#define BEE3_ST_MASK(sh)     (((u64)0xFF) << (sh))

/*  Замена октета по индексу k (в октетах от начала состояния). */
static inline void
bee3StPut(
    u64 s[],
    size_t k,
    octet v
)
{
    const size_t sh = 8 * (k % 8);
    const u64 m = BEE3_ST_MASK(sh);

    s[k / 8] = (s[k / 8] & ~m) | BEE3_ST_BYTE(v, sh);
}

/*  Наложение октета по индексу k. */
static inline void
bee3StXor(
    u64 s[],
    size_t k,
    octet v
)
{
    s[k / 8] ^= BEE3_ST_BYTE(v, 8 * (k % 8));
}

/*  Чтение октета по индексу k. */
static inline octet
bee3StGet(
    const u64 s[],
    size_t k
)
{
    return (octet)(s[k / 8] >> (8 * (k % 8)));
}

/*  Инвертирование одиночного бита по индексу k. */
static inline void
bee3StFlipBit(
    u64 s[],
    size_t k
)
{
    s[k / 64] ^= (u64)1 << (k % 64);
}

/*  Замена октетов [off, off+len) значениями buf. */
static inline void
bee3StSetMem(
    u64 s[],
    size_t off,
    const octet buf[],
    size_t len
)
{
    size_t i;
    for (i = 0; i < len; ++i)
        bee3StPut(s, off + i, buf[i]);
}

/*  Наложение октетов buf на [off, off+len). */
static inline void
bee3StXorMem(
    u64 s[],
    size_t off,
    const octet buf[],
    size_t len
)
{
    size_t i;
    for (i = 0; i < len; ++i)
        bee3StXor(s, off + i, buf[i]);
}

/*  Обнуление октетов [off, off+len). */
static inline void
bee3StZero(
    u64 s[],
    size_t off,
    size_t len
)
{
    size_t i;
    for (i = 0; i < len; ++i)
        bee3StPut(s, off + i, 0);
}

#endif /* __BEE3_BASH_ST_H */