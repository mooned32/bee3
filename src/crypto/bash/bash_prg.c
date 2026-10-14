/*
*******************************************************************************
\file    bash_prg.c
\brief   СТБ 34.101.77 (bash): программируемые алгоритмы, раздел 8

\note    Эталонная реализация. Проверена по таблице А.5 (программируемое
        хэширование, оба набора пар (ℓ, d)) и таблицы А.6
        (аутентифицированное шифрование) СТБ 34.101.77-2020, а также
        дифференциально с эталонной реализацией Bee2 на программах из
        случайных команд.

\note    Сборка программы из команд автомата, как её предписывает п. 8.11,
        выполнена буквально: каждая команда реализована по тексту своего
        пункта, а не по аналогии с предыдущей. Различия между ними существенны
        и сводятся к двум: start ЗАМЕНЯет состояние, restart НАЛАГАЕТ данные;
        squeeze копирует из буфера, encrypt XOR-ит с буфером и выдаёт буфер,
        decrypt XOR-ит в обратном порядке и ЗАМЕНЯЕТ буфер шифротекстом.
*******************************************************************************
*/

#include "bee3/core/secure_mem.h"

#include "bee3/crypto/bash.h"
#include "bee3/crypto/bash_prg.h"
#include "st.h"

/*
*******************************************************************************
Коды типов данных

Таблица 3 стандарта: код из 6 бит дополняется справа парой битов 01.
*******************************************************************************
*/

#define BASH_PRG_NULL   0x01    /* 000000 01 */
#define BASH_PRG_KEY    0x05    /* 000001 01 */
#define BASH_PRG_DATA   0x09    /* 000010 01 */
#define BASH_PRG_TEXT   0x0D    /* 000011 01 */
#define BASH_PRG_OUT    0x11    /* 000100 01 */

/*
*******************************************************************************
Команда commit

СТБ 34.101.77-2020, п. 8.4.2:
    1 S[pos..pos+8) ← S[pos..pos+8) ⊕ (t ‖ 01)
    2 S[r] ← S[r] ⊕ 1
    3 S ← bash-f(S)
    4 pos ← 0

\remark Шаг 1 затрагивает ВЕСЬ октет по адресу pos, а не один бит: пара «01»
        дописывается справа к шестибитному коду типа. Ошибка, состоящая в
        наложении только младших шести битов, дала бы неверный результат,
        неотличимый от правильного по длине.
*******************************************************************************
*/

static void
bashPrgCommit(
    bee3BashPrg* st,
    octet code
)
{
    bee3StXor(st->s, st->pos, code);
    bee3StXor(st->s, st->bufLen, 0x80);
    bee3BashF(st->s);
    st->pos = 0;
}

/*
*******************************************************************************
Команда start

СТБ 34.101.77-2020, п. 8.3.2:
    1 если K ≠ ⊥, то r ← 1536 − ℓ − dℓ/2
    2 иначе r ← 1536 − 2dℓ
    3 pos ← 8 + |A| + |K|
    4 S[...pos) ← ⟨|A|/2 + |K|/32⟩_8 ‖ A ‖ K
    5 S[pos...1472) ← 0
    6 S[1472...) ← ⟨ℓ/4 + d⟩_64

\remark Длины здесь и далее в тексте стандарта измеряются в битах, а
        реализация оперирует октетами: |A|/2 = 4·annLen, |K|/32 = keyLen/4,
        r/8 октетов. Смешение единиц здесь — ошибка, которая даёт корректно
        выглядящий и неверный результат, поэтому единицы приведены явно.
*******************************************************************************
*/

void
bee3BashPrgStart(
    bee3BashPrg* st,
    size_t l,
    size_t d,
    const octet ann[],
    size_t annLen,
    const octet key[],
    size_t keyLen
)
{
    size_t i;

    for (i = 0; i < BEE3_BASH_WORDS; ++i)
        st->s[i] = 0;
    for (i = 0; i < BEE3_BASH_WORDS; ++i)
        st->t[i] = 0;

    st->l = l;
    st->d = d;
    /*  Ключевой режим задаётся наличием ключа, а не отдельным флагом:
        режим определяется величиной r, и отдельный флаг мог бы с ней
        разойтись. */
    st->bufLen = keyLen != 0
        ? BEE3_BASH_SIZE - (l + d * l / 2) / 8
        : BEE3_BASH_SIZE - (2 * d * l) / 8;
    st->pos = 1 + annLen + keyLen;

    bee3StPut(st->s, 0, (octet)(annLen * 4 + keyLen / 4));
    bee3StSetMem(st->s, 1, ann, annLen);
    bee3StSetMem(st->s, 1 + annLen, key, keyLen);
    bee3StZero(st->s, st->pos, BEE3_BASH_SIZE - st->pos);
    bee3StPut(st->s, BEE3_BASH_SIZE - 8, (octet)(l / 4 + d));
}

/*
*******************************************************************************
Команда restart

СТБ 34.101.77-2020, п. 8.5.2. В отличие от start данные НАЛАГАЮТСЯ (⊕), а не
заменяют состояние, и переключение в ключевой режим происходит здесь.
*******************************************************************************
*/

void
bee3BashPrgRestart(
    bee3BashPrg* st,
    const octet ann[],
    size_t annLen,
    const octet key[],
    size_t keyLen
)
{
    if (keyLen != 0)
    {
        bashPrgCommit(st, BASH_PRG_KEY);
        st->bufLen = BEE3_BASH_SIZE - (st->l + st->d * st->l / 2) / 8;
    }
    else
        bashPrgCommit(st, BASH_PRG_NULL);

    st->pos = 1 + annLen + keyLen;
    bee3StXor(st->s, 0, (octet)(annLen * 4 + keyLen / 4));
    bee3StXorMem(st->s, 1, ann, annLen);
    bee3StXorMem(st->s, 1 + annLen, key, keyLen);
}

BEE3_BOOL
bee3BashPrgIsKeyed(
    const bee3BashPrg* st
)
{
    /*  Ключевой режим — это ровно то значение буфера, которое задаёт
        наличие ключа. Проверка через величину r, а не через флаг. */
    return (BEE3_BOOL)((st->bufLen == BEE3_BASH_SIZE -
                        (st->l + st->d * st->l / 2) / 8) ? 1 : 0);
}

/*
*******************************************************************************
Команда absorb

СТБ 34.101.77-2020, п. 8.6.2: commit(DATA), затем блоки по r бит, каждый
накладывается на состояние; полный блок вызывает перестановку.
*******************************************************************************
*/

void
bee3BashPrgAbsorb(
    bee3BashPrg* st,
    const octet in[],
    size_t len
)
{
    bashPrgCommit(st, BASH_PRG_DATA);

    while (len != 0)
    {
        size_t take = st->bufLen - st->pos;

        if (take > len)
            take = len;

        bee3StXorMem(st->s, st->pos, in, take);
        st->pos += take;
        in += take;
        len -= take;

        if (st->pos == st->bufLen)
        {
            bee3BashF(st->s);
            st->pos = 0;
        }
    }
}

/*
*******************************************************************************
Команда squeeze

СТБ 34.101.77-2020, п. 8.7.2: commit(OUT), затем полные блоки буфера
выгружаются с перестановкой после каждого, остаток — из текущего буфера.
*******************************************************************************
*/

void
bee3BashPrgSqueeze(
    bee3BashPrg* st,
    octet out[],
    size_t len
)
{
    bashPrgCommit(st, BASH_PRG_OUT);

    while (len != 0)
    {
        size_t take = st->bufLen - st->pos;
        size_t i;

        if (take > len)
            take = len;

        for (i = 0; i < take; ++i)
            out[i] = bee3StGet(st->s, st->pos + i);
        st->pos += take;
        out += take;
        len -= take;

        if (st->pos == st->bufLen)
        {
            bee3BashF(st->s);
            st->pos = 0;
        }
    }
}

/*
*******************************************************************************
Команда encrypt

СТБ 34.101.77-2020, п. 8.8.2: commit(TEXT), блоки накладываются на состояние,
и выдаётся содержимое буфера.
*******************************************************************************
*/

void
bee3BashPrgEncrypt(
    bee3BashPrg* st,
    const octet in[],
    size_t len,
    octet out[]
)
{
    size_t done = 0;

    bashPrgCommit(st, BASH_PRG_TEXT);

    while (done < len)
    {
        size_t take = st->bufLen - st->pos;
        size_t i;

        if (take > len - done)
            take = len - done;

        bee3StXorMem(st->s, st->pos, in + done, take);
        for (i = 0; i < take; ++i)
            out[done + i] = bee3StGet(st->s, st->pos + i);
        st->pos += take;
        done += take;

        if (st->pos == st->bufLen)
        {
            bee3BashF(st->s);
            st->pos = 0;
        }
    }
}

/*
*******************************************************************************
Команда decrypt

СТБ 34.101.77-2020, п. 8.9.2: обратный порядок относительно encrypt —
сначала читается буфер, потом ЗАМЕНЯЕТСЯ шифротекстом. Замена, а не наложение:
ошибка здесь проявилась бы только при рассинхронизации bufLen между
вызывающей и вызываемой стороной.
*******************************************************************************
*/

void
bee3BashPrgDecrypt(
    bee3BashPrg* st,
    const octet in[],
    size_t len,
    octet out[]
)
{
    size_t done = 0;

    bashPrgCommit(st, BASH_PRG_TEXT);

    while (done < len)
    {
        size_t take = st->bufLen - st->pos;
        size_t i;

        if (take > len - done)
            take = len - done;

        for (i = 0; i < take; ++i)
            out[done + i] = (octet)(bee3StGet(st->s, st->pos + i) ^ in[done + i]);
        bee3StSetMem(st->s, st->pos, in + done, take);
        st->pos += take;
        done += take;

        if (st->pos == st->bufLen)
        {
            bee3BashF(st->s);
            st->pos = 0;
        }
    }
}

/*
*******************************************************************************
Команда ratchet

СТБ 34.101.77-2020, п. 8.10.3: T ← S, commit(NULL), S ← S ⊕ T.
*******************************************************************************
*/

void
bee3BashPrgRatchet(
    bee3BashPrg* st
)
{
    size_t i;

    for (i = 0; i < BEE3_BASH_WORDS; ++i)
        st->t[i] = st->s[i];

    bashPrgCommit(st, BASH_PRG_NULL);

    for (i = 0; i < BEE3_BASH_WORDS; ++i)
        st->s[i] ^= st->t[i];
}

void
bee3BashPrgClean(
    bee3BashPrg* st
)
{
    bee3SecureZero(st, sizeof *st);
}

/*
*******************************************************************************
bash-prg-hash[ℓ, d]

СТБ 34.101.77-2020, п. 8.12.3: start(ann, ⊥), absorb(msg), squeeze(n).
*******************************************************************************
*/

void
bee3BashPrgHash(
    octet hash[],
    size_t hashLen,
    const octet ann[],
    size_t annLen,
    const octet msg[],
    size_t len,
    size_t l,
    size_t d
)
{
    bee3BashPrg st;

    bee3BashPrgStart(&st, l, d, ann, annLen, 0, 0);
    bee3BashPrgAbsorb(&st, msg, len);
    bee3BashPrgSqueeze(&st, hash, hashLen);
    bee3BashPrgClean(&st);
}

/*
*******************************************************************************
bash-prg-ae[ℓ, d] и bash-prg-ae−1[ℓ, d]

СТБ 34.101.77-2020, п. 8.13.3 и 8.13.4.
*******************************************************************************
*/

void
bee3BashPrgAeadEncr(
    octet mac[],
    octet ciph[],
    const octet ann[],
    size_t annLen,
    const octet msg[],
    size_t len,
    const octet data[],
    size_t dataLen,
    const octet key[],
    size_t keyLen,
    size_t l,
    size_t d
)
{
    bee3BashPrg st;

    bee3BashPrgStart(&st, l, d, ann, annLen, key, keyLen);
    bee3BashPrgAbsorb(&st, data, dataLen);
    bee3BashPrgEncrypt(&st, msg, len, ciph);
    bee3BashPrgSqueeze(&st, mac, l / 8);
    bee3BashPrgClean(&st);
}

BEE3_BOOL
bee3BashPrgAeadDecr(
    octet msg[],
    const octet mac[],
    const octet ciph[],
    size_t len,
    const octet ann[],
    size_t annLen,
    const octet data[],
    size_t dataLen,
    const octet key[],
    size_t keyLen,
    size_t l,
    size_t d
)
{
    bee3BashPrg st;
    octet mac_[64];
    BEE3_BOOL ok;

    bee3BashPrgStart(&st, l, d, ann, annLen, key, keyLen);
    bee3BashPrgAbsorb(&st, data, dataLen);
    bee3BashPrgDecrypt(&st, ciph, len, msg);
    bee3BashPrgSqueeze(&st, mac_, l / 8);

    ok = bee3SecureEq(mac, mac_, l / 8);
    bee3SecureZero(mac_, sizeof mac_);

    /*  П. 5.11: при неверной имитовставке расшифрованное сообщение
        недействительно и подлежит очистке. Без этой очистки неавторизованный
        вызывающий получил бы открытый текст, не имея права его видеть. */
    if (!ok)
        bee3SecureZero(msg, len);

    bee3BashPrgClean(&st);
    return ok;
}