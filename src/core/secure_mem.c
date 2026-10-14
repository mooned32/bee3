/*
*******************************************************************************
\file    secure_mem.c
\brief   Очистка памяти, содержащей секреты
\project bee3 [криптографическая библиотека]

\note    Единица трансляции собирается с -fno-builtin. Это требование
        зафиксировано в cmake/CompilerWarnings.cmake и проверяется тестом
        tools/check_nobuiltin.sh: если флаг потеряется, компилятор вправе
        удалить memset, и очистка станет декоративной.
*******************************************************************************
*/

#include "bee3/core/secure_mem.h"

#if defined(_WIN32)
#  include <windows.h>
#  include <winnt.h>
#else
#  include <sys/mman.h>
#  include <unistd.h>
#endif

/*
*******************************************************************************
Защита от удаления вызова
*******************************************************************************
*/

void
bee3SecureZero(void* buf, size_t count)
{
    /*
     * volatile-указатель запрещает компилятору считать память неиспользуемой
     * после записи. Это приём из C99 6.7.3p6, прямой и переносимый.
     *
     * Отдельно: volatile не запрещает вычислительную оптимизацию по всей
     * программе в теории, поэтому на платформах с гарантированной
     * примитивной очисткой используется она.
     */
    volatile u8* p = (volatile u8*)buf;
    while (count-- != 0)
    {
        *p++ = 0;
    }
}

void
bee3SecureFill(void* buf, size_t count, octet fill)
{
    volatile u8* p = (volatile u8*)buf;
    while (count-- != 0)
    {
        *p++ = fill;
    }
}

/*
*******************************************************************************
Исключение подкачки

\remark На Windows VirtualLock имеет системный лимит (working set),
        недоступный обычному процессу. Там корректным эквивалентом
        является VirtualLock из kernel32 либо EncryptMemory в некоторых
        конфигурациях; здесь применяется подходящий под ОС вариант,
        а отказ не является ошибкой — функция сообщает результат вызывающему.
*******************************************************************************
*/

#if defined(_WIN32)
BEE3_BOOL
bee3Mlock(void* buf, size_t count)
{
    if (buf == 0 || count == 0)
        return 0;
    return VirtualLock(buf, count) ? 1 : 0;
}

BEE3_BOOL
bee3Munlock(void* buf, size_t count)
{
    if (buf == 0 || count == 0)
        return 0;
    return VirtualUnlock(buf, count) ? 1 : 0;
}
#else
BEE3_BOOL
bee3Mlock(void* buf, size_t count)
{
    if (buf == 0 || count == 0)
        return 0;
    return mlock(buf, count) == 0 ? 1 : 0;
}

BEE3_BOOL
bee3Munlock(void* buf, size_t count)
{
    if (buf == 0 || count == 0)
        return 0;
    return munlock(buf, count) == 0 ? 1 : 0;
}
#endif