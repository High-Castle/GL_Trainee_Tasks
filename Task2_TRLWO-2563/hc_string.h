#ifndef __HC_STRING_H__
#define __HC_STRING_H__

#include <stddef.h>
#include <stdint.h>
#include <assert.h>

inline static int hc_streq_ic(const char *op0, size_t op0_sz, const char *op1,
    size_t op1_sz)
{
    if (op0_sz != op1_sz)
        return 0;

    for (size_t idx = 0; idx != op0_sz; ++idx)
    {
       if (tolower(op0[idx]) != tolower(op1[idx]))
           return 0;
    }

    return 1;
}

inline static int hc_streq(const char *op0, size_t op0_sz, const char *op1,
    size_t op1_sz)
{
    if (op0_sz != op1_sz)
        return 0;

    for (size_t idx = 0; idx != op0_sz; ++idx)
    {
       if (op0[idx] != op1[idx])
           return 0;
    }

    return 1;
}

inline static const char *hc_find_not_char (char ch, const char *arr,
    size_t arr_sz)
{
    for (const char *it = arr; it != arr + arr_sz; ++it)
    {
        if (ch != *it)
            return it;
    }

    return NULL;
}

inline static const char *hc_find_char (char ch, const char *arr, size_t arr_sz)
{
    for (const char *it = arr; it != arr + arr_sz; ++it)
        if (ch == *it)
            return it;
    return NULL;
}

inline static const char *hc_find_char_not_in (char ch, const char *arr,
    size_t arr_sz)
{
    for (const char *it = arr; it != arr + arr_sz; ++it)
        if (ch == *it)
            return NULL;
    return arr;
}

inline static const char *hc_rfind_not_char (char ch, const char *arr,
    size_t arr_sz)
{
    for (const char *it = arr; it != arr - arr_sz; --it)
        if (ch != *it)
            return it;
    return NULL;
}

inline static const char *hc_rfind_char (char ch, const char *arr,
    size_t arr_sz)
{
    for (const char *it = arr; it != arr - arr_sz; --it)
        if (ch == *it)
            return it;
    return NULL;
}

inline static char const *hc_strtok(const char *data, size_t data_sz,
    const char * delims, size_t delims_sz,
    char const*(*find_char)(char, const char *, size_t))
{
    for (const char *it = data; it != data + data_sz; ++it)
        if (find_char(*it, delims, delims_sz) != NULL)
            return it;

    return NULL;
}

inline static char const *hc_rstrtok(const char *data, size_t data_sz,
    const char * delims, size_t delims_sz,
    char const*(* find_char)(char, const char *, size_t))
{
    for (const char *it = data; it != data - data_sz; --it)
        if (find_char(*it, delims, delims_sz) != NULL)
            return it;

    return NULL;
}


inline static uintmax_t hc_digit_count(uintmax_t num, uintmax_t base)
{
    assert(base > 1);
    uintmax_t count = 1;
    for (; num /= base; ++count);
    return count;
}

#endif
