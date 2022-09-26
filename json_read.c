#include <stdlib.h> // atoi, atof
#include <ctype.h> // isspace
#include "include/json_read.h"

char *json_read_find_value(char *src, char *key)
{
    char *cursor = src;
    char *cursor_key = 0;
    if (!src)
        return 0;
    if (!key)
        return 0;
    while (*cursor) {
        cursor_key = key;
        // find start of key.
        while (*cursor && *cursor++ != '"');
        while (*cursor && *cursor++ == *cursor_key && cursor_key++);
        // cursor key consumed if the key matches entirely.
        if (*cursor_key)
            continue;
        // check if the entire key matches.
        if (*(cursor - 1) != '"')
            continue;
        // find :
        while (*cursor && *cursor++ != ':');
        // skip spaces
        while (*cursor && isspace(*cursor) && cursor++);
        return cursor;
    }
    return 0;
}

char *json_read_int(int *dest, char *src, char *key)
{
    char *value = json_read_find_value(src, key);
    *dest = value ? atoi(value) : 0;
    return value;
}

char *json_read_dbl(double *dest, char *src, char *key)
{
    char *value = json_read_find_value(src, key);
    *dest = value ? atof(value) : 0;
    return value;
}

char *json_read_bool(int *dest, char *src, char *key)
{
    char *value = json_read_find_value(src, key);
    *dest = value && *value == 't';
    return value;
}

char *json_read_str(char *dest, char *src, char *key, size_t n)
{
    char *value = json_read_find_value(src, key);
    char *cursor = value;
    // initial empty string value.
    *dest = 0;
    if (!cursor)
        return 0;
    // check if value is string.
    if (*cursor != '"')
        return 0;
    // skip initial start of string (")
    cursor++;
    while (*cursor && n > 1) {
        // check if we are at the end of the string
        // (and not an scaped " character)
        if (*cursor == '"' && *(cursor - 1) != '\\')
            break;
        *dest++ = *cursor++;
        n -= 1;
    }
    // null terminator.
    *dest = 0;
    return cursor;
}
