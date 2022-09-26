#ifndef JSON_READ_H
#define JSON_READ_H

#include <stddef.h> // size_t

#define json_read_str_arr(dest, json, key) \
json_read_str(dest, json, key, sizeof(dest))

// quick lib to read values from json.
// won't parse the json, just try to read
// values from it.

// notes
// - no memory is allocated.
// - NULL can be safely used for all parameters.
// - strings MUST be NULL terminated.
// - not meant to be used with primitive arrays, ie, [1,2,3]
//   but instead, objects and array of objects.
// - no validations are done when reading.
//   if a number can't be read, 0 will be stored.
//   if a bool can't be read, 0 will be stored.
//   if a string isn't a string, no bytes will be copied and
//   the first byte will be set to 0 (empty string)

// ---

// find the start of the value from key.
// - on failure (key wasn't found), NULL is returned.
// - on success, a pointer to the start of the value is returned.
// 
// example:
// json_read_find_value("{ "foo": 1234 }", "foo")
//   -> 12... (pointer to start of the value)
char *json_read_find_value(char *json, char *key);

// read values from key into dest.
// - on failure, NULL is returned.
// - on success, a pointer past the key will be returned
//   to keep reading from that point.
// 
// example:
// cursor = "{ "foo", 1234, "bar", 32 }";
// cursor = json_read_int(..., cursor, "foo");
// cursor = json_read_int(..., cursor, "bar");
// on the second call, instead of searching from
// the beginning of the json string, we can
// use the cursor, skiping past "foo". this can be 
// useful for arrays.
char *json_read_int(int *dest, char *json, char *key);
char *json_read_dbl(double *dest, char *json, char *key);
char *json_read_bool(int *dest, char *json, char *key);
// read up to n bytes. dest will be NULL terminated.
char *json_read_str(char *dest, char *json, char *key, size_t n);

#endif //JSON_READ_H
