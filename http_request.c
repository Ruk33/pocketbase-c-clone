#include <stdlib.h> // atoi
#include <string.h> // strlen
#include <ctype.h> // tolower, isspace
#include "include/http_request.h"

int http_request_content_length(char *src)
{
    char *content_length_key = "content-length:";
    int partial = -1;
    int not_found = -2;
    if (!src)
        return not_found;
    while (*src) {
        char *key = content_length_key;
        // find the key.
        while (*src && tolower(*src++) == *key && key++);
        // read something but not entirely.
        // ie, "content-le", partial match.
        if (!*src && key != content_length_key)
            return partial;
        // null only if the entire key was found.
        if (*key)
            continue;
        // skip white space after ":".
        while (*src && isspace(*src) && src++);
        char *value = src;
        // skip past the number.
        while (*src && !isspace(*src) && src++);
        // make sure the entire value is read.
        // if it doesn't end on a new line, it means
        // the entire request hasn't been sent.
        if (!isspace(*src))
            return partial;
        return atoi(value);
    }
    return not_found;
}

char *http_request_body(char *src)
{
    if (!src)
        return 0;
    int crlf = '\r' + '\n';
    char *body = src;
    // skip first line (ie, GET /path HTTP...)
    while (!isspace(*body) && body++);
    while (isspace(*body) && body++);
    // minimum size is 4 bytes (two crlf)
    if (body - src < 4)
        return 0;
    // find last two crlf characters.
    while (*body &&
           !((*(body - 3) + *(body - 2)) == crlf &&
             (*(body - 1) + *(body - 0)) == crlf) &&
           body++);
    if (!*body)
        return 0;
    // skip last new line. start at the body.
    body++;
    return body;
}

enum http_request_method http_request_get_method(char *src)
{
    if (!src)
        return METHOD_UNKNOWN;
    if (strncmp(src, "GET ", sizeof("GET")) == 0)
        return METHOD_GET;
    if (strncmp(src, "POST ", sizeof("POST")) == 0)
        return METHOD_POST;
    if (strncmp(src, "PATCH ", sizeof("PATCH")) == 0)
        return METHOD_PATCH;
    if (strncmp(src, "PUT ", sizeof("PUT")) == 0)
        return METHOD_PUT;
    if (strncmp(src, "DELETE ", sizeof("DELETE")) == 0)
        return METHOD_DELETE;
    if (strncmp(src, "HEAD ", sizeof("HEAD")) == 0)
        return METHOD_HEAD;
    if (strncmp(src, "CONNECT ", sizeof("CONNECT")) == 0)
        return METHOD_CONNECT;
    if (strncmp(src, "OPTIONS ", sizeof("OPTIONS")) == 0)
        return METHOD_OPTIONS;
    if (strncmp(src, "TRACE ", sizeof("TRACE")) == 0)
        return METHOD_TRACE;
    return METHOD_UNKNOWN;
}

int http_request_is_partial(char *src)
{
    if (!src)
        return 1;
    char *body = http_request_body(src);
    if (!body)
        return 1;
    int content_len = http_request_content_length(src);
    // no content length, then the entire request was read.
    if (content_len == -2)
        return 0;
    if (content_len == -1)
        return 1;
    return strlen(body) < (size_t) content_len;
}

int http_request_matches_path(char *src, char *path)
{
    if (!src)
        return 0;
    if (!path)
        return 0;
    // skip method
    while (!isspace(*src++));
    // the start of the path + length should
    // end up in a space/newline if it matches.
    // example: GET /my_path HTTP/1.1
    size_t len = strlen(path);
    if (!isspace(*(src + len)))
        return 0;
    return strncmp(src, path, len) == 0;
}
