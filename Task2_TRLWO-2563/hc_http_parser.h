#ifndef __HC_HTTP_PARSER_H__
#define __HC_HTTP_PARSER_H__

#include <stddef.h>

enum
{
    HC_HTTP_PARSER_REQUEST_LINE_NOTHING,
    HC_HTTP_PARSER_REQUEST_LINE_METHOD,
    HC_HTTP_PARSER_REQUEST_LINE_URI,
    HC_HTTP_PARSER_REQUEST_LINE_VERSION,
    HC_HTTP_PARSER_REQUEST_HEADER_NAME,
    HC_HTTP_PARSER_REQUEST_HEADER_VALUE,
    HC_HTTP_PARSER_REQUEST_CRLF,
    HC_HTTP_PARSER_REQUEST_EMPTY_LINE,
    HC_HTTP_PARSER_REQUEST_PARSE_ERROR,

    HC_HTTP_URI_DECODE_TO_SZ_ERROR_SUCCESS,
    HC_HTTP_URI_DECODE_TO_SZ_ERROR_NULL_NOT_FOUND,
    HC_HTTP_URI_DECODE_TO_SZ_ERROR_BAD_SRC_STR,
};

const char *hc_http_parser_request_enum_to_str(int);

const char *hc_http_parse_request(const char *read_curr_ptr,
    const char *const end_of_line, const char **token_begin,
    const char **token_end, int *last_parsed);

int hc_http_uri_decode (char* dst, char const *str, size_t max_read);

#endif
