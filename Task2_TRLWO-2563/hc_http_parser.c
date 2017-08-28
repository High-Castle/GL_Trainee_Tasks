#include <assert.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "hc_string.h"
#include "hc_http_parser.h"

const char *hc_http_parser_request_enum_to_str(int val)
{
    switch (val)
    {
        case HC_HTTP_PARSER_REQUEST_LINE_NOTHING:
            return "Nothing";
        case HC_HTTP_PARSER_REQUEST_LINE_METHOD:
            return "Method";
        case HC_HTTP_PARSER_REQUEST_LINE_URI:
            return "Uri";
        case HC_HTTP_PARSER_REQUEST_LINE_VERSION:
            return "Version";
        case HC_HTTP_PARSER_REQUEST_HEADER_NAME:
            return "Header.name";
        case HC_HTTP_PARSER_REQUEST_HEADER_VALUE:
            return "Header.value";
        case HC_HTTP_PARSER_REQUEST_CRLF:
            return "CRLF";
        case HC_HTTP_PARSER_REQUEST_EMPTY_LINE:
            return "Empty line";
        case HC_HTTP_PARSER_REQUEST_PARSE_ERROR:
            return "Error";
        default :
            assert(!"Bad Value");
    }
    return NULL;
}

const char *hc_http_parse_request(const char *read_curr_ptr,
    const char *const end_of_line, const char **token_begin,
    const char **token_end, int *last_parsed)
{
    assert(read_curr_ptr);
    assert(end_of_line);
    assert(token_end);
    assert(token_begin);

    switch (*last_parsed)
    {

    case HC_HTTP_PARSER_REQUEST_LINE_NOTHING:

        if (!*token_begin)
        {
            if (!(*token_begin = hc_find_not_char(' ',
                read_curr_ptr, end_of_line - read_curr_ptr)))
            {
                return end_of_line;
            }
            read_curr_ptr = *token_begin;
        }

        if (!(*token_end = hc_find_char(' ', read_curr_ptr,
            end_of_line - read_curr_ptr)))
        {
            *last_parsed = HC_HTTP_PARSER_REQUEST_LINE_NOTHING;
            return end_of_line;
        }

        *last_parsed = HC_HTTP_PARSER_REQUEST_LINE_METHOD;

        return *token_end;

    case HC_HTTP_PARSER_REQUEST_LINE_METHOD:

        if (!*token_begin)
        {
            if (!(*token_begin = hc_find_not_char(' ', read_curr_ptr,
                end_of_line - read_curr_ptr)))
            {
                return end_of_line;
            }
            read_curr_ptr = *token_begin;
        }

        if (!(*token_end = hc_find_char(' ', read_curr_ptr,
            end_of_line - read_curr_ptr)))
        {
            return end_of_line;
        }

        *last_parsed = HC_HTTP_PARSER_REQUEST_LINE_URI;

        return *token_end;

    case HC_HTTP_PARSER_REQUEST_LINE_URI:

        if (!*token_begin)
        {
            if (!(*token_begin = hc_find_not_char(' ', read_curr_ptr,
                end_of_line - read_curr_ptr)))
            {
                return end_of_line;
            }
            read_curr_ptr = *token_begin;
        }

        if (!(*token_end = hc_strtok(read_curr_ptr,
            end_of_line - read_curr_ptr, "\r\n ", 3, hc_find_char)))
        {
            return end_of_line;
        }

        *last_parsed = HC_HTTP_PARSER_REQUEST_LINE_VERSION;

        return *token_end;

    case HC_HTTP_PARSER_REQUEST_LINE_VERSION:
    case HC_HTTP_PARSER_REQUEST_HEADER_VALUE:

        if (!*token_begin)
        {
            if (!(*token_begin = hc_find_not_char(' ', read_curr_ptr,
                end_of_line - read_curr_ptr)))
            {
                return end_of_line;
            }

            read_curr_ptr = *token_begin;
        }
        else
        {
            if (read_curr_ptr == end_of_line)
                return end_of_line;
        }

        assert(read_curr_ptr != end_of_line);
        assert(read_curr_ptr < end_of_line);

        if (*read_curr_ptr != '\n')
        {
	    if (*read_curr_ptr != '\r')
	    {
		*token_end = read_curr_ptr;
		*last_parsed = HC_HTTP_PARSER_REQUEST_PARSE_ERROR;
		return read_curr_ptr;
	    }

	    if (end_of_line - read_curr_ptr >= 2
		&& read_curr_ptr[1] != '\n')
	    {
		*token_end = read_curr_ptr;
		*last_parsed = HC_HTTP_PARSER_REQUEST_PARSE_ERROR;
		return read_curr_ptr;
	    }
	    else
	    {
		*token_end = NULL;
		return read_curr_ptr + 1;
	    }
	}

        *token_end = read_curr_ptr + (*read_curr_ptr == '\n' ? 1 : 2); //

        *last_parsed = HC_HTTP_PARSER_REQUEST_CRLF;

        return *token_end;

    case HC_HTTP_PARSER_REQUEST_CRLF:

        if (!*token_begin)
        {
            if (!(*token_begin = hc_find_not_char(' ', read_curr_ptr,
                end_of_line - read_curr_ptr)))
            {
                return end_of_line;
            }

            read_curr_ptr = *token_begin;

            if (**token_begin == '\n')
            {
                *last_parsed = HC_HTTP_PARSER_REQUEST_EMPTY_LINE;
                return *token_end = *token_begin + 1;
            }

            if (**token_begin == '\r')
            {
                if (end_of_line - *token_begin < 2)
                {
                    *token_end = NULL;
                    *last_parsed = HC_HTTP_PARSER_REQUEST_EMPTY_LINE;
                    return end_of_line;
                }


                *last_parsed = *(*token_begin + 1) != '\n' ?
                    HC_HTTP_PARSER_REQUEST_PARSE_ERROR
                    : HC_HTTP_PARSER_REQUEST_EMPTY_LINE;
                *token_end = *token_begin + 2;

                return *token_end;
            }
        }

        if (!(*token_end = hc_strtok(read_curr_ptr,
            end_of_line - read_curr_ptr, " :", 2, hc_find_char)))
        {
            return end_of_line;
        }

        *last_parsed = HC_HTTP_PARSER_REQUEST_HEADER_NAME;

        return *token_end;

    case HC_HTTP_PARSER_REQUEST_HEADER_NAME:

        if (!*token_begin)
        {
            if (!(*token_begin = hc_strtok(read_curr_ptr,
                end_of_line - read_curr_ptr, " :", 2, hc_find_char_not_in)))
            {
                return end_of_line;
            }
            read_curr_ptr = *token_begin;
        }

        if (!(*token_end = hc_strtok(read_curr_ptr,
            end_of_line - read_curr_ptr, "\r\n", 2, hc_find_char)))
        {
            return end_of_line;
        }

        *last_parsed = HC_HTTP_PARSER_REQUEST_HEADER_VALUE;

        return *token_end;

    case HC_HTTP_PARSER_REQUEST_EMPTY_LINE:

        if (!*token_begin)
        {
            if (!(*token_begin = hc_find_not_char(' ', read_curr_ptr,
                end_of_line - read_curr_ptr)))
            {
                return end_of_line;
            }
            read_curr_ptr = *token_begin;
        }

        *token_end = hc_find_char('\n', read_curr_ptr,
            end_of_line - read_curr_ptr) ;

        if (*token_end)
            return ++*token_end;

        return end_of_line;

    case HC_HTTP_PARSER_REQUEST_PARSE_ERROR:

        return read_curr_ptr;

    default :
        assert(!"bad last_parsed value");
    }

    return read_curr_ptr;
}

int hc_http_uri_decode (char* dst, char const *str, size_t max_read)
{
    unsigned char *dst_it = (unsigned char *)dst;
    char const *it = str;
    char const *num_begin;
    unsigned char decoded_ch;
    size_t count = 0;

    for (;; ++it, ++dst_it, ++count)
    {
        if (count == max_read)
            return HC_HTTP_URI_DECODE_TO_SZ_ERROR_NULL_NOT_FOUND;

        if (*it != '%')
        {
            *dst_it = *it;
            if (*it == '\0')
                break;
            continue;
        }

        count += 2;

        if (count >= max_read)
            return HC_HTTP_URI_DECODE_TO_SZ_ERROR_NULL_NOT_FOUND;

        if (!isxdigit(*++it))
            return HC_HTTP_URI_DECODE_TO_SZ_ERROR_BAD_SRC_STR;

        num_begin = it;

        if (!isxdigit(*++it))
            return HC_HTTP_URI_DECODE_TO_SZ_ERROR_BAD_SRC_STR;

        sscanf(num_begin, "%2hhx", &decoded_ch);

        *dst_it = decoded_ch;
    }

    return HC_HTTP_URI_DECODE_TO_SZ_ERROR_SUCCESS;
}
