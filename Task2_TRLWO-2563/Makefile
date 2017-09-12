DEFAULT_CFLAGS = -std=gnu99 -g3 -Wall -Wextra -pedantic -Werror -lrt

MBEDTLS_ROOT = utilities/mbedtls
MBEDTLS_TARGETS = libmbedx509.a libmbedtls.a libmbedcrypto.a

PARSON_ROOT = utilities/parson
PARSON_TARGETS = $(PARSON_ROOT)/parson.o
PARSON_PREREQ = $(PARSON_ROOT)/parson.h $(PARSON_ROOT)/parson.c Makefile
PARSON_CFLAGS = $(DEFAULT_CFLAGS) -fPIC

SERVER_PARSER_TARGETS = server_config.o
SERVER_PARSER_PREREQ = $(SERVER_PARSER_TARGETS:.o=.c) \
	$(SERVER_PARSER_TARGETS:.o=.h) $(PARSON_TARGETS) Makefile
SERVER_PARSER_CFLAGS = $(DEFAULT_CFLAGS)

HC_HTTP_PARSER_TARGETS = hc_http_parser.o
HC_HTTP_PARSER_PREREQ  = $(HC_HTTP_PARSER_TARGETS:.o=.c) hc_string.h
HC_HTTP_PARSER_CFLAGS  = $(DEFAULT_CFLAGS) -fPIC

HTTP_TCP_SUBSERVER_TARGETS = http_tcp_subserver.so
HTTP_TCP_SUBSERVER_PREREQ = $(wildcard server_config.{h c}) $(PARSON_TARGETS) \
	http_tcp_subserver.c \
	http_subserver.h Makefile
HTTP_TCP_SUBSERVER_CFLAGS = $(DEFAULT_CFLAGS) -fPIC -shared

HTTP_TLS_SUBSERVER_TARGETS = http_tls_subserver.so
HTTP_TLS_SUBSERVER_PREREQ = $(MBEDTLS_TARGETS) $(PARSON_TARGET) \
	$(wildcard server*config.{h c}) \
	http_tls_subserver.c http_subserver.h Makefile
HTTP_TLS_SUBSERVER_CFLAGS = $(DEFAULT_CFLAGS) -fPIC -shared \
	-L$(MBEDTLS_ROOT)/library/ -I$(MBEDTLS_ROOT)/include/ \
	$(MBEDTLS_TARGETS:lib%.a=-l%)

RELEASE_TARGETS = http_server
RELEASE_PREREQ  = $(addsuffix .c, $(RELEASE_TARGETS)) $(SERVER_PARSER_TARGETS) \
	$(HC_HTTP_PARSER_TARGETS) $(HTTP_TLS_SUBSERVER_TARGETS) \
	$(HTTP_TCP_SUBSERVER_TARGETS) hc_string.h \
	hc_list.h hc_address.h hc_event_handler.h
RELEASE_CFLAGS  = $(DEFAULT_CFLAGS) -ldl

CLEANUP_TARGETS  = $(RELEASE_TARGETS) $(SERVER_PARSER_TARGETS) \
	$(PARSON_TARGETS) $(HC_HTTP_PARSER_TARGETS) \
	$(HTTP_TLS_SUBSERVER_TARGETS) \
	$(HTTP_TCP_SUBSERVER_TARGETS)

$(RELEASE_TARGETS): $(RELEASE_PREREQ)
	$(CC) -o $@ $@.c $(SERVER_PARSER_TARGETS) $(PARSON_TARGETS) \
		$(HC_HTTP_PARSER_TARGETS) $(RELEASE_CFLAGS)

$(SERVER_PARSER_TARGETS): $(SERVER_PARSER_PREREQ)
	$(CC) -o $@ -c $(filter %.c, $^)  $(SERVER_PARSER_CFLAGS)

$(PARSON_TARGETS): $(PARSON_PREREQ)
	$(CC) -o $@ -c $(patsubst %.o, %.c, $@) $(PARSON_CFLAGS)

$(HC_HTTP_PARSER_TARGETS): $(HC_HTTP_PARSER_PREREQ)
	$(CC) -o $@ -c $(patsubst %.o, %.c, $@) $(HC_HTTP_PARSER_CFLAGS)

$(HTTP_TLS_SUBSERVER_TARGETS): $(HTTP_TLS_SUBSERVER_PREREQ)
	$(CC) -o $@ $(patsubst %.so, %.c, $@) $(wildcard server*config.c) \
		$(HTTP_TLS_SUBSERVER_CFLAGS) $(PARSON_TARGETS) $(HC_HTTP_PARSER_TARGETS)

$(HTTP_TCP_SUBSERVER_TARGETS): $(HTTP_TCP_SUBSERVER_PREREQ)
	$(CC) -o $@ $(patsubst %.so, %.c, $@) $(HTTP_TCP_SUBSERVER_CFLAGS) \
		server_config.c $(PARSON_TARGETS) $(HC_HTTP_PARSER_TARGETS)

$(MBEDTLS_TARGETS):
	make -C $(MBEDTLS_ROOT)/library/

MBEDTLS_CLEAN:
	make -C $(MBEDTLS_ROOT)/library/ clean

clean:
	rm $(CLEANUP_TARGETS)
	make MBEDTLS_CLEAN
