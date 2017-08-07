DEFAULT_CFLAGS = -std=gnu11 -g3 -Wall -Wextra -pedantic -Werror -Wno-error=unused-parameter -Wno-error=unused-function

PARSON_ROOT = utilities/parson
PARSON_TARGETS = $(PARSON_ROOT)/parson.o
PARSON_PREREQ = $(PARSON_ROOT)/parson.h $(PARSON_ROOT)/parson.c Makefile
PARSON_CFLAGS = $(DEFAULT_CFLAGS)


SERVER_PARSER_TARGETS = server_config.o
SERVER_PARSER_PREREQ = $(SERVER_PARSER_TARGETS:.o=.c) $(SERVER_PARSER_TARGETS:.o=.h) $(PARSON_TARGETS) Makefile
SERVER_PARSER_CFLAGS = $(DEFAULT_CFLAGS)

RELEASE_TARGETS = tcp_echo_server
RELEASE_PREREQ  = $(addsuffix .c, $(RELEASE_TARGETS)) $(SERVER_PARSER_TARGETS) hc_list.h hc_address.h hc_event_handler.h Makefile
RELEASE_CFLAGS  = $(DEFAULT_CFLAGS)

CLEANUP_TARGETS  = $(RELEASE_TARGETS) $(SERVER_PARSER_TARGETS) $(PARSON_TARGETS)

$(RELEASE_TARGETS): $(RELEASE_PREREQ)
	$(CC) -o $@ $@.c $(SERVER_PARSER_TARGETS) $(PARSON_TARGETS) $(RELEASE_CFLAGS)

$(SERVER_PARSER_TARGETS): $(SERVER_PARSER_PREREQ)
	$(CC) -o $@ -c $(filter %.c, $^)  $(SERVER_PARSER_CFLAGS) 

$(PARSON_TARGETS): $(PARSON_PREREQ)
	$(CC) -o $@ -c $(patsubst %.o, %.c, $@) $(PARSON_CFLAGS)

clean:
	rm $(CLEANUP_TARGETS)
