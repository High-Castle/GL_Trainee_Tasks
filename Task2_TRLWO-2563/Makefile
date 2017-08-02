RELEASE_TARGETS = tcp_echo_server
RELEASE_PREREQ  = $(addsuffix .c, $(RELEASE_TARGETS)) hc_list.h hc_address.h hc_event_handler.h Makefile
RELEASE_CFLAGS  = -std=gnu11 -g3 -Wall -Wextra -pedantic -Werror -Wno-error=unused-parameter -Wno-error=unused-function

CLEANUP_TARGETS  = $(RELEASE_TARGETS)

$(RELEASE_TARGETS): $(RELEASE_PREREQ)
	$(CC) -o $@ $@.c $(RELEASE_CFLAGS)

clean:
	rm $(CLEANUP_TARGETS)
