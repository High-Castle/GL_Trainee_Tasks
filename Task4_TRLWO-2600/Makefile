wnshow: hc_list.h wnshow.c Makefile
	$(CC) wnshow.c -o wnshow -pedantic -Wall -Wextra\
		$(shell pkg-config --cflags libnl-genl-3.0)\
		$(shell pkg-config --libs libnl-genl-3.0)
clean:
	rm wnshow
