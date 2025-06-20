all: log_stats

log_stats: main.c
	$(CC) $^ -o $@ -Wall -Wextra -Wpedantic -std=c11 `pkg-config --cflags --libs glib-2.0` -lpthread

clean:
	rm -f log_stats

.PHONY: all clean