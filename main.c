#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <glib.h>
#include <errno.h>

// Cтруктура для хранения статистики
typedef struct {
    GHashTable *url_traffic;
    GHashTable *referer_counts;
    guint64 total_bytes;
    pthread_mutex_t lock;
} Stats;

// Структура для передачи данных потокам
typedef struct {
    char *filename;
    Stats *stats;
} ThreadData;

// Структура для хранения информации об URL и траффике
typedef struct {
    char *key;
    guint64 value;
} UrlEntry;

// Структура для хранения информации о количеств рефереров
typedef struct {
    char *key;
    gint value;
} RefererEntry;

// Функция для декодирования URL в читаемую для пользователя форму
char *urldecode(const char *src) {
    size_t src_len = strlen(src);
    char *decoded = malloc(src_len + 1);
    if (!decoded) return NULL;

    char *dst = decoded;
    for (size_t i = 0; i < src_len; i++) {
        if (src[i] == '%' && i + 2 < src_len) {
            char hex[3] = {src[i+1], src[i+2], '\0'};
            char *endptr;
            long int c = strtol(hex, &endptr, 16);
            if (*endptr == '\0') {
                *dst++ = (char)c;
                i += 2;
                continue;
            }
        }
        *dst++ = src[i] == '+' ? ' ' : src[i];
    }
    *dst = '\0';
    return decoded;
}

// Основная функция для обработки файла лога
void process_log_file(const char *filename, Stats *stats) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error opening file %s: %s\n", filename, strerror(errno));
        return;
    }

    char line[4096];
    while (fgets(line, sizeof(line), file)) {
        char *r = strstr(line, "\"");
        if (!r) continue;
        
        char *method = r + 1;
        char *url = strchr(method, ' ');
        if (!url) continue;
        *url++ = '\0';
        
        char *protocol = strchr(url, ' ');
        if (!protocol) continue;
        *protocol++ = '\0';
        
        char *status_str = strchr(protocol, '"');
        if (!status_str) continue;
        *status_str++ = '\0';
        
        while (*status_str == ' ') status_str++;
        char *bytes_str = strchr(status_str, ' ');
        if (!bytes_str) continue;
        *bytes_str++ = '\0';
        
        while (*bytes_str == ' ') bytes_str++;
        char *referer_start = strchr(bytes_str, '"');
        if (!referer_start) continue;
        *referer_start++ = '\0';
        
        char *referer_end = strchr(referer_start, '"');
        if (!referer_end) continue;
        *referer_end++ = '\0';
        
        guint64 bytes = strtoull(bytes_str, NULL, 10);
        if (bytes == 0 && errno == EINVAL) continue;
        
        char *referer = referer_start;
        if (strcmp(referer, "-") == 0) {
            referer = NULL;
        }
        
        // Потокобезопасное обновление статистики
        pthread_mutex_lock(&stats->lock);
        
        stats->total_bytes += bytes;
        
        char *url_copy = g_strdup(url);
        guint64 *url_bytes = g_hash_table_lookup(stats->url_traffic, url_copy);
        if (url_bytes) {
            *url_bytes += bytes;
            g_free(url_copy);
        } else {
            url_bytes = g_new(guint64, 1);
            *url_bytes = bytes;
            g_hash_table_insert(stats->url_traffic, url_copy, url_bytes);
        }
        
        if (referer) {
            char *referer_copy = g_strdup(referer);
            gint *count = g_hash_table_lookup(stats->referer_counts, referer_copy);
            if (count) {
                (*count)++;
                g_free(referer_copy);
            } else {
                count = g_new(gint, 1);
                *count = 1;
                g_hash_table_insert(stats->referer_counts, referer_copy, count);
            }
        }
        
        pthread_mutex_unlock(&stats->lock);
    }
    fclose(file);
}

// Функция потока
void *thread_func(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    process_log_file(data->filename, data->stats);
    free(data->filename);
    free(data);
    return NULL;
}

// Функция для сравнения элементов хеш-таблицы Url с траффиком
gint compare_url_entries(gconstpointer a, gconstpointer b) {
    const UrlEntry *ua = a;
    const UrlEntry *ub = b;
    if (ua->value < ub->value) return 1;
    if (ua->value > ub->value) return -1;
    return 0;
}

// Функция для сравнения элементов хеш-таблицы Referers с количествоv
gint compare_referer_entries(gconstpointer a, gconstpointer b) {
    const RefererEntry *ra = a;
    const RefererEntry *rb = b;
    if (ra->value < rb->value) return 1;
    if (ra->value > rb->value) return -1;
    return 0;
}

// Вывод топ-10 самых популярных URL по траффику
void print_top_urls(GHashTable *table, int limit) {
    GList *entries = NULL;
    
    GHashTableIter ht_iter;
    gpointer key, value;
    g_hash_table_iter_init(&ht_iter, table);
    while (g_hash_table_iter_next(&ht_iter, &key, &value)) {
        UrlEntry *entry = g_new(UrlEntry, 1);
        entry->key = urldecode((char *)key); 
        entry->value = *(guint64 *)value;
        entries = g_list_prepend(entries, entry);
    }
    
    entries = g_list_sort(entries, (GCompareFunc)compare_url_entries);
    
    printf("\nTop %d URLs by traffic:\n", limit);
    GList *current = entries;
    for (int i = 0; i < limit && current != NULL; i++, current = current->next) {
        UrlEntry *entry = current->data;
        printf("%2d. %s (%" G_GUINT64_FORMAT " bytes)\n", i+1, entry->key, entry->value);
        free(entry->key);
        free(entry);
    }
    
    g_list_free(entries);
}

// Вывод топ-10 самых популярных рефереров по количеству обращений
void print_top_referers(GHashTable *table, int limit) {
    GList *entries = NULL;
    
    GHashTableIter ht_iter;
    gpointer key, value;
    g_hash_table_iter_init(&ht_iter, table);
    while (g_hash_table_iter_next(&ht_iter, &key, &value)) {
        RefererEntry *entry = g_new(RefererEntry, 1);
        entry->key = urldecode((char *)key); 
        entry->value = *(gint *)value;
        entries = g_list_prepend(entries, entry);
    }
    
    entries = g_list_sort(entries, (GCompareFunc)compare_referer_entries);
    
    printf("\nTop %d Referers by count:\n", limit);
    GList *current = entries;
    for (int i = 0; i < limit && current != NULL; i++, current = current->next) {
        RefererEntry *entry = current->data;
        printf("%2d. %s (%d hits)\n", i+1, entry->key, entry->value);
        free(entry->key);
        free(entry);
    }
    
    g_list_free(entries);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <log_directory> <num_threads>\n", argv[0]);
        return 1;
    }
    
    const char *log_dir = argv[1];
    int num_threads = atoi(argv[2]);
    
    if (num_threads < 1) {
        fprintf(stderr, "Number of threads must be at least 1\n");
        return 1;
    }
    
    Stats stats = {
        .url_traffic = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free),
        .referer_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free),
        .total_bytes = 0
    };
    pthread_mutex_init(&stats.lock, NULL);
    
    DIR *dir = opendir(log_dir);
    if (!dir) {
        fprintf(stderr, "Error opening directory %s: %s\n", log_dir, strerror(errno));
        return 1;
    }
    
    GQueue *files = g_queue_new();
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char *path = g_build_filename(log_dir, entry->d_name, NULL);
            g_queue_push_tail(files, path);
        }
    }
    closedir(dir);
    
    if (g_queue_is_empty(files)) {
        printf("No log files found in directory %s\n", log_dir);
        g_queue_free(files);
        return 0;
    }
    
    pthread_t *threads = g_new(pthread_t, num_threads);
    int active_threads = 0;
    
    while (!g_queue_is_empty(files)) {
        if (active_threads < num_threads) {
            ThreadData *data = g_new(ThreadData, 1);
            data->filename = g_queue_pop_head(files);
            data->stats = &stats;
            
            if (pthread_create(&threads[active_threads], NULL, thread_func, data) != 0) {
                fprintf(stderr, "Error creating thread\n");
                free(data->filename);
                free(data);
                continue;
            }
            
            active_threads++;
        } else {
            for (int i = 0; i < active_threads; i++) {
                if (pthread_tryjoin_np(threads[i], NULL) == 0) {
                    for (int j = i; j < active_threads - 1; j++) {
                        threads[j] = threads[j+1];
                    }
                    active_threads--;
                    break;
                }
            }
        }
    }
    
    for (int i = 0; i < active_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    g_free(threads);
    g_queue_free(files);
    
    printf("Total bytes served: %" G_GUINT64_FORMAT "\n", stats.total_bytes);
    print_top_urls(stats.url_traffic, 10);
    print_top_referers(stats.referer_counts, 10);
    
    g_hash_table_destroy(stats.url_traffic);
    g_hash_table_destroy(stats.referer_counts);
    pthread_mutex_destroy(&stats.lock);
    
    return 0;
}