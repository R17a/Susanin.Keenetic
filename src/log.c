#define _GNU_SOURCE
#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static int g_level = SL_INFO;

void slog_init(const char *level)
{
    if (!level)
        return;
    if (!strcmp(level, "quiet")) g_level = SL_QUIET;
    else if (!strcmp(level, "error")) g_level = SL_ERROR;
    else if (!strcmp(level, "info")) g_level = SL_INFO;
    else if (!strcmp(level, "debug")) g_level = SL_DEBUG;
    else if (!strcmp(level, "trace")) g_level = SL_TRACE;
    else g_level = SL_INFO;
}

int slog_enabled(int lvl)
{
    return lvl <= g_level;
}

void slogf(int lvl, const char *fmt, ...)
{
    va_list ap;
    const char *tag;
    char ts[16];
    time_t now;
    struct tm tmv;
    if (!slog_enabled(lvl))
        return;
    if (lvl <= SL_ERROR) tag = "ERR";
    else if (lvl <= SL_WARN) tag = "WARN";
    else if (lvl <= SL_INFO) tag = "INFO";
    else tag = "DBG";
    now = time(NULL);
    localtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);
    fprintf(stdout, "%s %s: ", ts, tag);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

/* Ротация файла лога по размеру (раньше ротация была только при старте
 * службы — сутками растущий лог в tmpfs и уронил роутер: RAM не отдаёт,
 * reboot стирает улики). Если размер > max_kb — оставляем хвост keep_kb
 * (контекст нужен именно перед инцидентом), остальное отсекаем.
 * Писатели с O_APPEND продолжат с нового EOF — пересоздавать fd не нужно. */
void log_rotate_if_big(const char *path, long max_kb, long keep_kb)
{
    struct stat st;
    char *buf;
    size_t keep, got, i;
    off_t from;
    FILE *f;

    if (!path || !path[0] || max_kb <= 0)
        return;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return;
    if (st.st_size < (off_t)max_kb * 1024)
        return;
    keep = (size_t)(keep_kb > 0 ? keep_kb : 1024) * 1024;
    if (keep > (size_t)st.st_size)
        keep = (size_t)st.st_size;
    from = st.st_size - (off_t)keep;
    buf = malloc(keep ? keep : 1);
    if (!buf)
        return;
    f = fopen(path, "rb");
    if (!f) {
        free(buf);
        return;
    }
    if (fseek(f, (long)from, SEEK_SET) != 0) {
        fclose(f);
        free(buf);
        return;
    }
    got = fread(buf, 1, keep, f);
    fclose(f);
    /* не оставлять неполную строку в начале: сдвигаем до первого \n */
    for (i = 0; i < got && buf[i] != '\n'; i++)
        ;
    if (i < got) {
        memmove(buf, buf + i + 1, got - i - 1);
        got -= i + 1;
    }
    f = fopen(path, "wb");
    if (f) {
        if (got)
            fwrite(buf, 1, got, f);
        fclose(f);
    }
    free(buf);
}

/* 1, если путь лежит на tmpfs (RAM). Парсим /proc/mounts, ищем самое длинное
 * совпадение точки монтирования — как ядро. Ошибки чтения = «не tmpfs». */
int path_on_tmpfs(const char *path)
{
    char line[512];
    char dev[256], mnt[256], type[64];
    char best_mnt[256] = "";
    char best_type[64] = "";
    FILE *f;

    if (!path || !path[0])
        return 0;
    f = fopen("/proc/mounts", "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%255s %255s %63s", dev, mnt, type) != 3)
            continue;
        {
            size_t ml = strlen(mnt);
            if (ml == 0)
                continue;
            if (!strncmp(path, mnt, ml) && (ml == 1 || path[ml] == '/' || path[ml] == '\0')) {
                if (ml > strlen(best_mnt)) {
                    snprintf(best_mnt, sizeof(best_mnt), "%s", mnt);
                    snprintf(best_type, sizeof(best_type), "%s", type);
                }
            }
        }
    }
    fclose(f);
    return strcmp(best_type, "tmpfs") == 0;
}
