#define _GNU_SOURCE
#include "lang.h"

#include <string.h>

/* 0 = ru (значение по умолчанию и, одновременно, исходный текст сообщений),
 * 1 = en, 2 = zh. */
static int g_lang;

int lang_known(const char *code)
{
    return code && (!strcmp(code, "ru") || !strcmp(code, "en") ||
                    !strcmp(code, "zh"));
}

void lang_set(const char *code)
{
    if (!code || !code[0] || !strcmp(code, "ru"))
        g_lang = 0;
    else if (!strcmp(code, "en"))
        g_lang = 1;
    else if (!strcmp(code, "zh"))
        g_lang = 2;
    else
        g_lang = 0;
}

const char *lang_code(void)
{
    static const char *names[] = { "ru", "en", "zh" };
    return names[g_lang];
}

/* Индекс переводов: линейный поиск по 191 записи на каждую строку лога — при
 * частых логах заметно. Таблица открытой адресации строится один раз. */
#define LANG_HASH 512
static short g_hash[LANG_HASH];
static int g_hash_built;

static unsigned lang_hash(const char *s)
{
    unsigned h = 5381u;
    while (*s)
        h = h * 33u + (unsigned char)*s++;
    return h;
}

static void lang_hash_build(void)
{
    int i;

    for (i = 0; i < LANG_HASH; i++)
        g_hash[i] = -1;
    for (i = 0; i < g_lang_msgs_n && i < LANG_HASH; i++) {
        unsigned h = lang_hash(g_lang_msgs[i].ru) % LANG_HASH;
        while (g_hash[h] >= 0)
            h = (h + 1) % LANG_HASH;
        g_hash[h] = (short)i;
    }
    g_hash_built = 1;
}

const char *lang_tr(const char *ru)
{
    unsigned h;
    int n = 0;

    if (!ru || !ru[0] || !g_lang)
        return ru;
    if (!g_hash_built)
        lang_hash_build();
    h = lang_hash(ru) % LANG_HASH;
    while (g_hash[h] >= 0 && n++ < LANG_HASH) {
        const struct lang_msg *m = &g_lang_msgs[g_hash[h]];
        if (!strcmp(m->ru, ru))
            return g_lang == 1 ? m->en : m->zh;
        h = (h + 1) % LANG_HASH;
    }
    return ru;      /* перевода нет — печатаем исходный русский шаблон */
}
