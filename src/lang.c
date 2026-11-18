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

const char *lang_tr(const char *ru)
{
    int i;

    if (!ru || !ru[0] || !g_lang)
        return ru;
    for (i = 0; i < g_lang_msgs_n; i++) {
        if (!strcmp(g_lang_msgs[i].ru, ru))
            return g_lang == 1 ? g_lang_msgs[i].en : g_lang_msgs[i].zh;
    }
    return ru;      /* перевода нет — печатаем исходный русский шаблон */
}
