#ifndef SUSANIN_LANG_H
#define SUSANIN_LANG_H

/* Локализация сообщений журнала. Ключ — русский шаблон ровно в том виде, в
 * каком он стоит в slogf(); таблица собирается tools/gen-lang.py из
 * lang/slog.json, поэтому вызовы в коде менять не нужно. */
struct lang_msg {
    const char *ru;
    const char *en;
    const char *zh;
};

extern const struct lang_msg g_lang_msgs[];
extern const int g_lang_msgs_n;

/* ru|en|zh; пусто или неизвестное значение — русский. */
void lang_set(const char *code);
const char *lang_code(void);
int lang_known(const char *code);

/* Перевод шаблона для текущего языка; если перевода нет — сам шаблон. */
const char *lang_tr(const char *ru);

#endif
