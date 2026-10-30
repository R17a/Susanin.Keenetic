/* W6: разбор ответа GitHub и сравнение версий. make test (host). */
#define _GNU_SOURCE
#include "release.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

int main(void)
{
    char tag[RELEASE_TAG_MAX], url[RELEASE_URL_MAX];
    const char *js =
        "{\"tag_name\":\"v0.4.3\","
        "\"html_url\":\"https://github.com/R17a/Susanin.Keenetic/releases/tag/v0.4.3\"}";

    printf("=== разбор ответа GitHub ===\n");
    CHECK(release_parse_payload(js, tag, sizeof(tag), url, sizeof(url)) == 0,
          "ответ разобран");
    CHECK(strcmp(tag, "0.4.3") == 0, "tag без префикса v");
    CHECK(strcmp(url, "https://github.com/R17a/Susanin.Keenetic/releases/tag/v0.4.3") == 0,
          "html_url сохранён");
    CHECK(release_parse_payload("{\"tag_name\":\"0.4.3\"}", tag, sizeof(tag),
                                url, sizeof(url)) == 0,
          "ответ без html_url разобран");
    CHECK(strcmp(url, "https://github.com/R17a/Susanin.Keenetic/releases/tag/v0.4.3") == 0,
          "url собран из tag");
    CHECK(release_parse_payload("{\"message\":\"Not Found\"}", tag, sizeof(tag),
                                url, sizeof(url)) != 0,
          "ответ без tag_name отклонён");
    CHECK(release_parse_payload("{}", tag, sizeof(tag), url, sizeof(url)) != 0,
          "пустой объект отклонён");
    CHECK(release_parse_payload("{\"tag_name\":\"latest\"}", tag, sizeof(tag),
                                url, sizeof(url)) != 0,
          "нечисловой tag отклонён");

    printf("=== сравнение версий ===\n");
    CHECK(release_version_cmp("0.4.2", "0.4.3") < 0, "0.4.2 старее 0.4.3");
    CHECK(release_version_cmp("0.4.3", "0.4.2") > 0, "0.4.3 новее 0.4.2");
    CHECK(release_version_cmp("v0.4.3", "0.4.3") == 0, "префикс v не мешает");
    CHECK(release_version_cmp("0.4.3", "0.4.3") == 0, "равные версии");
    CHECK(release_version_cmp("0.4.10", "0.4.9") > 0, "0.4.10 новее 0.4.9");
    CHECK(release_version_cmp("0.4.2-dev7", "0.4.2") < 0, "dev-сборка старее релиза");
    CHECK(release_version_cmp("0.4.0.RC1", "0.4.0") < 0, "RC старее релиза");
    CHECK(release_version_cmp("0.4.3", "0.4.3-dev1") > 0, "релиз новее dev");
    CHECK(release_version_cmp("0.4.3-dev2", "0.4.3-dev1") > 0, "dev2 новее dev1");

    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "все проверки пройдены");
    return failures ? 1 : 0;
}
