/* Тест устойчивости SOCKS-ассоциации к молчаливому серверу.
 *
 * Проверяемое свойство — НЕ длительность (она зависит от планировщика), а то,
 * что socks_associate ВОЗВРАЩАЕТ отказ: прежняя версия сидела в блокирующих
 * connect()/read() и воркер (он один) останавливался навсегда — весь UDP дома
 * вставал, и отпускало только убийство процесса. Поэтому если код регресснёт,
 * тест не «упадет по таймауту», а убьётся по alarm(): так честнее.
 *
 * make test (хост-компилятор; в поставку не входит).
 */
#define _GNU_SOURCE
#include "udp_relay.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(cond, msg) do { if (cond) printf("ok  %s\n", msg); \
    else { printf("FAIL %s\n", msg); failures++; } } while (0)

static void on_alarm(int s)
{
    (void)s;
    printf("FAIL socks_associate не вернулся: блокирующий вызов без таймаута\n");
    _exit(1);
}

static int listen_loopback(int *port_out)
{
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    socklen_t al = sizeof(a);

    if (l < 0)
        return -1;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(l, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(l, 4) != 0 ||
        getsockname(l, (struct sockaddr *)&a, &al) != 0) {
        close(l);
        return -1;
    }
    *port_out = ntohs(a.sin_port);
    return l;
}

int main(void)
{
    struct sockaddr_in relay;
    int port = 0, l;

    slog_init("quiet");
    signal(SIGALRM, on_alarm);
    alarm(20);                       /* страховка от вернувшегося вечного wait */

    /* 1) сервер принимает соединение и молчит (Xray жив, SOCKS не отвечает) */
    l = listen_loopback(&port);
    if (l < 0) {
        printf("SKIP: не удалось открыть слушающий сокет\n");
        return 0;
    }
    CHECK(socks_associate("127.0.0.1", port, &relay) == -1,
          "молчаливый сервер -> отказ, а не вечное ожидание");
    close(l);

    /* 2) сервер отвечает «успехом» с нулевой версией (чужой порт вместо SOCKS):
     *     раньше такой ответ принимался, и релей уходил мусорным адресом */
    port = 0;
    l = listen_loopback(&port);
    if (l >= 0) {
        pid_t pid = fork();

        if (pid == 0) {
            int c = accept(l, NULL, NULL);

            if (c >= 0) {
                unsigned char q[64], r[16];
                ssize_t n;

                n = read(c, q, sizeof(q)); (void)n;      /* greeting */
                r[0] = 5; r[1] = 0;
                n = write(c, r, 2); (void)n;             /* метод принят */
                n = read(c, q, sizeof(q)); (void)n;      /* ASSOCIATE */
                memset(r, 0, sizeof(r));
                r[1] = 0; r[3] = 1;                      /* версия не 5 */
                n = write(c, r, 10); (void)n;
                close(c);
            }
            _exit(0);
        }
        CHECK(pid > 0 &&
              socks_associate("127.0.0.1", port, &relay) == -1,
              "ответ с неверной версией отвергается");
        close(l);
    }

    alarm(0);
    printf("\n%s\n", failures ? "ЕСТЬ ОШИБКИ" : "ИТОГ: все проверки пройдены");
    return failures ? 1 : 0;
}
