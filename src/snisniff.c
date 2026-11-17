#include <stdio.h>
#include <string.h>

#include "snisniff.h"

/* Нижний регистр и грубая проверка, что это похоже на DNS-имя. */
static int name_ok(char *s)
{
    size_t i, l;
    if (!s || !s[0])
        return 0;
    l = strlen(s);
    if (l > 253)
        return 0;
    for (i = 0; i < l; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '-'))
            return 0;
    }
    if (s[l - 1] == '.')
        s[l - 1] = '\0';
    return s[0] != '\0';
}

/* SNI живёт в расширении 0x0000 внутри ClientHello:
 *   handshake: type(1)=0x01, len(3), version(2), random(32),
 *              session_id_len(1)+id, cipher_len(2)+suites, comp_len(1)+comp,
 *              ext_len(2), then ext{type(2),len(2),data}.
 * В server_name: list_len(2), name_type(1)=0, name_len(2), name. */
int sni_parse_client_hello(const unsigned char *p, size_t len, char *out, size_t n)
{
    size_t i = 0, q, ext_end;
    unsigned hs_len, ext_len;

    if (!p || !out || n == 0)
        return 0;
    out[0] = '\0';
    /* TLS record: 0x16 (handshake), версия 3.x, длина записи. */
    if (len < 9 || p[0] != 0x16 || p[1] != 0x03 || p[2] > 0x04)
        return 0;
    if (p[5] != 0x01)                     /* не ClientHello */
        return 0;
    hs_len = ((unsigned)p[6] << 16) | ((unsigned)p[7] << 8) | p[8];
    if (hs_len + 9u > len)                /* обрезано — не угадываем */
        hs_len = (unsigned)(len - 9);
    i = 9;
    q = i + 2 + 32;                       /* version + random */
    if (q + 1 > len)
        return 0;
    q += 1 + p[q];                        /* session_id */
    if (q + 2 > len)
        return 0;
    q += 2 + (((size_t)p[q] << 8) | p[q + 1]);   /* cipher_suites */
    if (q + 1 > len)
        return 0;
    q += 1 + p[q];                        /* compression */
    if (q + 2 > len)
        return 0;
    ext_len = ((size_t)p[q] << 8) | p[q + 1];
    q += 2;
    if (q + ext_len > len)
        ext_len = len - q;
    ext_end = q + ext_len;
    while (q + 4 <= ext_end) {
        unsigned et = ((unsigned)p[q] << 8) | p[q + 1];
        unsigned el = ((unsigned)p[q + 2] << 8) | p[q + 3];
        q += 4;
        if (q + el > ext_end)
            return 0;
        if (et == 0x0000 && el >= 5) {
            size_t r = q + 2;             /* список server_name */
            unsigned rt = p[r++];
            unsigned rl = ((unsigned)p[r] << 8) | p[r + 1];
            r += 2;
            if (rt != 0 || rl == 0 || r + rl > q + el || rl >= n)
                return 0;
            memcpy(out, p + r, rl);
            out[rl] = '\0';
            {
                size_t k;
                for (k = 0; k < rl; k++)
                    if (out[k] >= 'A' && out[k] <= 'Z')
                        out[k] = (char)(out[k] - 'A' + 'a');
            }
            return name_ok(out);
        }
        q += el;
    }
    return 0;
}
