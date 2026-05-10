/*
 * checkpassword-dovecot
 *
 * Bridges qmail-smtpd's classic checkpassword-program interface to dovecot's
 * auth-client text protocol over a Unix socket.  Reads the standard auth
 * payload on FD3 (<user>\0<pass>\0<timestamp>\0...), authenticates via
 * dovecot, and on success exec()s the next program in argv (typically
 * /bin/true).
 *
 * In the DSMR stack, dovecot already chains a vpopmail SQL passdb, a
 * /etc/dovecot/system-passwd file, and PAM as fallbacks.  Routing SMTP-AUTH
 * through dovecot therefore makes vpopmail virtual users and curated system
 * users authenticatable from a single passdb chain.
 *
 * Exit codes follow the DJB checkpassword-program convention as understood
 * by qmail-smtpd:
 *
 *     0    success — argv[1..] was exec()d
 *     1    auth rejected
 *   111    transient internal error (qmail-smtpd will reply 454)
 *
 * Build:  cc -O2 -Wall -Wextra -o checkpassword-dovecot checkpassword-dovecot.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#define AUTHFD          3
#define AUTHBUFLEN      512
#define DOVECOT_SOCKET  "/var/run/dovecot/auth-client-smtp"
#define SERVICE_NAME    "smtp"
#define IO_TIMEOUT_SEC  10

static void die_temp(const char *m) {
    fprintf(stderr, "checkpassword-dovecot: %s: %s\n", m, strerror(errno));
    _exit(111);
}

static void die_perm(const char *m) {
    fprintf(stderr, "checkpassword-dovecot: %s\n", m);
    _exit(1);
}

static const char b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64encode(const unsigned char *in, size_t n, char *out) {
    size_t i, j = 0;
    for (i = 0; i + 2 < n; i += 3) {
        out[j++] = b64chars[(in[i] >> 2) & 0x3F];
        out[j++] = b64chars[((in[i] & 0x03) << 4) | ((in[i + 1] >> 4) & 0x0F)];
        out[j++] = b64chars[((in[i + 1] & 0x0F) << 2) | ((in[i + 2] >> 6) & 0x03)];
        out[j++] = b64chars[in[i + 2] & 0x3F];
    }
    if (i < n) {
        out[j++] = b64chars[(in[i] >> 2) & 0x3F];
        if (i + 1 < n) {
            out[j++] = b64chars[((in[i] & 0x03) << 4) | ((in[i + 1] >> 4) & 0x0F)];
            out[j++] = b64chars[(in[i + 1] & 0x0F) << 2];
        } else {
            out[j++] = b64chars[(in[i] & 0x03) << 4];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    out[j] = '\0';
    return j;
}

static int writeall(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/* Read one '\n'-terminated line from fd into buf (NUL-terminated, no '\n'). */
static ssize_t readline(int fd, char *buf, size_t cap) {
    size_t i = 0;
    while (i + 1 < cap) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        if (c == '\n') {
            buf[i] = '\0';
            return (ssize_t)i;
        }
        buf[i++] = c;
    }
    buf[i] = '\0';
    return (ssize_t)i;
}

int main(int argc, char **argv) {
    if (argc < 2) die_perm("usage: checkpassword-dovecot prog [args...]");

    /* ----- Read auth payload from FD3. ----- */
    char abuf[AUTHBUFLEN];
    ssize_t n = read(AUTHFD, abuf, sizeof abuf);
    close(AUTHFD);
    if (n <= 0)            die_temp("read fd3");
    if (n == sizeof abuf)  die_perm("auth payload too long");

    size_t ulen = strnlen(abuf, (size_t)n);
    if (ulen == 0 || ulen >= (size_t)n - 1) die_perm("malformed auth payload");
    const char *user = abuf;
    const char *pass = abuf + ulen + 1;
    size_t plen = strnlen(pass, (size_t)n - ulen - 1);
    if (plen == 0) die_perm("empty password");

    /* Reject control chars in user that would break the auth-client framing. */
    for (size_t i = 0; i < ulen; i++) {
        if ((unsigned char)user[i] < 0x20 || user[i] == 0x7F)
            die_perm("invalid character in username");
    }

    /* ----- Build SASL PLAIN response: \0<authcid>\0<password>. ----- */
    if (ulen > 255 || plen > 255) die_perm("user/pass too long");
    unsigned char raw[1 + 255 + 1 + 255];
    size_t rl = 0;
    raw[rl++] = 0;
    memcpy(raw + rl, user, ulen); rl += ulen;
    raw[rl++] = 0;
    memcpy(raw + rl, pass, plen); rl += plen;

    char b64buf[((sizeof raw) / 3 + 1) * 4 + 4];
    b64encode(raw, rl, b64buf);

    /* ----- Connect to dovecot auth-client. ----- */
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) die_temp("socket");

    struct timeval tv = { .tv_sec = IO_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (strlen(DOVECOT_SOCKET) >= sizeof sa.sun_path)
        die_perm("dovecot socket path too long");
    strcpy(sa.sun_path, DOVECOT_SOCKET);
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0)
        die_temp("connect dovecot");

    /* ----- Send our handshake first to avoid any read/write deadlock. ----- */
    char buf[2048];
    int len = snprintf(buf, sizeof buf,
        "VERSION\t1\t2\nCPID\t%d\n", (int)getpid());
    if (len < 0 || (size_t)len >= sizeof buf) die_temp("snprintf handshake");
    if (writeall(s, buf, (size_t)len) < 0) die_temp("write handshake");

    /* ----- Read server greeting until DONE. ----- */
    char line[1024];
    int saw_done = 0;
    while (!saw_done) {
        ssize_t l = readline(s, line, sizeof line);
        if (l < 0) die_temp("read greeting");
        if (l == 0 && saw_done == 0) die_temp("eof during greeting");
        if (strcmp(line, "DONE") == 0) saw_done = 1;
    }

    /* ----- Send AUTH PLAIN. ----- */
    len = snprintf(buf, sizeof buf,
        "AUTH\t1\tPLAIN\tservice=" SERVICE_NAME "\tresp=%s\n", b64buf);
    if (len < 0 || (size_t)len >= sizeof buf) die_temp("snprintf auth");
    if (writeall(s, buf, (size_t)len) < 0) die_temp("write auth");

    /* ----- Read response. ----- */
    for (;;) {
        ssize_t l = readline(s, line, sizeof line);
        if (l < 0)                            die_temp("read auth response");
        if (l == 0)                           die_temp("eof during auth");
        if (strncmp(line, "OK\t",   3) == 0)  break;
        if (strncmp(line, "FAIL\t", 5) == 0) { close(s); return 1; }
        if (strncmp(line, "CONT\t", 5) == 0)  die_perm("unexpected CONT");
        /* Ignore any other response lines. */
    }
    close(s);

    execvp(argv[1], argv + 1);
    die_temp("execvp");
    return 111; /* unreached */
}
