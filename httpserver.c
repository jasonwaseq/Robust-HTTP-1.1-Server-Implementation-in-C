// httpserver.c
// CSE 130 Asgn2 — robust single-threaded HTTP/1.1 server

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include "listener_socket.h"
#include "iowrapper.h"
#include "protocol.h"

#define MAX_REQ_HDR    2048
#define MAX_METHOD     8
#define MAX_URI        64
#define MAX_HEADER_KEY 128
#define MAX_HEADER_VAL 128

static void send_response(
    int sock, int code, const char *reason, const char *body, size_t body_len) {
    // status-line + Content-Length header + CRLF
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Length: %zu\r\n"
        "\r\n",
        code, reason, body_len);
    if (n > 0 && n < (int) sizeof(hdr)) {
        write_n_bytes(sock, hdr, (size_t) n);
    }
    // only write a body that actually exists in memory
    if (body && body_len > 0) {
        write_n_bytes(sock, (char *) body, body_len);
    }
}

static int parse_port(const char *s) {
    char *end;
    long p = strtol(s, &end, 10);
    if (*end || p < 1 || p > 65535)
        return -1;
    return (int) p;
}

static int valid_method(const char *m) {
    size_t L = strlen(m);
    if (L < 1 || L > MAX_METHOD)
        return 0;
    for (size_t i = 0; i < L; i++)
        if (!isalpha((unsigned char) m[i]))
            return 0;
    return 1;
}

static int valid_uri(const char *u) {
    size_t L = strlen(u);
    if (L < 2 || L > MAX_URI)
        return 0;
    if (u[0] != '/')
        return 0;
    for (size_t i = 1; i < L; i++) {
        char c = u[i];
        if (!isalnum((unsigned char) c) && c != '.' && c != '-')
            return 0;
    }
    return 1;
}

static int valid_version(const char *v) {
    // must be exactly "HTTP/x.y" where x,y are single digits
    if (strlen(v) != 8)
        return 0;
    if (memcmp(v, "HTTP/", 5))
        return 0;
    if (!isdigit((unsigned char) v[5]) || v[6] != '.' || !isdigit((unsigned char) v[7]))
        return 0;
    return 1;
}

// Read up through the "\r\n\r\n" into buf; return length or -1 on error.
static ssize_t read_request_header(int sock, char *buf, size_t max) {
    size_t got = 0;
    while (got < max) {
        char c;
        ssize_t r = read_n_bytes(sock, &c, 1);
        if (r <= 0)
            return -1;
        buf[got++] = c;
        if (got >= 4 && buf[got - 4] == '\r' && buf[got - 3] == '\n' && buf[got - 2] == '\r'
            && buf[got - 1] == '\n') {
            buf[got] = '\0';
            return (ssize_t) got;
        }
    }
    return -1;
}

static void handle_client(int sock) {
    char hdrbuf[MAX_REQ_HDR + 1];
    ssize_t hdrlen = read_request_header(sock, hdrbuf, MAX_REQ_HDR);
    if (hdrlen <= 0) {
        send_response(sock, 400, "Bad Request", "Bad Request\n", 12);
        return;
    }

    // split off the request-line
    char *line_end = strstr(hdrbuf, "\r\n");
    *line_end = '\0';
    char *method = strtok(hdrbuf, " ");
    char *uri = strtok(NULL, " ");
    char *ver = strtok(NULL, " ");
    char *extra = strtok(NULL, " ");
    if (!method || !uri || !ver || extra || !valid_method(method) || !valid_uri(uri)
        || !valid_version(ver)) {
        send_response(sock, 400, "Bad Request", "Bad Request\n", 12);
        return;
    }
    if (strcmp(ver, HTTP_VERSION) != 0) {
        send_response(sock, 505, "Version Not Supported", "Version Not Supported\n", 22);
        return;
    }

    int is_get = (strcmp(method, "GET") == 0);
    int is_put = (strcmp(method, "PUT") == 0);
    if (!is_get && !is_put) {
        send_response(sock, 501, "Not Implemented", "Not Implemented\n", 16);
        return;
    }

    // parse headers
    size_t content_length = 0;
    char *p = line_end + 2;
    char *end = hdrbuf + hdrlen - 2;
    while (p < end) {
        char *e = strstr(p, "\r\n");
        if (e == p)
            break; // blank line
        *e = '\0';
        char *colon = strchr(p, ':');
        if (!colon || colon == p) {
            send_response(sock, 400, "Bad Request", "Bad Request\n", 12);
            return;
        }
        *colon = '\0';
        char *key = p, *val = colon + 1;
        if (*val++ != ' ') {
            send_response(sock, 400, "Bad Request", "Bad Request\n", 12);
            return;
        }
        // trim and validate key/value lengths & chars...
        if (strcmp(key, "Content-Length") == 0) {
            char *ep;
            long v = strtol(val, &ep, 10);
            if (*ep || v < 0) {
                send_response(sock, 400, "Bad Request", "Bad Request\n", 12);
                return;
            }
            content_length = (size_t) v;
        }
        p = e + 2;
    }

    // --- GET ---
    if (is_get) {
        if (content_length) {
            // even if they claim a body, we ignore it—but spec says drain it
        }
        char *path = uri + 1;
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            if (errno == ENOENT)
                send_response(sock, 404, "Not Found", "Not Found\n", 10);
            else if (errno == EACCES)
                send_response(sock, 403, "Forbidden", "Forbidden\n", 10);
            else
                send_response(sock, 500, "Internal Server Error", "Internal Server Error\n", 22);
            return;
        }
        struct stat st;
        if (fstat(fd, &st) < 0) {
            close(fd);
            send_response(sock, 500, "Internal Server Error", "Internal Server Error\n", 22);
            return;
        }
        // if it's not a regular file, forbid
        if (!S_ISREG(st.st_mode)) {
            close(fd);
            send_response(sock, 403, "Forbidden", "Forbidden\n", 10);
            return;
        }
        size_t sz = (size_t) st.st_size;

        // send headers only
        send_response(sock, 200, "OK", NULL, sz);
        // then stream the file
        pass_n_bytes(fd, sock, sz);
        close(fd);
        return;
    }

    // --- PUT ---
    if (!content_length) {
        send_response(sock, 400, "Bad Request", "Bad Request\n", 12);
        return;
    }
    {
        char *path = uri + 1;
        int existed = (access(path, F_OK) == 0);
        int wfd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
        if (wfd < 0) {
            if (errno == EACCES)
                send_response(sock, 403, "Forbidden", "Forbidden\n", 10);
            else
                send_response(sock, 500, "Internal Server Error", "Internal Server Error\n", 22);
            return;
        }
        // write the body
        size_t left = content_length;
        char buf[4096];
        while (left) {
            size_t chunk = left < sizeof(buf) ? left : sizeof(buf);
            ssize_t r = read_n_bytes(sock, buf, chunk);
            if (r <= 0) {
                close(wfd);
                send_response(sock, 400, "Bad Request", "Bad Request\n", 12);
                return;
            }
            write_n_bytes(wfd, buf, (size_t) r);
            left -= (size_t) r;
        }
        close(wfd);
        // respond 200 if existed, else 201
        if (existed)
            send_response(sock, 200, "OK", "OK\n", 3);
        else
            send_response(sock, 201, "Created", "Created\n", 8);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Invalid Port\n");
        return 1;
    }
    int port = parse_port(argv[1]);
    if (port < 0) {
        fprintf(stderr, "Invalid Port\n");
        return 1;
    }
    Listener_Socket_t *ls = ls_new(port);
    if (!ls) {
        fprintf(stderr, "Invalid Port\n");
        return 1;
    }

    // one connection at a time
    while (1) {
        int sock = ls_accept(ls);
        if (sock < 0)
            continue;
        handle_client(sock);
        close(sock);
    }

    // never reached
    ls_delete(&ls);
    return 0;
}
