#define _GNU_SOURCE

#include <libmilter/mfapi.h>

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define HEADER_NAME "X-FSMailermon-ID"
#define KEY_BYTES 32
#define MAC_BYTES 32
#define MAX_KID 32
#define MAX_TOKEN 512

static unsigned char signing_key[KEY_BYTES];
static char key_id[MAX_KID + 1];
struct message_state {
    unsigned int existing_headers;
};

static void
clear_message_state(SMFICTX *ctx)
{
    struct message_state *state = smfi_getpriv(ctx);

    if (state != NULL) {
        free(state);
        smfi_setpriv(ctx, NULL);
    }
}

/*
 * Key file format:
 *
 * kid=2026-01
 * secret_hex=<64 hexadecimal characters>
 *
 * The file must be a regular file with no group/other permissions.
 */

static int
hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    return -1;
}

static int
valid_kid(const char *s)
{
    size_t n = strlen(s);

    if (n == 0 || n > MAX_KID)
        return 0;

    for (size_t i = 0; i < n; i++) {
        char c = s[i];

        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-'))
            return 0;
    }

    return 1;
}

static char *
trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;

    size_t n = strlen(s);

    while (n > 0 &&
           (s[n - 1] == ' ' || s[n - 1] == '\t' ||
            s[n - 1] == '\r' || s[n - 1] == '\n')) {
        s[--n] = '\0';
    }

    return s;
}

static int
load_key(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

    if (fd < 0) {
        syslog(LOG_ERR, "cannot open key file: %s", strerror(errno));
        return -1;
    }

    struct stat st;

    if (fstat(fd, &st) != 0 ||
        !S_ISREG(st.st_mode) ||
        (st.st_mode & 077) != 0) {
        syslog(LOG_ERR,
               "key file must be regular and have no group/other permissions");
        close(fd);
        return -1;
    }

    FILE *fp = fdopen(fd, "r");

    if (fp == NULL) {
        syslog(LOG_ERR, "fdopen failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    char secret_hex[KEY_BYTES * 2 + 1] = "";
    int got_kid = 0;
    int got_secret = 0;

    while ((length = getline(&line, &capacity, fp)) != -1) {
        (void)length;

        char *value = trim(line);

        if (*value == '\0' || *value == '#')
            continue;

        if (strncmp(value, "kid=", 4) == 0) {
            value = trim(value + 4);

            if (!valid_kid(value) || got_kid)
                goto invalid;

            strcpy(key_id, value);
            got_kid = 1;
        } else if (strncmp(value, "secret_hex=", 11) == 0) {
            value = trim(value + 11);

            if (strlen(value) != KEY_BYTES * 2 || got_secret)
                goto invalid;

            strcpy(secret_hex, value);
            got_secret = 1;
        } else {
            goto invalid;
        }
    }

    if (ferror(fp) || !got_kid || !got_secret)
        goto invalid;

    for (size_t i = 0; i < KEY_BYTES; i++) {
        int high = hex_value(secret_hex[i * 2]);
        int low = hex_value(secret_hex[i * 2 + 1]);

        if (high < 0 || low < 0)
            goto invalid;

        signing_key[i] = (unsigned char)((high << 4) | low);
    }

    OPENSSL_cleanse(secret_hex, sizeof(secret_hex));
    free(line);
    fclose(fp);

    syslog(LOG_INFO, "loaded signing key with kid=%s", key_id);
    return 0;

invalid:
    syslog(LOG_ERR, "invalid key file format");
    OPENSSL_cleanse(secret_hex, sizeof(secret_hex));
    free(line);
    fclose(fp);
    return -1;
}

/* Fill a buffer completely using the operating system CSPRNG. */
static int
secure_random(unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t n = getrandom(buffer + offset, length - offset, 0);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        offset += (size_t)n;
    }

    return 0;
}

static int
make_uuid(char output[37])
{
    unsigned char b[16];

    if (secure_random(b, sizeof(b)) != 0)
        return -1;

    /* RFC 4122 UUID version 4 and variant bits. */
    b[6] = (unsigned char)((b[6] & 0x0f) | 0x40);
    b[8] = (unsigned char)((b[8] & 0x3f) | 0x80);

    snprintf(output, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
             "%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3],
             b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11],
             b[12], b[13], b[14], b[15]);

    OPENSSL_cleanse(b, sizeof(b));
    return 0;
}

/* Unpadded Base64URL encoding. */
static int
base64url(const unsigned char *input, size_t input_len,
          char *output, size_t output_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    size_t required = (input_len * 8 + 5) / 6;

    if (output_size <= required)
        return -1;

    size_t in = 0;
    size_t out = 0;

    while (in + 3 <= input_len) {
        uint32_t v = ((uint32_t)input[in] << 16) |
                     ((uint32_t)input[in + 1] << 8) |
                     input[in + 2];

        output[out++] = alphabet[(v >> 18) & 63];
        output[out++] = alphabet[(v >> 12) & 63];
        output[out++] = alphabet[(v >> 6) & 63];
        output[out++] = alphabet[v & 63];

        in += 3;
    }

    if (input_len - in == 1) {
        uint32_t v = (uint32_t)input[in] << 16;

        output[out++] = alphabet[(v >> 18) & 63];
        output[out++] = alphabet[(v >> 12) & 63];
    } else if (input_len - in == 2) {
        uint32_t v = ((uint32_t)input[in] << 16) |
                     ((uint32_t)input[in + 1] << 8);

        output[out++] = alphabet[(v >> 18) & 63];
        output[out++] = alphabet[(v >> 12) & 63];
        output[out++] = alphabet[(v >> 6) & 63];
    }

    output[out] = '\0';
    return (int)out;
}


static int
create_token(char *token, size_t token_size, char uuid[37])
{
    char metadata[256];
    unsigned char mac[MAC_BYTES];
    unsigned char combined[MAC_BYTES + 1 + sizeof(metadata)];
    unsigned int mac_len = 0;

    time_t now = time(NULL);

    if (now == (time_t)-1 || make_uuid(uuid) != 0)
        return -1;

    int metadata_len = snprintf(
        metadata, sizeof(metadata),
        "{\"v\":1,\"kid\":\"%s\",\"mailermon_id\":\"%s\",\"iat\":%lld}",
        key_id, uuid, (long long)now);

    if (metadata_len < 0 || (size_t)metadata_len >= sizeof(metadata)) {
        OPENSSL_cleanse(metadata, sizeof(metadata));
        return -1;
    }

    static const char domain[] = "FS-MailerMon-ID:v1:";
    unsigned char input[sizeof(domain) - 1 + sizeof(metadata)];

    memcpy(input, domain, sizeof(domain) - 1);
    memcpy(input + sizeof(domain) - 1, metadata, (size_t)metadata_len);

    if (HMAC(EVP_sha256(), signing_key, KEY_BYTES,
             input, sizeof(domain) - 1 + (size_t)metadata_len,
             mac, &mac_len) == NULL ||
        mac_len != MAC_BYTES) {
        OPENSSL_cleanse(input, sizeof(input));
        OPENSSL_cleanse(mac, sizeof(mac));
        OPENSSL_cleanse(metadata, sizeof(metadata));
        return -1;
    }

    /*
     * Token layout before Base64URL encoding:
     * [32-byte HMAC][|][JSON metadata]
     */
    memcpy(combined, mac, MAC_BYTES);
    combined[MAC_BYTES] = '|';
    memcpy(combined + MAC_BYTES + 1, metadata, (size_t)metadata_len);

    size_t combined_len = MAC_BYTES + 1 + (size_t)metadata_len;

    int encoded_len = base64url(
        combined, combined_len, token, token_size);

    OPENSSL_cleanse(input, sizeof(input));
    OPENSSL_cleanse(mac, sizeof(mac));
    OPENSSL_cleanse(combined, sizeof(combined));
    OPENSSL_cleanse(metadata, sizeof(metadata));

    if (encoded_len < 0) {
        OPENSSL_cleanse(token, token_size);
        return -1;
    }

    return 0;
}

static sfsistat
mlfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
    (void)ctx;
    (void)hostname;
    (void)hostaddr;

    return SMFIS_CONTINUE;
}

static sfsistat
mlfi_header(SMFICTX *ctx, char *name, char *value)
{
    (void)value;

    struct message_state *state = smfi_getpriv(ctx);

    if (state == NULL)
        return SMFIS_TEMPFAIL;

    if (strcasecmp(name, HEADER_NAME) == 0)
        state->existing_headers++;

    return SMFIS_CONTINUE;
}

static sfsistat
mlfi_envrcpt(SMFICTX *ctx, char **argv)
{
    (void)ctx;
    (void)argv;

    return SMFIS_CONTINUE;
}

static sfsistat
mlfi_envfrom(SMFICTX *ctx, char **argv)
{
    (void)argv;

    clear_message_state(ctx);

    struct message_state *state = calloc(1, sizeof(*state));

    if (state == NULL)
        return SMFIS_TEMPFAIL;

    if (smfi_setpriv(ctx, state) != MI_SUCCESS) {
        free(state);
        return SMFIS_TEMPFAIL;
    }

    return SMFIS_CONTINUE;
}

static sfsistat
mlfi_eom(SMFICTX *ctx)
{
    struct message_state *state = smfi_getpriv(ctx);

    if (state == NULL)
        return SMFIS_TEMPFAIL;

    char token[MAX_TOKEN] = {0};
    char uuid[37] = {0};

    if (create_token(token, sizeof(token), uuid) != 0) {
        syslog(LOG_ERR, "failed to create message identity");
        clear_message_state(ctx);
        return SMFIS_TEMPFAIL;
    }

    for (unsigned int i = state->existing_headers; i > 0; i--) {
        if (smfi_chgheader(ctx, HEADER_NAME, (int)i, NULL) != MI_SUCCESS) {
            syslog(LOG_ERR, "failed to remove existing identity header");
            OPENSSL_cleanse(token, sizeof(token));
            clear_message_state(ctx);
            return SMFIS_TEMPFAIL;
        }
    }

    if (smfi_addheader(ctx, HEADER_NAME, token) != MI_SUCCESS) {
        syslog(LOG_ERR, "failed to add identity header");
        OPENSSL_cleanse(token, sizeof(token));
        clear_message_state(ctx);
        return SMFIS_TEMPFAIL;
    }

    syslog(LOG_INFO, "issued MailerMon identity %s", uuid);

    OPENSSL_cleanse(token, sizeof(token));
    clear_message_state(ctx);

    return SMFIS_CONTINUE;
}

static sfsistat
mlfi_eoh(SMFICTX *ctx)
{
    (void)ctx;

    return SMFIS_CONTINUE;
}

static sfsistat
mlfi_abort(SMFICTX *ctx)
{
    clear_message_state(ctx);
    return SMFIS_CONTINUE;
}

static sfsistat
mlfi_close(SMFICTX *ctx)
{
    clear_message_state(ctx);
    return SMFIS_CONTINUE;
}

static struct smfiDesc mailermon_filter = {
    .xxfi_name = "MailerMon",
    .xxfi_version = SMFI_VERSION,
    .xxfi_flags = SMFIF_ADDHDRS | SMFIF_CHGHDRS,
    .xxfi_envfrom = mlfi_envfrom,
    .xxfi_header = mlfi_header,
    .xxfi_eom = mlfi_eom,
    .xxfi_connect = mlfi_connect,
    .xxfi_abort = mlfi_abort,
    .xxfi_close = mlfi_close,
    .xxfi_envrcpt = mlfi_envrcpt,
    .xxfi_eoh = mlfi_eoh,
};

int
main(int argc, char **argv)
{
    const char *socket = NULL;
    const char *keyfile = NULL;

    int opt;

    while ((opt = getopt(argc, argv, "s:k:")) != -1) {
        switch (opt) {
        case 's':
            socket = optarg;
            break;
        case 'k':
            keyfile = optarg;
            break;
        default:
            fprintf(stderr,
                    "Usage: %s -s socket -k keyfile\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (socket == NULL || keyfile == NULL) {
        fprintf(stderr, "Usage: %s -s socket -k keyfile\n", argv[0]);
        return EXIT_FAILURE;
    }

    openlog("mailermon-milter", LOG_PID, LOG_MAIL);

    if (load_key(keyfile) != 0)
        return EXIT_FAILURE;

    if (smfi_setconn((char *)socket) != MI_SUCCESS) {
        syslog(LOG_ERR, "smfi_setconn failed");
        return EXIT_FAILURE;
    }

    if (smfi_settimeout(30) != MI_SUCCESS) {
        syslog(LOG_ERR, "smfi_settimeout failed");
        return EXIT_FAILURE;
    }

    if (smfi_register(mailermon_filter) != MI_SUCCESS) {
        syslog(LOG_ERR, "smfi_register failed");
        return EXIT_FAILURE;
    }

    syslog(LOG_INFO, "starting MailerMon milter on %s", socket);

    int result = smfi_main();

    OPENSSL_cleanse(signing_key, sizeof(signing_key));
    closelog();

    return result == MI_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}
