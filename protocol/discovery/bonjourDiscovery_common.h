/*
 * bonjourDiscovery_common.h
 *
 * Shared types, constants, and URI-buffer helpers used by both the
 * Avahi (Linux) and dns_sd / Bonjour (macOS) discovery backends.
 *
 * The two backends expose identical public symbols:
 *
 *   int  bonjour_probe_nw_scanners(void);   // fills aUriBuf
 *   int  bonjour_lookup(const char *host);  // fills ipAddressBuff
 *
 * Return values (both functions):
 *   BONJOUR_STATUS_OK    – at least one scanner found / host resolved
 *   BONJOUR_STATUS_ERROR – nothing found or a fatal error occurred
 *
 * The caller reads results from the two globals below, then calls
 * bonjour_reset() to free / clear them before the next probe.
 */

#ifndef BONJOUR_DISCOVERY_COMMON_H
#define BONJOUR_DISCOVERY_COMMON_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/* Tunables                                                             */
/* ------------------------------------------------------------------ */

#define MAX_URI_LEN          512
#define HP_MAX_SCAN_BUFF    4096   /* initial URI buffer size          */
#define HP_EXT_SCAN_BUFF    1024   /* realloc increment                */
#define MAX_IP_ADDR_LEN       64   /* enough for IPv4 and IPv6         */
#define MAX_NAME_LENGTH      256
#define APPEND_LOCAL_LEN       6   /* strlen(".local")                 */

/* eSCL / WSD Bonjour service types to browse */
#define BONJOUR_SVC_USCAN    "_uscan._tcp"    /* eSCL over HTTP        */
#define BONJOUR_SVC_USCANS   "_uscans._tcp"   /* eSCL over HTTPS       */
#define BONJOUR_SVC_SCANNER  "_scanner._tcp"  /* WSD / legacy          */

/* HP manufacturer strings (same semantics as the Avahi version) */
#define MFG_HP               "HP"
#define MFG_HP_LEN           2
#define MFG_NAME             "mfg"
#define TYPE_NAME            "ty"
#define HP_SKIP_MFG_NAME_SIZE  3   /* skip "HP " prefix in ty field   */

/* Status codes */
#define BONJOUR_STATUS_OK    0
#define BONJOUR_STATUS_ERROR 1

/* ------------------------------------------------------------------ */
/* Shared output buffers (defined in each backend's .c file)           */
/* ------------------------------------------------------------------ */

/*
 * aUriBuf  – heap-allocated, semicolon-delimited list of hp:/net/ URIs.
 *            Set by bonjour_probe_nw_scanners(); caller must NOT free it
 *            directly – call bonjour_reset() instead.
 *
 * ipAddressBuff – filled by bonjour_lookup(); plain IPv4 string.
 */
extern char  *aUriBuf;
extern char   ipAddressBuff[MAX_IP_ADDR_LEN];

/* ------------------------------------------------------------------ */
/* Logging macros (match the originals in hplip)                       */
/* ------------------------------------------------------------------ */
#ifndef DBG
#  define DBG(fmt, ...)  fprintf(stderr, "[DBG] " fmt, ##__VA_ARGS__)
#endif
#ifndef BUG
#  define BUG(fmt, ...)  fprintf(stderr, "[BUG] " fmt, ##__VA_ARGS__)
#endif

/* ------------------------------------------------------------------ */
/* URI-buffer helpers – inline so both backends share the same code    */
/* without needing a separate .c compilation unit.                     */
/* ------------------------------------------------------------------ */

/*
 * Internal state for building the URI buffer.
 * Each backend declares one instance as a file-scope static.
 */
typedef struct {
    int   bytesWritten;
    int   allocated;
} UriBufState;

/*
 * Append a URI to aUriBuf (with trailing ';') if it is not already
 * present.  Reallocates the buffer if needed.
 *
 * Returns true on success, false on allocation failure.
 */
static inline bool uriBuf_append(char **buf, UriBufState *st,
                                 const char *uri)
{
    /* First use – allocate the initial buffer */
    if (*buf == NULL) {
        *buf = (char *)calloc(HP_MAX_SCAN_BUFF, 1);
        if (*buf == NULL) {
            BUG("uriBuf_append: initial calloc failed\n");
            return false;
        }
        st->allocated    = HP_MAX_SCAN_BUFF;
        st->bytesWritten = 0;
    }

    /* Deduplicate */
    if (strstr(*buf, uri) != NULL)
        return true;

    /* Grow if necessary */
    if ((st->bytesWritten + MAX_URI_LEN) > st->allocated) {
        int newSize = st->allocated + HP_EXT_SCAN_BUFF;
        char *tmp = (char *)realloc(*buf, (size_t)newSize);
        if (tmp == NULL) {
            BUG("uriBuf_append: realloc failed\n");
            return false;
        }
        *buf          = tmp;
        st->allocated = newSize;
    }

    st->bytesWritten += snprintf(*buf + st->bytesWritten,
                                 (size_t)(st->allocated - st->bytesWritten),
                                 "%s;", uri);
    return true;
}

/*
 * Build the hp:/net/<model>?ip=<ip>&queue=false URI string.
 *
 * modelStr  – value of the "ty" TXT record key (already lower-cased /
 *             space-to-underscore converted by the caller).
 * offset    – characters to skip at the front (e.g. "HP ").
 * ipAddress – dotted-decimal IPv4 string.
 * out       – caller-supplied buffer of at least MAX_URI_LEN bytes.
 */
static inline void build_hp_uri(const char *modelStr, size_t offset,
                                 const char *ipAddress,
                                 char out[MAX_URI_LEN])
{
    snprintf(out, MAX_URI_LEN,
             "hp:/net/%s?ip=%s&queue=false",
             modelStr + offset, ipAddress);
}

/*
 * Normalise a model-name string in-place:
 *   – spaces → underscores
 *   – all characters lower-cased
 */
static inline void normalise_model_name(char *str, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (isspace((unsigned char)str[i]))
            str[i] = '_';
        str[i] = (char)tolower((unsigned char)str[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Public API (implemented separately in avahiDiscovery.c /            */
/*             dnssdDiscovery.c)                                        */
/* ------------------------------------------------------------------ */

/**
 * Probe the local network for HP scanners advertising via Bonjour/mDNS.
 *
 * On return aUriBuf contains a ';'-delimited list of hp:/net/ URIs.
 *
 * @return BONJOUR_STATUS_OK if ≥1 scanner was found,
 *         BONJOUR_STATUS_ERROR otherwise.
 */
int bonjour_probe_nw_scanners(void);

/**
 * Resolve a plain hostname (without ".local") to an IPv4 address.
 *
 * On success ipAddressBuff is filled with the dotted-decimal string.
 *
 * @param iHostName  Hostname without the ".local" suffix.
 * @return BONJOUR_STATUS_OK on success, BONJOUR_STATUS_ERROR otherwise.
 */
int bonjour_lookup(const char *iHostName);

/**
 * Free / clear all module-level state so the module can be reused.
 * Call this after consuming aUriBuf / ipAddressBuff.
 */
void bonjour_reset(void);

#endif /* BONJOUR_DISCOVERY_COMMON_H */
