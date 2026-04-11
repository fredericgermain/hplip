/*
 * dnssdDiscovery.c  –  macOS / dns_sd Bonjour backend
 *
 * Drop-in replacement for avahiDiscovery.c on macOS.
 * Implements the same public API declared in bonjourDiscovery_common.h:
 *
 *   int  bonjour_probe_nw_scanners(void);
 *   int  bonjour_lookup(const char *iHostName);
 *   void bonjour_reset(void);
 *
 * Design notes
 * ────────────
 * dns_sd is fully callback-driven and asynchronous.  To keep the same
 * synchronous call-return contract as the Avahi version we:
 *
 *   1. Open a browse ref for each service type.
 *   2. Run a CFRunLoop (or a select() loop) for BROWSE_TIMEOUT_SEC.
 *   3. For every BROWSE_ADD event immediately open a resolve ref.
 *   4. Wait for all pending resolves to complete (or time out).
 *   5. For each resolved service query the "ty" / "mfg" TXT keys,
 *      decide whether it is an HP device, build the URI, append to
 *      aUriBuf.
 *
 * Compile with:
 *   clang -o discovery dnssdDiscovery.c -framework CoreServices
 * or just add -framework CoreServices to your Makefile.
 */

#ifdef __APPLE__

#include "bonjourDiscovery_common.h"

#include <dns_sd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/* Module globals                                                       */
/* ------------------------------------------------------------------ */

char  *aUriBuf        = NULL;
char   ipAddressBuff[MAX_IP_ADDR_LEN] = {'\0'};

static UriBufState  gUriBufState = {0, 0};

/* How long (seconds) to wait for Bonjour responses */
#define BROWSE_TIMEOUT_SEC   5
#define RESOLVE_TIMEOUT_SEC  3
#define LOOKUP_TIMEOUT_SEC   3

/* Maximum simultaneous resolve operations */
#define MAX_PENDING_RESOLVES 32

/* ------------------------------------------------------------------ */
/* Internal context passed through callbacks                           */
/* ------------------------------------------------------------------ */

typedef struct {
    DNSServiceRef   sdRef;          /* resolve ref (or browse ref)    */
    bool            done;           /* set when resolve is finished   */
} ResolveCtx;

static ResolveCtx  gResolvePool[MAX_PENDING_RESOLVES];
static int         gResolveCount = 0;  /* active entries in pool       */

/* ------------------------------------------------------------------ */
/* TXT record helpers                                                   */
/* ------------------------------------------------------------------ */

/*
 * Extract the value for 'key' from a raw TXT record blob.
 * Returns a newly malloc'd string (caller must free) or NULL.
 */
static char *txt_get_value(const char *key,
                            uint16_t    txtLen,
                            const void *txtRecord)
{
    uint8_t valueLen = 0;
    const void *rawValue = TXTRecordGetValuePtr(txtLen,
                                                txtRecord,
                                                key,
                                                &valueLen);
    if (rawValue == NULL || valueLen == 0)
        return NULL;

    char *out = (char *)malloc((size_t)valueLen + 1);
    if (out == NULL)
        return NULL;

    memcpy(out, rawValue, valueLen);
    out[valueLen] = '\0';
    return out;
}

/*
 * Decide whether the TXT record belongs to an HP scanner and – if so –
 * fill outModel (caller supplies buffer[MAX_URI_LEN]) and *outOffset.
 *
 * Returns true if it is an HP scanner.
 */
static bool get_hp_scanner_model(uint16_t    txtLen,
                                  const void *txtRecord,
                                  char        outModel[MAX_URI_LEN],
                                  size_t     *outOffset)
{
    bool found = false;

    char *ty  = txt_get_value(TYPE_NAME, txtLen, txtRecord);
    char *mfg = txt_get_value(MFG_NAME,  txtLen, txtRecord);

    if (ty != NULL) {
        if (strncmp(MFG_HP, ty, MFG_HP_LEN) == 0) {
            /* "ty=HP DeskJet 2700 series" – starts with "HP " */
            found      = true;
            *outOffset = HP_SKIP_MFG_NAME_SIZE;
            strncpy(outModel, ty, MAX_URI_LEN - 1);
            outModel[MAX_URI_LEN - 1] = '\0';
        } else if (mfg != NULL) {
            /* "ty=DeskJet 2700" + "mfg=HP" */
            /* mfg value looks like "HP" (TXTRecordGetValuePtr gives raw) */
            if (strncmp(MFG_HP, mfg, MFG_HP_LEN) == 0) {
                found      = true;
                *outOffset = 0;
                strncpy(outModel, ty, MAX_URI_LEN - 1);
                outModel[MAX_URI_LEN - 1] = '\0';
            }
        }
    }

    if (found) {
        size_t len = strlen(outModel);
        normalise_model_name(outModel, len);
        DBG("HP model: %s  offset: %zu\n", outModel, *outOffset);
    }

    free(ty);
    free(mfg);
    return found;
}

/* ------------------------------------------------------------------ */
/* Resolve callback                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    DNSServiceRef  sdRef;
    bool           done;
    int            resolvePoolIdx;
} ResolveCallbackCtx;

static void DNSSD_API resolve_callback(
        DNSServiceRef        sdRef,
        DNSServiceFlags      flags,
        uint32_t             interfaceIndex,
        DNSServiceErrorType  errorCode,
        const char          *fullname,
        const char          *hosttarget,
        uint16_t             port,          /* network byte order */
        uint16_t             txtLen,
        const unsigned char *txtRecord,
        void                *context)
{
    ResolveCallbackCtx *ctx = (ResolveCallbackCtx *)context;
    ctx->done = true;          /* signal the pump to stop waiting     */

    if (errorCode != kDNSServiceErr_NoError) {
        BUG("resolve_callback: error %d for %s\n", errorCode,
            fullname ? fullname : "(null)");
        return;
    }

    /* ── Resolve host → IPv4 via getaddrinfo ───────────────────── */
    char ipStr[MAX_IP_ADDR_LEN] = {'\0'};

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;   /* IPv4 only, matching Avahi version */
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hosttarget, NULL, &hints, &res) == 0 && res != NULL) {
        struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sa->sin_addr, ipStr, sizeof(ipStr));
        freeaddrinfo(res);
    } else {
        BUG("resolve_callback: getaddrinfo failed for %s\n", hosttarget);
        return;
    }

    DBG("Resolved %s → %s:%u\n", fullname, ipStr,
        ntohs(port));

    /* ── Check TXT record for HP model name ────────────────────── */
    char   modelStr[MAX_URI_LEN] = {'\0'};
    size_t offset = 0;

    if (get_hp_scanner_model(txtLen, txtRecord, modelStr, &offset)) {
        char uri[MAX_URI_LEN] = {'\0'};
        build_hp_uri(modelStr, offset, ipStr, uri);
        DBG("URI: %s\n", uri);
        uriBuf_append(&aUriBuf, &gUriBufState, uri);
    }
}

/* ------------------------------------------------------------------ */
/* Browse callback                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    DNSServiceRef  mainRef;   /* shared connection for resolve refs  */
    int           *pendingResolves;
} BrowseCallbackCtx;

static void DNSSD_API browse_callback(
        DNSServiceRef        sdRef,
        DNSServiceFlags      flags,
        uint32_t             interfaceIndex,
        DNSServiceErrorType  errorCode,
        const char          *serviceName,
        const char          *regtype,
        const char          *replyDomain,
        void                *context)
{
    if (errorCode != kDNSServiceErr_NoError) {
        BUG("browse_callback: error %d\n", errorCode);
        return;
    }

    if (!(flags & kDNSServiceFlagsAdd))
        return;   /* service removal – ignore */

    if (gResolveCount >= MAX_PENDING_RESOLVES) {
        BUG("browse_callback: resolve pool full, dropping %s\n", serviceName);
        return;
    }

    DBG("Found service: %s  type: %s  domain: %s\n",
        serviceName, regtype, replyDomain);

    /* Allocate a resolve context on the heap so it outlives this call */
    ResolveCallbackCtx *rctx = (ResolveCallbackCtx *)
                                calloc(1, sizeof(ResolveCallbackCtx));
    if (rctx == NULL) {
        BUG("browse_callback: calloc for resolve context failed\n");
        return;
    }
    rctx->done            = false;
    rctx->resolvePoolIdx  = gResolveCount;

    DNSServiceErrorType err =
        DNSServiceResolve(&rctx->sdRef,
                          0,                   /* flags         */
                          interfaceIndex,
                          serviceName,
                          regtype,
                          replyDomain,
                          resolve_callback,
                          rctx);

    if (err != kDNSServiceErr_NoError) {
        BUG("DNSServiceResolve failed: %d\n", err);
        free(rctx);
        return;
    }

    /* Register the fd so the event pump can poll it */
    gResolvePool[gResolveCount].sdRef = rctx->sdRef;
    gResolvePool[gResolveCount].done  = false;
    gResolveCount++;
}

/* ------------------------------------------------------------------ */
/* Generic select()-based event pump                                    */
/* ------------------------------------------------------------------ */

/*
 * Run a select() loop for at most timeoutSec seconds, processing
 * events on sdRef plus all active resolve refs in gResolvePool.
 *
 * Returns when:
 *   – the timeout expires, OR
 *   – stopWhenResolveDone is true AND all pending resolves finished.
 */
static void run_event_loop(DNSServiceRef *browseRefs,
                            int            browseCount,
                            int            timeoutSec,
                            bool           stopWhenResolveDone)
{
    struct timeval deadline;
    gettimeofday(&deadline, NULL);
    deadline.tv_sec += timeoutSec;

    for (;;) {
        struct timeval now, remaining;
        gettimeofday(&now, NULL);
        remaining.tv_sec  = deadline.tv_sec  - now.tv_sec;
        remaining.tv_usec = deadline.tv_usec - now.tv_usec;
        if (remaining.tv_usec < 0) {
            remaining.tv_sec--;
            remaining.tv_usec += 1000000;
        }
        if (remaining.tv_sec < 0)
            break;   /* timed out */

        /* Check if all resolves are done */
        if (stopWhenResolveDone && gResolveCount > 0) {
            bool allDone = true;
            for (int i = 0; i < gResolveCount; i++) {
                if (!gResolvePool[i].done) { allDone = false; break; }
            }
            if (allDone)
                break;
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        int maxFd = -1;

        /* Add browse refs */
        for (int i = 0; i < browseCount; i++) {
            int fd = DNSServiceRefSockFD(browseRefs[i]);
            if (fd >= 0) { FD_SET(fd, &readfds); if (fd > maxFd) maxFd = fd; }
        }

        /* Add active resolve refs */
        for (int i = 0; i < gResolveCount; i++) {
            if (!gResolvePool[i].done) {
                int fd = DNSServiceRefSockFD(gResolvePool[i].sdRef);
                if (fd >= 0) { FD_SET(fd, &readfds); if (fd > maxFd) maxFd = fd; }
            }
        }

        if (maxFd < 0)
            break;  /* nothing to wait on */

        int ret = select(maxFd + 1, &readfds, NULL, NULL, &remaining);
        if (ret < 0)
            break;
        if (ret == 0)
            continue;  /* timeout slice – re-check deadline */

        /* Process ready browse refs */
        for (int i = 0; i < browseCount; i++) {
            int fd = DNSServiceRefSockFD(browseRefs[i]);
            if (fd >= 0 && FD_ISSET(fd, &readfds))
                DNSServiceProcessResult(browseRefs[i]);
        }

        /* Process ready resolve refs and mark done */
        for (int i = 0; i < gResolveCount; i++) {
            if (gResolvePool[i].done)
                continue;
            int fd = DNSServiceRefSockFD(gResolvePool[i].sdRef);
            if (fd >= 0 && FD_ISSET(fd, &readfds)) {
                DNSServiceProcessResult(gResolvePool[i].sdRef);
                /* resolve_callback sets ctx->done; we mirror it here  */
                /* by checking the fd becoming inactive after one call. */
                gResolvePool[i].done = true;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* bonjour_probe_nw_scanners                                            */
/* ------------------------------------------------------------------ */

int bonjour_probe_nw_scanners(void)
{
    const char *serviceTypes[] = {
        BONJOUR_SVC_USCAN,
        BONJOUR_SVC_SCANNER,
    };
    const int   nTypes = (int)(sizeof(serviceTypes) / sizeof(serviceTypes[0]));

    DNSServiceRef browseRefs[2] = {NULL, NULL};
    int           openedCount   = 0;

    /* Open a browser for each service type */
    for (int i = 0; i < nTypes; i++) {
        DNSServiceErrorType err =
            DNSServiceBrowse(&browseRefs[i],
                             0,                         /* flags        */
                             kDNSServiceInterfaceIndexAny,
                             serviceTypes[i],
                             NULL,                      /* default domain */
                             browse_callback,
                             NULL);
        if (err != kDNSServiceErr_NoError) {
            BUG("DNSServiceBrowse failed for %s: %d\n", serviceTypes[i], err);
            browseRefs[i] = NULL;
        } else {
            openedCount++;
        }
    }

    if (openedCount == 0)
        goto cleanup;

    /* Phase 1: browse for BROWSE_TIMEOUT_SEC to collect service names */
    run_event_loop(browseRefs, nTypes, BROWSE_TIMEOUT_SEC, false);

    /* Phase 2: wait for all pending resolves */
    if (gResolveCount > 0)
        run_event_loop(browseRefs, nTypes, RESOLVE_TIMEOUT_SEC, true);

cleanup:
    for (int i = 0; i < nTypes; i++)
        if (browseRefs[i])  DNSServiceRefDeallocate(browseRefs[i]);

    for (int i = 0; i < gResolveCount; i++)
        if (gResolvePool[i].sdRef)  DNSServiceRefDeallocate(gResolvePool[i].sdRef);

    return (gUriBufState.bytesWritten > 0)
           ? BONJOUR_STATUS_OK
           : BONJOUR_STATUS_ERROR;
}

/* ------------------------------------------------------------------ */
/* bonjour_lookup                                                       */
/* ------------------------------------------------------------------ */

/*
 * Simple synchronous host-name → IPv4 wrapper using getaddrinfo.
 * (dns_sd has DNSServiceGetAddrInfo but getaddrinfo is simpler and
 * honours the system mDNS resolver automatically on macOS.)
 */
int bonjour_lookup(const char *iHostName)
{
    if (iHostName == NULL || *iHostName == '\0')
        return BONJOUR_STATUS_ERROR;

    int hostNameLen = (int)strlen(iHostName);
    if (hostNameLen > (MAX_NAME_LENGTH - APPEND_LOCAL_LEN))
        return BONJOUR_STATUS_ERROR;

    char fullName[MAX_NAME_LENGTH] = {0};
    snprintf(fullName, sizeof(fullName), "%s.local", iHostName);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(fullName, NULL, &hints, &res) != 0 || res == NULL) {
        BUG("bonjour_lookup: getaddrinfo failed for %s\n", fullName);
        return BONJOUR_STATUS_ERROR;
    }

    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sa->sin_addr, ipAddressBuff, sizeof(ipAddressBuff));
    freeaddrinfo(res);

    DBG("bonjour_lookup: %s → %s\n", fullName, ipAddressBuff);
    return BONJOUR_STATUS_OK;
}

/* ------------------------------------------------------------------ */
/* bonjour_reset                                                        */
/* ------------------------------------------------------------------ */

void bonjour_reset(void)
{
    free(aUriBuf);
    aUriBuf = NULL;
    memset(&gUriBufState, 0, sizeof(gUriBufState));
    memset(ipAddressBuff, 0, sizeof(ipAddressBuff));
    memset(gResolvePool,  0, sizeof(gResolvePool));
    gResolveCount = 0;
}

#endif /* __APPLE__ */
