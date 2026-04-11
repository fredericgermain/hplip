/*
 * avahiDiscovery.c  –  Linux / Avahi Bonjour backend (refactored)
 *
 * Original logic preserved; boilerplate moved into
 * bonjourDiscovery_common.h (uriBuf_append, build_hp_uri,
 * normalise_model_name, shared constants).
 *
 * Public API (same as original, now aliased to the common names):
 *
 *   int  bonjour_probe_nw_scanners(void);   // was avahi_probe_nw_scanners()
 *   int  bonjour_lookup(const char *host);  // was avahi_lookup()
 *   void bonjour_reset(void);               // new – frees aUriBuf etc.
 */

#ifdef HAVE_LIBAVAHI

#include "bonjourDiscovery_common.h"
#include "avahiDiscovery.h"   /* keep original header for AVAHI_* constants */

#include <errno.h>
#include <dbus/dbus.h>

/* ------------------------------------------------------------------ */
/* Module globals                                                       */
/* ------------------------------------------------------------------ */

char  *aUriBuf        = NULL;
char   ipAddressBuff[MAX_IP_ADDR_LEN] = {'\0'};

static UriBufState   gUriBufState  = {0, 0};
static AvahiSimplePoll *aSimplePoll = NULL;
static int           aAllForNow    = 0;
static int           aResolving    = 0;

DBusConnection *conn;   /* kept global – matches original ABI */

/* ------------------------------------------------------------------ */
/* Terminate helper (unchanged logic)                                   */
/* ------------------------------------------------------------------ */

static void check_terminate(void)
{
    assert(aAllForNow >= 0);
    assert(aResolving  >= 0);

    if (aAllForNow <= 0 && aResolving <= 0)
        avahi_simple_poll_quit(aSimplePoll);
}

/* ------------------------------------------------------------------ */
/* D-Bus / polkit / systemd helpers (unchanged from original)          */
/* ------------------------------------------------------------------ */

static void addDictWithStringValue(DBusMessageIter *iter,
                                    const char *key, const char *str)
{
    DBusMessageIter dict, entry, value;
    dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
        DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
        DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
        DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);
    dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
        DBUS_TYPE_STRING_AS_STRING, &value);
    dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &str);
    dbus_message_iter_close_container(&entry, &value);
    dbus_message_iter_close_container(&dict, &entry);
    dbus_message_iter_close_container(iter, &dict);
}

static void addEmptyStringDict(DBusMessageIter *iter)
{
    DBusMessageIter dict;
    dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
        DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
        DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_STRING_AS_STRING
        DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);
    dbus_message_iter_close_container(iter, &dict);
}

static void addArgumentsForAuthentication(DBusConnection *c,
                                           DBusMessageIter *iter)
{
    const char *busname = dbus_bus_get_unique_name(c);
    const char *kind    = SYSTEM_BUS_NAME;
    const char *action  = ACTION_ID;
    const char *cancel  = "";
    dbus_uint32_t flags = 1;
    DBusMessageIter subject;

    dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL, &subject);
    dbus_message_iter_append_basic(&subject, DBUS_TYPE_STRING, &kind);
    addDictWithStringValue(&subject, "name", busname);
    dbus_message_iter_close_container(iter, &subject);

    dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &action);
    addEmptyStringDict(iter);
    dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &flags);
    dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &cancel);
}

static bool systemdStartAvahiService(void)
{
    DBusMessage *msg, *response;
    DBusError    err;
    dbus_error_init(&err);

    const char *unit = AVAHI_SERVICE_NAME;
    const char *mode = AVHHI_SERVICE_MODE_REPLACE;

    msg = dbus_message_new_method_call(SYSTEMD_DBUS_NAME,
                                        SYSTEMD_DBUS_PATH,
                                        SYSTEMD_DBUS_INTF,
                                        SYSTEMD_START_SERVICE_METHOD);
    if (!msg) { BUG("failed to create dbus message\n"); return false; }

    dbus_message_append_args(msg,
        DBUS_TYPE_STRING, &unit,
        DBUS_TYPE_STRING, &mode,
        DBUS_TYPE_INVALID);

    response = dbus_connection_send_with_reply_and_block(
                   conn, msg, SYSTEMD_SERVICE_TIMEOUT, &err);
    if (dbus_error_is_set(&err)) {
        dbus_message_unref(msg);
        BUG("failed to start service: %s\n", err.message);
        return false;
    }
    dbus_message_unref(msg);
    dbus_message_unref(response);
    return true;
}

static bool checkAuthorizationForAvahiService(void)
{
    DBusMessage    *msg, *reply;
    DBusMessageIter iter;
    DBusError       err;
    bool            authorized = false;

    conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
    if (!conn) { BUG("Can't get on system bus"); return false; }

    msg = dbus_message_new_method_call(POLKIT_AUTH_DBUS,
                                        POLKIT_AUTH_PATH,
                                        POLKIT_AUTH_INTF,
                                        POLKIT_AUTH_METHOD_CALL);
    if (!msg) { BUG("Can't allocate new method call\n"); return false; }

    dbus_message_iter_init_append(msg, &iter);
    addArgumentsForAuthentication(conn, &iter);

    dbus_error_init(&err);
    reply = dbus_connection_send_with_reply_and_block(
                conn, msg, DBUS_TIMEOUT_INFINITE, &err);
    dbus_message_unref(msg);

    if (!reply) {
        if (dbus_error_is_set(&err)) {
            BUG("%s\n", err.message);
            dbus_error_free(&err);
        } else {
            BUG("Can't check authorization\n");
        }
        return false;
    }

    if (dbus_message_has_signature(reply, "(bba{ss})")) {
        DBusMessageIter result;
        dbus_bool_t     respAuthorized;
        dbus_message_iter_init(reply, &iter);
        dbus_message_iter_recurse(&iter, &result);
        dbus_message_iter_get_basic(&result, &respAuthorized);
        DBG("Authorized %d\n", respAuthorized);
        if (respAuthorized)
            authorized = true;
    } else {
        BUG("dbus response signature mismatch\n");
    }

    dbus_message_unref(reply);
    return authorized;
}

/* ------------------------------------------------------------------ */
/* HP model extraction – now delegates to common helpers               */
/* ------------------------------------------------------------------ */

static bool getHPScannerModel(AvahiStringList *iStrList,
                               const char      *ikey,
                               char           **oKeyValue,
                               size_t          *aMdlStrLen,
                               size_t          *oOffset)
{
    AvahiStringList *aStrList = avahi_string_list_find(iStrList, ikey);
    bool aValueFound = false;
    char *aKey = NULL, *aMfgValue = NULL;

    if (aStrList != NULL &&
        avahi_string_list_get_pair(aStrList, &aKey, oKeyValue, aMdlStrLen) == 0 &&
        *oKeyValue != NULL)
    {
        if (strncmp(MFG_HP, *oKeyValue, MFG_HP_LEN) == 0) {
            aValueFound = true;
            *oOffset    = HP_SKIP_MFG_NAME_SIZE;
        } else {
            AvahiStringList *bStrList = avahi_string_list_find(iStrList, MFG_NAME);
            if (bStrList)
                aMfgValue = avahi_string_list_get_text(bStrList);

            /* mfgValue looks like "mfg=HP"; compare from offset +4 */
            if (aMfgValue != NULL &&
                strncmp(MFG_HP, aMfgValue + 4, MFG_HP_LEN) == 0)
            {
                aValueFound = true;
                *oOffset    = 0;
            }
        }

        if (aValueFound) {
            /* Delegate to shared helper */
            normalise_model_name(*oKeyValue, *aMdlStrLen);
            DBG("oKeyValue is %s\n", *oKeyValue);
        }
    }

    if (aKey != NULL)
        avahi_free((void *)aKey);

    return aValueFound;
}

/* ------------------------------------------------------------------ */
/* Avahi resolve callback                                               */
/* ------------------------------------------------------------------ */

static void resolve_callback(
        AvahiServiceResolver             *r,
        AVAHI_GCC_UNUSED AvahiIfIndex     interface,
        AVAHI_GCC_UNUSED AvahiProtocol    protocol,
        AvahiResolverEvent                event,
        const char                       *name,
        const char                       *type,
        const char                       *domain,
        const char                       *host_name,
        const AvahiAddress               *address,
        uint16_t                          port,
        AvahiStringList                  *txt,
        AvahiLookupResultFlags            flags,
        AVAHI_GCC_UNUSED void            *userdata)
{
    assert(r);

    switch (event) {
    case AVAHI_RESOLVER_FAILURE:
        BUG("(Resolver) Failed to resolve service '%s' of type '%s' "
            "in domain '%s': %s\n",
            name, type, domain,
            avahi_strerror(avahi_client_errno(
                avahi_service_resolver_get_client(r))));
        break;

    case AVAHI_RESOLVER_FOUND: {
        char  aIPAddress[AVAHI_ADDRESS_STR_MAX] = {'\0'};
        char *aMdlStr   = NULL;
        size_t aMdlStrLen = 0;
        size_t aOffset    = 0;

        DBG("Service '%s' of type '%s' in domain '%s'\n",
            name, type, domain);

        avahi_address_snprint(aIPAddress, sizeof(aIPAddress), address);
        DBG("IP: %s\n", aIPAddress);

        if (getHPScannerModel(txt, TYPE_NAME, &aMdlStr,
                               &aMdlStrLen, &aOffset) == true)
        {
            char uri[MAX_URI_LEN] = {'\0'};
            build_hp_uri(aMdlStr, aOffset, aIPAddress, uri);

            /* Delegate buffer management to shared helper */
            uriBuf_append(&aUriBuf, &gUriBufState, uri);
        }

        if (aMdlStr != NULL)
            avahi_free((void *)aMdlStr);
        break;
    }
    }

    assert(aResolving > 0);
    aResolving--;
    check_terminate();
}

/* ------------------------------------------------------------------ */
/* Avahi browse callback                                                */
/* ------------------------------------------------------------------ */

static void browse_callback(
        AvahiServiceBrowser              *b,
        AvahiIfIndex                      interface,
        AvahiProtocol                     protocol,
        AvahiBrowserEvent                 event,
        const char                       *name,
        const char                       *type,
        const char                       *domain,
        AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
        void                             *userdata)
{
    AvahiClient *c = (AvahiClient *)userdata;
    assert(b);

    switch (event) {
    case AVAHI_BROWSER_CACHE_EXHAUSTED:
    case AVAHI_BROWSER_REMOVE:
        break;

    case AVAHI_BROWSER_FAILURE:
        BUG("(Browser) %s\n",
            avahi_strerror(avahi_client_errno(
                avahi_service_browser_get_client(b))));
        avahi_simple_poll_quit(aSimplePoll);
        return;

    case AVAHI_BROWSER_NEW:
        DBG("(Browser) NEW: service '%s' of type '%s' in domain '%s'\n",
            name, type, domain);
        if (!avahi_service_resolver_new(c, interface, protocol,
                name, type, domain,
                AVAHI_PROTO_INET, (AvahiLookupFlags)0,
                resolve_callback, c))
            BUG("Failed to resolve service '%s': %s\n",
                name, avahi_strerror(avahi_client_errno(c)));
        else
            aResolving++;
        break;

    case AVAHI_BROWSER_ALL_FOR_NOW:
        aAllForNow--;
        check_terminate();
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Avahi client callback (unchanged)                                    */
/* ------------------------------------------------------------------ */

static void client_callback(AvahiClient *c, AvahiClientState state,
                             AVAHI_GCC_UNUSED void *userdata)
{
    assert(c);
    if (state == AVAHI_CLIENT_FAILURE) {
        BUG("Server connection failure: %s\n",
            avahi_strerror(avahi_client_errno(c)));
        avahi_simple_poll_quit(aSimplePoll);
    }
}

/* ------------------------------------------------------------------ */
/* Avahi host-name resolver callback (unchanged)                        */
/* ------------------------------------------------------------------ */

static void host_name_resolver_callback(
        AvahiHostNameResolver            *r,
        AVAHI_GCC_UNUSED AvahiIfIndex     interface,
        AVAHI_GCC_UNUSED AvahiProtocol    protocol,
        AvahiResolverEvent                event,
        const char                       *name,
        const AvahiAddress               *a,
        AVAHI_GCC_UNUSED AvahiLookupResultFlags flags,
        AVAHI_GCC_UNUSED void            *userdata)
{
    assert(r);

    switch (event) {
    case AVAHI_RESOLVER_FOUND:
        avahi_address_snprint(ipAddressBuff, sizeof(ipAddressBuff), a);
        DBG("%s\t%s\n", name, ipAddressBuff);
        avahi_simple_poll_quit(aSimplePoll);
        break;

    case AVAHI_RESOLVER_FAILURE:
        BUG("Failed to resolve host name '%s'\n", name);
        avahi_simple_poll_quit(aSimplePoll);
        break;
    }

    avahi_host_name_resolver_free(r);
}

/* ------------------------------------------------------------------ */
/* avahi_setup – internal bootstrap (unchanged logic)                  */
/* ------------------------------------------------------------------ */

static void avahi_setup(const int iCommandType, const char *iHostName)
{
    AvahiClient       *client = NULL;
    AvahiServiceBrowser *sb   = NULL;
    int                error  = 0;

    if (!(aSimplePoll = avahi_simple_poll_new())) {
        BUG("Failed to create simple poll object.\n");
        goto fail;
    }

    client = avahi_client_new(avahi_simple_poll_get(aSimplePoll),
                               AVAHI_CLIENT_IGNORE_USER_CONFIG,
                               client_callback, NULL, &error);
    if (!client) {
        if ((error == AVAHI_ERR_NO_DAEMON || error == AVAHI_ERR_DISCONNECTED)
            && checkAuthorizationForAvahiService()
            && systemdStartAvahiService())
        {
            client = avahi_client_new(avahi_simple_poll_get(aSimplePoll),
                                       AVAHI_CLIENT_IGNORE_USER_CONFIG,
                                       client_callback, NULL, &error);
        }
        if (!client) {
            BUG("Failed to create client object: %s\n",
                avahi_strerror(error));
            goto fail;
        }
    }

    if (iCommandType == AVAHI_NET_DISCOVERY) {

        /* Browse _uscan._tcp */
        sb = avahi_service_browser_new(client, AVAHI_IF_UNSPEC,
                 AVAHI_PROTO_INET, BONJOUR_SVC_USCAN, NULL,
                 (AvahiLookupFlags)0, browse_callback, client);
        if (!sb) {
            if ((error == AVAHI_ERR_NO_DAEMON || error == AVAHI_ERR_DISCONNECTED)
                && checkAuthorizationForAvahiService()
                && systemdStartAvahiService())
            {
                sb = avahi_service_browser_new(client, AVAHI_IF_UNSPEC,
                         AVAHI_PROTO_INET, BONJOUR_SVC_USCAN, NULL,
                         (AvahiLookupFlags)0, browse_callback, client);
            }
            if (!sb) {
                BUG("Failed to create service browser: %s\n",
                    avahi_strerror(avahi_client_errno(client)));
                goto fail;
            }
        }
        aAllForNow++;

        /* Browse _scanner._tcp */
        sb = avahi_service_browser_new(client, AVAHI_IF_UNSPEC,
                 AVAHI_PROTO_INET, BONJOUR_SVC_SCANNER, NULL,
                 (AvahiLookupFlags)0, browse_callback, client);
        if (!sb) {
            BUG("Failed to create service browser: %s\n",
                avahi_strerror(avahi_client_errno(client)));
            goto fail;
        }
        aAllForNow++;

    } else if (iCommandType == AVAHI_HOST_LOOKUP) {
        if (!avahi_host_name_resolver_new(client, AVAHI_IF_UNSPEC,
                 AVAHI_PROTO_UNSPEC, iHostName, AVAHI_PROTO_INET,
                 (AvahiLookupFlags)0, host_name_resolver_callback, NULL))
        {
            BUG("Failed to create host name resolver: %s\n",
                avahi_strerror(avahi_client_errno(client)));
            goto fail;
        }
    }

    avahi_simple_poll_loop(aSimplePoll);

fail:
    if (client)     avahi_client_free(client);
    if (aSimplePoll) avahi_simple_poll_free(aSimplePoll);
    aSimplePoll = NULL;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int bonjour_probe_nw_scanners(void)
{
    avahi_setup(AVAHI_NET_DISCOVERY, "");
    return (gUriBufState.bytesWritten > 0)
           ? BONJOUR_STATUS_OK
           : BONJOUR_STATUS_ERROR;
}

/* Backwards-compat alias so existing call-sites still compile */
int avahi_probe_nw_scanners(void)
{
    return bonjour_probe_nw_scanners();
}

int bonjour_lookup(const char *iHostName)
{
    if (iHostName == NULL) return BONJOUR_STATUS_ERROR;

    int len = (int)strlen(iHostName);
    if (len > (MAX_NAME_LENGTH - APPEND_LOCAL_LEN))
        return BONJOUR_STATUS_ERROR;

    char fullName[MAX_NAME_LENGTH] = {0};
    snprintf(fullName, sizeof(fullName), "%s.local", iHostName);

    avahi_setup(AVAHI_HOST_LOOKUP, fullName);

    size_t ipLen = strlen(ipAddressBuff);
    return (ipLen > 0 && ipLen <= MAX_IP_ADDR_LEN)
           ? BONJOUR_STATUS_OK
           : BONJOUR_STATUS_ERROR;
}

/* Backwards-compat alias */
int avahi_lookup(const char *iHostName)
{
    return bonjour_lookup(iHostName);
}

void bonjour_reset(void)
{
    free(aUriBuf);
    aUriBuf = NULL;
    memset(&gUriBufState,  0, sizeof(gUriBufState));
    memset(ipAddressBuff,  0, sizeof(ipAddressBuff));
    aAllForNow = 0;
    aResolving = 0;
}

#endif /* HAVE_LIBAVAHI */
