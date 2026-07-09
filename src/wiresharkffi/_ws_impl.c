/*
 * _ws_impl.c - C helper layer for wiresharkffi.
 *
 * Abstracts the API differences between libwireshark 4.2.x, 4.4.x, 4.6.x, and 4.7.x
 * so that Python (_reader.py) and the CFFI cdef (_ws_build.py) stay stable across all
 * supported versions.  Every function that changed signatures or struct layouts
 * between versions is wrapped here behind a version-gate macro.
 *
 * Compiled by CFFI at install time; not intended to be built standalone.
 */

#include <stdlib.h>
#include <glib.h>
#include <ws_version.h>
#include <wsutil/buffer.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/wslog.h>
#include <wiretap/wtap.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/proto.h>
#include <epan/frame_data.h>
#include <epan/ftypes/ftypes.h>
#include <epan/tvbuff.h>
#include <wsutil/wmem/wmem.h>
#include <epan/wmem_scopes.h>
#include <epan/register.h>
#include <epan/prefs.h>
#include <wiretap/wtap_opttypes.h>

/* dfilter.h includes "dfilter-loc.h" which is an internal generated header not
 * installed by libwireshark-dev. Forward-declare only the pieces we need. */
typedef struct epan_dfilter dfilter_t;
/* Partial declaration: the real df_error_t also has a df_loc_t loc field which
 * requires dfilter-loc.h. We access only code and msg, so the truncated layout
 * is safe as long as we never read loc or pass df_error_t by value. */
typedef struct { int code; char *msg; } df_error_t;
extern void    df_error_free         (df_error_t **ep);
extern bool    dfilter_compile_full  (const char *text, dfilter_t **dfp,
                                      df_error_t **errpp, unsigned flags,
                                      const char *caller);
extern void    dfilter_free          (dfilter_t *df);
extern gboolean dfilter_apply_edt    (dfilter_t *df, struct epan_dissect *edt);
extern void    epan_dissect_prime_with_dfilter(epan_dissect_t *edt,
                                               const dfilter_t *dfcode);

/* DF_EXPAND_MACROS (bit 1) | DF_OPTIMIZE (bit 2) from epan/dfilter/dfilter.h.
 * Matches the dfilter_compile() convenience macro. Verify bit positions against
 * dfilter.h on each WS version bump - if new flags are inserted below bit 1 these
 * would silently enable or disable the wrong behaviour. */
#define _WS_DF_FLAGS ((1U << 1) | (1U << 2))

/* True when running against WS >= maj.min */
#define _WS_VERSION_GE(maj, min) \
    (WIRESHARK_VERSION_MAJOR > (maj) || \
     (WIRESHARK_VERSION_MAJOR == (maj) && WIRESHARK_VERSION_MINOR >= (min)))


/* ws_field_t
 *
 * Output record for _ws_walk_tree.  One entry per proto_tree node.
 *
 * vtype encoding:
 *   0 = no value     (field skipped - label_buf full or fvalue absent)
 *   1 = WSF_U32      u_val  (FT_UINT8/16/24/32, FT_CHAR, FT_FRAMENUM)
 *   2 = WSF_U64      u_val  (FT_UINT40..64, FT_EUI64)
 *   3 = WSF_I32      i_val  (FT_INT8..32)
 *   4 = WSF_I64      i_val  (FT_INT40..64)
 *   5 = WSF_DBL      d_val  (FT_FLOAT, FT_DOUBLE, FT_IEEE_11073_*)
 *   6 = WSF_STR      s_val  (string types + label fallback)
 *   7 = WSF_BYTES    s_val  raw bytes pointer, u_val = byte count (FT_BYTES / FT_UINT_BYTES)
 */
typedef struct {
    const char *abbrev;
    const char *s_val;
    uint64_t    u_val;
    int64_t     i_val;
    double      d_val;
    int         ftype;
    int         vtype;
} ws_field_t;


/* _ws_walk_tree
 *
 * Single C call per packet: iteratively walks the entire proto_node tree,
 * extracts typed values into out[0..n-1], and returns n.
 *
 * String values for pre-rendered nodes (almost all nodes when
 * proto_tree_visible=TRUE) point directly into the wmem pinfo pool via
 * fi->rep->representation - zero copy, valid until epan_dissect_reset.
 * The rare fill_label fallback writes into label_buf (one 240-byte slot each).
 *
 * If label_buf runs out of slots, the affected nodes are skipped (left with
 * vtype=0) and *dropped is incremented by one per skipped node so the caller
 * can surface the loss instead of silently returning a truncated field set.
 * *dropped may be NULL if the caller does not care.
 *
 * Stack depth 4096 is safe for any real packet (deepest seen: ~50 levels for
 * TLS/X.509 certificate chains).
 */
static int _ws_walk_tree(proto_tree *root,
                          ws_field_t *out,
                          char       *lbuf,
                          int         max_fields,
                          int         lbuf_size,
                          int        *dropped)
{
    proto_node *stack[4096];
    int sp = 0, nf = 0, lb = 0;

    if (dropped) *dropped = 0;
    if (!root) return 0;
    stack[sp++] = root;

    while (sp > 0 && nf < max_fields) {
        proto_node *node = stack[--sp];
        while (node && nf < max_fields) {
            field_info *fi = node->finfo;
            if (fi) {
                ws_field_t *f = &out[nf++];
                int ft        = fi->hfinfo->type;
                f->abbrev     = fi->hfinfo->abbrev;
                f->ftype      = ft;
                f->vtype      = 0;
                f->s_val      = NULL;

                fvalue_t *fv  = fi->value;

                if      (ft == FT_UINT8  || ft == FT_UINT16 || ft == FT_UINT24 ||
                         ft == FT_UINT32 || ft == FT_CHAR    || ft == FT_FRAMENUM) {
                    f->u_val = fvalue_get_uinteger(fv);   f->vtype = 1;

                } else if (ft == FT_UINT40 || ft == FT_UINT48 ||
                           ft == FT_UINT56 || ft == FT_UINT64 || ft == FT_EUI64) {
                    f->u_val = fvalue_get_uinteger64(fv); f->vtype = 2;

                } else if (ft == FT_INT8  || ft == FT_INT16 ||
                           ft == FT_INT24 || ft == FT_INT32) {
                    f->i_val = fvalue_get_sinteger(fv);   f->vtype = 3;

                } else if (ft == FT_INT40 || ft == FT_INT48 ||
                           ft == FT_INT56 || ft == FT_INT64) {
                    f->i_val = fvalue_get_sinteger64(fv); f->vtype = 4;

                } else if (ft == FT_FLOAT  || ft == FT_DOUBLE ||
                           ft == FT_IEEE_11073_SFLOAT || ft == FT_IEEE_11073_FLOAT) {
                    f->d_val = fvalue_get_floating(fv);   f->vtype = 5;

                } else if (ft == FT_BYTES || ft == FT_UINT_BYTES) {
                    const void *data = fvalue_get_bytes_data(fv);
                    size_t len       = fvalue_get_bytes_size(fv);
                    if (data && len > 0) {
                        f->s_val = (const char *)data;  /* bytes pointer, not a C string */
                        f->u_val = (uint64_t)len;
                        f->vtype = 7;                   /* WSF_BYTES */
                    }

                } else if (ft == FT_STRING     || ft == FT_STRINGZ   ||
                           ft == FT_UINT_STRING || ft == FT_STRINGZPAD ||
                           ft == FT_STRINGZTRUNC) {
                    f->s_val = fvalue_get_string(fv);     f->vtype = 6;

                } else {
                    /*
                     * All other types (IPv4, IPv6, Ethernet, bytes, OIDs, ...):
                     * use the pre-rendered rep string if present, else fall
                     * back to proto_item_fill_label into a label_buf slot.
                     * Strip the "abbrev: " prefix for non-container nodes.
                     */
                    if (fi->rep) {
                        const char *r = fi->rep->representation;
                        if (ft == FT_NONE || ft == FT_PROTOCOL) {
                            f->s_val = r;
                        } else {
                            const char *c = strstr(r, ": ");
                            f->s_val = c ? c + 2 : r;
                        }
                        f->vtype = 6;
                    } else if (lbuf_size - lb >= 240) {
                        char *slot = lbuf + lb;
#if _WS_VERSION_GE(4, 4)
                        size_t vo = 0;
                        proto_item_fill_label(fi, slot, &vo);
#else
                        proto_item_fill_label(fi, slot);
#endif
                        if (ft == FT_NONE || ft == FT_PROTOCOL) {
                            f->s_val = slot;
                        } else {
                            const char *c = strstr(slot, ": ");
                            f->s_val = c ? c + 2 : slot;
                        }
                        f->vtype = 6;
                        lb += 240;
                    } else if (dropped) {
                        /* label_buf full - node keeps vtype=0 and is skipped by
                         * collect_fields; report it so the caller can warn. */
                        (*dropped)++;
                    }
                }
            }

            if (node->first_child && sp < 4095)
                stack[sp++] = node->first_child;
            node = node->next;
        }
    }
    return nf;
}


/* _ws_global_init
 *
 * One-shot global init: logging, policies, config, wtap, epan, preferences.
 * Idempotent and thread-safe - safe to call from every PcapReader constructor;
 * only the first call does real work.
 *
 * Returns 0 on success, -1 if epan_init failed.
 */
G_LOCK_DEFINE_STATIC(ws_init_lock);
static int _ws_init_done = 0;
static int _ws_global_init(const char *argv0, int load_plugins)
{
    G_LOCK(ws_init_lock);
    if (_ws_init_done) { G_UNLOCK(ws_init_lock); return 0; }
    /* Set done=1 and release the lock BEFORE the slow epan_init call.
     * A racing thread will see done=1, skip init, and may call epan APIs
     * before epan_init completes - this is acceptable because epan_init is
     * not reentrant and callers must serialise their first PcapReader construction
     * if they need guaranteed ordering. */
    _ws_init_done = 1;
    G_UNLOCK(ws_init_lock);
#if _WS_VERSION_GE(4, 7)
    ws_log_init(NULL, NULL);
#elif _WS_VERSION_GE(4, 4)
    ws_log_init(NULL);
#else
    ws_log_init("libwireshark", NULL);
#endif
    init_process_policies();
    /* Strings match tshark's wireshark_flavor.c so we inherit its config paths and
     * env-var lookups. All must be non-NULL: libwireshark dereferences them during
     * config-path resolution deep inside epan_init. */
#if _WS_VERSION_GE(4, 7)
    configuration_init(argv0 ? argv0 : "tshark", "wireshark");
#elif _WS_VERSION_GE(4, 4)
    configuration_init(argv0 ? argv0 : "tshark");
#else
    configuration_init(argv0 ? argv0 : "tshark", NULL);
#endif
#if _WS_VERSION_GE(4, 7)
    wtap_init(FALSE, "WIRESHARK", NULL, 0);
#else
    wtap_init(FALSE);
#endif
#if _WS_VERSION_GE(4, 7)
    /* 4.7 moved dissector registration out of libwireshark: register_func/handoff_func
     * must point at the standard registries or no dissectors load. */
    static epan_app_data_t app_data;
    memset(&app_data, 0, sizeof(app_data));
    app_data.env_var_prefix = "WIRESHARK";
    app_data.register_func  = register_all_protocols;
    app_data.handoff_func   = register_all_protocol_handoffs;
    if (!epan_init(NULL, NULL, (gboolean)load_plugins, &app_data))
        return -1;
#else
    if (!epan_init(NULL, NULL, (gboolean)load_plugins))
        return -1;
#endif
    epan_load_settings();
    return 0;
}


/* packet_provider_funcs
 *
 * The callback signatures inside this struct changed in WS 4.4, so it is kept
 * opaque in the CFFI cdef.  Allocation and free are handled here in C.
 */
static struct packet_provider_funcs *_ws_alloc_prov_funcs(void)
{
    return g_new0(struct packet_provider_funcs, 1);
}

static void _ws_free_prov_funcs(struct packet_provider_funcs *pf)
{
    g_free(pf);
}


/* epan_dissect accessors */
static proto_tree *_ws_edt_tree(epan_dissect_t *edt) { return edt->tree; }


/* wtap_rec helpers
 *
 * wtap_rec layout changed in WS 4.4 (wtap_rec_init gained a size parameter).
 * Access is wrapped here so _reader.py never touches the struct directly.
 */
static wtap_rec *_ws_alloc_rec(void)
{
    wtap_rec *r = g_new0(wtap_rec, 1);
#if _WS_VERSION_GE(4, 4)
    wtap_rec_init(r, 65536);
#else
    wtap_rec_init(r);
#endif
    return r;
}

static void _ws_free_rec(wtap_rec *r)
{
    wtap_rec_cleanup(r);
    g_free(r);
}

static uint32_t _ws_rec_type    (const wtap_rec *r) { return r->rec_type; }
static long     _ws_rec_ts_secs (const wtap_rec *r) { return r->ts.secs; }
static int      _ws_rec_ts_nsecs(const wtap_rec *r) { return r->ts.nsecs; }
static uint32_t _ws_rec_caplen  (const wtap_rec *r) { return r->rec_header.packet_header.caplen; }
static uint32_t _ws_rec_len     (const wtap_rec *r) { return r->rec_header.packet_header.len; }


/* frame_data helpers */
static frame_data *_ws_alloc_fdata(void)
{
    return g_new0(frame_data, 1);
}

/* Reuse an already-allocated frame_data for the next packet. */
static void _ws_reinit_fdata(frame_data *fd, guint32 num,
                              const wtap_rec *rec, gint64 offset, guint32 cum)
{
    frame_data_destroy(fd);
    memset(fd, 0, sizeof(*fd));
    frame_data_init(fd, num, rec, offset, cum);
}

static void _ws_free_fdata(frame_data *fd)
{
    frame_data_destroy(fd);
    g_free(fd);
}


/* _ws_read
 *
 * WS 4.2: wtap_read(wth, rec, buf, err, err_info, offset)
 * WS 4.4: wtap_read(wth, rec, err, err_info, offset)  - Buffer param removed
 */
static gboolean _ws_read(wtap *wth, wtap_rec *rec, Buffer *ext_buf,
                          int *err, char **err_info, gint64 *offset)
{
#if _WS_VERSION_GE(4, 4)
    (void)ext_buf;
    return (gboolean)wtap_read(wth, rec, err, err_info, offset);
#else
    return wtap_read(wth, rec, ext_buf, err, err_info, offset);
#endif
}


/* _ws_dissect_run
 *
 * WS 4.2: epan_dissect_run(edt, ftype, rec, tvb, fd, cinfo)
 * WS 4.4: epan_dissect_run(edt, ftype, rec, fd, cinfo)  - tvb param removed;
 *         tvb is created internally from wtap_rec.
 *
 * On WS 4.2 we build the tvb manually from the Buffer contents.
 */
static void _ws_dissect_run(epan_dissect_t *edt, int ftype,
                             wtap_rec *rec, Buffer *ext_buf, frame_data *fd)
{
#if _WS_VERSION_GE(4, 4)
    (void)ext_buf;
    epan_dissect_run(edt, ftype, rec, fd, NULL);
#else
    {
        guint caplen  = rec->rec_header.packet_header.caplen;
        guint wirelen = rec->rec_header.packet_header.len;
        const uint8_t *data   = ext_buf->data + ext_buf->start;
        size_t         buflen = ext_buf->first_free - ext_buf->start;
        guint pkt_len = (buflen > 0 && caplen > buflen) ? (guint)buflen : caplen;
        tvbuff_t *tvb = tvb_new_real_data(data, pkt_len, (gint)wirelen);
        epan_dissect_run(edt, ftype, rec, tvb, fd, NULL);
    }
#endif
}


/* _ws_set_pref
 *
 * Set a preference and apply it immediately. Constructs "name:value" and
 * calls prefs_set_pref (same format as tshark -o), then prefs_apply_all
 * if global init has already run. The prefs= dict on PcapReader is the
 * recommended path since it always runs after epan_load_settings.
 *
 * Returns prefs_set_pref_e: 0=OK, 1=syntax error, 2=no such pref, 3=obsolete.
 */
static int _ws_set_pref(const char *name, const char *value)
{
    /* prefs_set_pref requires epan to be initialized; calling it before
     * epan_init / epan_load_settings crashes with a GLib assertion. */
    if (!g_atomic_int_get(&_ws_init_done)) return -1;
    if (!name || !value) return (int)PREFS_SET_SYNTAX_ERR;

    size_t nlen = strlen(name);
    size_t vlen = strlen(value);
    char *arg = (char *)malloc(nlen + 1 + vlen + 1);
    if (!arg) return (int)PREFS_SET_SYNTAX_ERR;

    memcpy(arg, name, nlen);
    arg[nlen] = ':';
    memcpy(arg + nlen + 1, value, vlen + 1);   /* copies NUL terminator */

    char *errmsg = NULL;
    int result = (int)prefs_set_pref(arg, &errmsg);
    if (errmsg) g_free(errmsg);
    free(arg);

    if (result == (int)PREFS_SET_OK)
        prefs_apply_all();

    return result;
}


/* Display filter helpers
 *
 * Wraps dfilter_compile / dfilter_apply_edt / dfilter_free.
 * Error messages are written into a caller-supplied buffer so Python can read
 * them without needing a separate g_free call.
 */
static dfilter_t *_ws_dfilter_compile(const char *text, char *err_buf, int err_buf_size)
{
    df_error_t *df_err = NULL;
    dfilter_t  *df     = NULL;
    if (err_buf && err_buf_size > 0) err_buf[0] = '\0';
    if (!dfilter_compile_full(text, &df, &df_err, _WS_DF_FLAGS, "_ws_dfilter_compile")) {
        if (df_err) {
            if (err_buf && err_buf_size > 1)
                snprintf(err_buf, (size_t)err_buf_size, "%s",
                         df_err->msg ? df_err->msg : "unknown error");
            df_error_free(&df_err);
        }
        return NULL;
    }
    return df;
}

static void     _ws_dfilter_free (dfilter_t *df)               { dfilter_free(df); }
static gboolean _ws_dfilter_apply(dfilter_t *df, epan_dissect_t *edt) { return dfilter_apply_edt(df, edt); }


/* ws_metadata_t / _ws_get_metadata
 *
 * Reads SHB (Section Header Block) string options.  Returns NULL char* for absent opts.
 * String pointers point into wtap's internal storage - valid until wtap_close.
 */
typedef struct {
    const char *shb_hardware;
    const char *shb_os;
    const char *shb_userappl;
} ws_metadata_t;

static void _ws_get_metadata(wtap *wth, ws_metadata_t *out)
{
    memset(out, 0, sizeof(*out));
    wtap_block_t shb = wtap_file_get_shb(wth, 0);
    if (!shb) return;
    char *val = NULL;
    if (wtap_block_get_string_option_value(shb, OPT_SHB_HARDWARE, &val) == WTAP_OPTTYPE_SUCCESS)
        out->shb_hardware = val;
    if (wtap_block_get_string_option_value(shb, OPT_SHB_OS, &val) == WTAP_OPTTYPE_SUCCESS)
        out->shb_os = val;
    if (wtap_block_get_string_option_value(shb, OPT_SHB_USERAPPL, &val) == WTAP_OPTTYPE_SUCCESS)
        out->shb_userappl = val;
}


/* _ws_get_idb_count / _ws_get_idb_strings
 *
 * Expose all Interface Description Blocks individually.
 *
 * wtap_file_get_idb_info returns a thin wrapper around the original wtap_block_t
 * objects (no deep copy). String pointers therefore point into the wtap handle's
 * storage and remain valid until wtap_close. Free only the outer wrapper (g_free),
 * not the interface_data array or the blocks inside.
 */
static uint32_t _ws_get_idb_count(wtap *wth)
{
    wtapng_iface_descriptions_t *idb_info = wtap_file_get_idb_info(wth);
    if (!idb_info) return 0;
    uint32_t n = idb_info->interface_data ? (uint32_t)idb_info->interface_data->len : 0;
    g_free(idb_info);
    return n;
}

static void _ws_get_idb_strings(wtap *wth, uint32_t idx,
                                  const char **name_out, const char **desc_out)
{
    *name_out = NULL;
    *desc_out = NULL;
    wtapng_iface_descriptions_t *idb_info = wtap_file_get_idb_info(wth);
    if (!idb_info) return;
    if (idb_info->interface_data && idx < (uint32_t)idb_info->interface_data->len) {
        wtap_block_t idb = g_array_index(idb_info->interface_data, wtap_block_t, idx);
        if (idb) {
            char *val = NULL;
            if (wtap_block_get_string_option_value(idb, OPT_IDB_NAME, &val) == WTAP_OPTTYPE_SUCCESS)
                *name_out = val;
            if (wtap_block_get_string_option_value(idb, OPT_IDB_DESCRIPTION, &val) == WTAP_OPTTYPE_SUCCESS)
                *desc_out = val;
        }
    }
    g_free(idb_info);
}


/* _ws_wtap_open_offline: absorbs the app_env_var_prefix arg added in WS 4.7 so the
 * cdef sees one signature. do_random is int because CFFI's _Bool round-trip is awkward. */
static wtap *_ws_wtap_open_offline(const char *filename, unsigned int type,
                                    int *err, char **err_info, int do_random)
{
#if _WS_VERSION_GE(4, 7)
    return wtap_open_offline(filename, type, err, err_info, (bool)do_random, "WIRESHARK");
#else
    return wtap_open_offline(filename, type, err, err_info, (bool)do_random);
#endif
}


/* Capture-file accessors
 *
 * Both underlying wtap functions are stable across all supported WS versions
 * (wtap_snapshot_length since 1.x, wtap_file_type_subtype_name since 3.4), so
 * no version gate is needed. Wrapping them fixes the return types in C rather
 * than pinning them in the cdef.
 */
static uint32_t _ws_snaplen(wtap *wth) { return (uint32_t)wtap_snapshot_length(wth); }

/* Short format name, e.g. "pcapng" / "pcap". Combines the subtype lookup and
 * the name lookup so Python receives a ready-to-decode string. */
static const char *_ws_file_type_name(wtap *wth)
{
    return wtap_file_type_subtype_name(wtap_file_type_subtype(wth));
}


/* Version accessors
 *
 * Expose compile-time WIRESHARK_VERSION_* macros as callable functions so
 * that the Python layer can inspect them at runtime without parsing strings.
 */
static int _ws_version_major(void) { return WIRESHARK_VERSION_MAJOR; }
static int _ws_version_minor(void) { return WIRESHARK_VERSION_MINOR; }
