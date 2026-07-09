"""
_ws_build.py - CFFI build module for wiresharkffi.

setuptools discovers `ffi` at module level via setup.py's cffi_modules entry.
Can also be run directly to compile in-place:
    python3 src/wiresharkffi/_ws_build.py

Supports libwireshark 4.2.x, 4.4.x, 4.6.x, and 4.7.x (version-adaptive C helpers in _ws_impl.c).

Requirements (Ubuntu/Debian):
    sudo apt install libwireshark-dev libwiretap-dev libwsutil-dev \
                     libglib2.0-dev pkg-config python3-cffi
Requirements (Arch):
    sudo pacman -S wireshark-qt python-cffi pkg-config
"""

import os
import pathlib
import subprocess
from cffi import FFI

ffi = FFI()

# cdef
#
# API (compile) mode: the C compiler resolves struct layouts exactly.
#
# Structs whose layout changed between WS 4.2 and 4.4 are kept OPAQUE here.
# All access goes through _ws_* C helpers defined in _ws_impl.c.
# This makes the cdef stable across versions.

ffi.cdef(r"""
/* Opaque handles */
typedef struct epan_session     epan_t;
typedef struct tvbuff           tvbuff_t;
typedef struct wtap             wtap;
typedef struct wtap_rec         wtap_rec;
typedef struct _frame_data      frame_data;

/* Opaque - layout changed in WS 4.4 (hfinfo gained const, new display field) */
typedef struct field_info  field_info;

/* Opaque - use _ws_node_* helpers */
typedef struct _proto_node proto_node;

/* Opaque - use _ws_edt_* helpers */
typedef struct epan_dissect epan_dissect_t;

/* Opaque - callback signatures changed in WS 4.4 */
struct packet_provider_data;
struct packet_provider_funcs;

/* GLib / C primitives */
typedef unsigned int   guint;
typedef int            gint;
typedef int            gboolean;
typedef unsigned char  guint8;
typedef unsigned short guint16;
typedef unsigned int   guint32;
typedef long           gint64;
typedef unsigned long  guint64;
typedef void          *gpointer;
typedef char           gchar;

/* Buffer (wsutil/buffer.h) - layout unchanged across WS versions */
typedef struct {
    uint8_t *data;
    size_t   allocated;
    size_t   start;
    size_t   first_free;
} Buffer;

void ws_buffer_init(Buffer *buffer, size_t space);
void ws_buffer_free(Buffer *buffer);

/* proto_node type aliases */
typedef proto_node proto_tree;
typedef proto_node proto_item;

/* Field type enum - FT_NUM_TYPES omitted, its value shifts as WS adds types */
typedef enum ftenum {
    FT_NONE,   FT_PROTOCOL, FT_BOOLEAN, FT_CHAR,
    FT_UINT8,  FT_UINT16,   FT_UINT24,  FT_UINT32,
    FT_UINT40, FT_UINT48,   FT_UINT56,  FT_UINT64,
    FT_INT8,   FT_INT16,    FT_INT24,   FT_INT32,
    FT_INT40,  FT_INT48,    FT_INT56,   FT_INT64,
    FT_IEEE_11073_SFLOAT, FT_IEEE_11073_FLOAT,
    FT_FLOAT,  FT_DOUBLE,
    FT_ABSOLUTE_TIME, FT_RELATIVE_TIME,
    FT_STRING, FT_STRINGZ,  FT_UINT_STRING,
    FT_ETHER,  FT_BYTES,    FT_UINT_BYTES,
    FT_IPv4,   FT_IPv6,     FT_IPXNET,     FT_FRAMENUM,
    FT_GUID,   FT_OID,      FT_EUI64,      FT_AX25,    FT_VINES,
    FT_REL_OID, FT_SYSTEM_ID,
    FT_STRINGZPAD, FT_FCWWN, FT_STRINGZTRUNC
} ftenum_t;

/* Preference result codes (prefs_set_pref_e) */
typedef enum {
    PREFS_SET_OK,
    PREFS_SET_SYNTAX_ERR,
    PREFS_SET_NO_SUCH_PREF,
    PREFS_SET_OBSOLETE
} prefs_set_pref_e;

/* epan session */
epan_t *epan_new (struct packet_provider_data *prov,
                  const struct packet_provider_funcs *funcs);
void    epan_free(epan_t *session);

/* epan_dissect (opaque - use helpers below) */
epan_dissect_t *epan_dissect_new  (epan_t *session,
                                   gboolean create_proto_tree,
                                   gboolean proto_tree_visible);
void            epan_dissect_reset(epan_dissect_t *edt);
void            epan_dissect_free (epan_dissect_t *edt);

/* wtap I/O */
wtap *_ws_wtap_open_offline (const char *filename, unsigned int type,
                              int *err, char **err_info, int do_random);
int   wtap_file_type_subtype(wtap *wth);
void  wtap_close            (wtap *wth);

/*
 * ws_field_t - one entry per proto_tree node, filled by _ws_walk_tree.
 *
 * vtype values:
 *   0 = no value     abbrev only
 *   1 = WSF_U32      u_val  (FT_UINT8 / UINT16 / UINT24 / UINT32 / CHAR / FRAMENUM)
 *   2 = WSF_U64      u_val  (FT_UINT40..UINT64, FT_EUI64)
 *   3 = WSF_I32      i_val  (FT_INT8..INT32)
 *   4 = WSF_I64      i_val  (FT_INT40..INT64)
 *   5 = WSF_DBL      d_val  (FT_FLOAT / DOUBLE / IEEE_11073_*)
 *   6 = WSF_STR      s_val  non-NULL string pointer
 *   7 = WSF_BYTES    s_val  raw bytes pointer, u_val = byte count (FT_BYTES / FT_UINT_BYTES)
 */
typedef struct {
    const char *abbrev;   /* permanent pointer into hfinfo table  */
    const char *s_val;    /* string value (wmem pool or label_buf) */
    uint64_t    u_val;
    int64_t     i_val;
    double      d_val;
    int         ftype;    /* ftenum_t                              */
    int         vtype;    /* 0..7 as above                         */
} ws_field_t;

/*
 * Walk the proto_tree rooted at `root`, writing at most `max_fields`
 * ws_field_t entries into `out`.  String fallbacks (fill_label) write
 * into `label_buf` (size `label_buf_size`).  Returns the number of
 * entries written.  One C call per packet replaces O(nodes) CFFI calls.
 * `dropped` is set to the number of nodes skipped because label_buf ran
 * out of slots (may be NULL).
 */
int _ws_walk_tree(proto_tree *root,
                  ws_field_t *out,
                  char       *label_buf,
                  int         max_fields,
                  int         label_buf_size,
                  int        *dropped);

/*
 * C helpers - stable API across WS versions.
 * All version-sensitive calls live inside these; Python never calls the
 * raw WS functions that changed signatures between 4.2 and 4.4.
 */

/* One-shot global init: ws_log, policies, config, wtap, epan, settings.
   Returns 0 on success, -1 if epan_init failed. Idempotent after first call. */
int _ws_global_init(const char *argv0, int load_plugins);

/* packet_provider_funcs - opaque alloc/free (struct changed in WS 4.4) */
struct packet_provider_funcs *_ws_alloc_prov_funcs(void);
void                          _ws_free_prov_funcs (struct packet_provider_funcs *pf);

/* edt.tree accessor */
proto_tree *_ws_edt_tree(epan_dissect_t *edt);

/* wtap_rec helpers */
wtap_rec  *_ws_alloc_rec   (void);
void       _ws_free_rec    (wtap_rec *rec);
uint32_t   _ws_rec_type    (const wtap_rec *r);
long       _ws_rec_ts_secs (const wtap_rec *r);
int        _ws_rec_ts_nsecs(const wtap_rec *r);
uint32_t   _ws_rec_caplen  (const wtap_rec *r);
uint32_t   _ws_rec_len     (const wtap_rec *r);

/* frame_data helpers */
frame_data *_ws_alloc_fdata  (void);
void        _ws_reinit_fdata (frame_data *fd, uint32_t num,
                               const wtap_rec *rec, gint64 offset, uint32_t cum);
void        _ws_free_fdata   (frame_data *fd);

/* Read one packet (hides Buffer-param removal in WS 4.4) */
gboolean _ws_read(wtap *wth, wtap_rec *rec, Buffer *ext_buf,
                  int *err, char **err_info, gint64 *offset);

/* Dissect one packet (hides tvb-param removal and tvb creation in WS 4.4) */
void _ws_dissect_run(epan_dissect_t *edt, int ftype,
                     wtap_rec *rec, Buffer *ext_buf, frame_data *fd);

/* Set a preference by "name:value" and apply immediately.
   Returns prefs_set_pref_e (0=OK, 1=syntax err, 2=no such pref, 3=obsolete). */
int _ws_set_pref(const char *name, const char *value);

/* Display filter */
typedef struct epan_dfilter dfilter_t;
dfilter_t *_ws_dfilter_compile(const char *text, char *err_buf, int err_buf_size);
void       _ws_dfilter_free   (dfilter_t *df);
gboolean   _ws_dfilter_apply  (dfilter_t *df, epan_dissect_t *edt);
void epan_dissect_prime_with_dfilter(epan_dissect_t *edt, const dfilter_t *dfcode);

/* Metadata: SHB string options */
typedef struct {
    const char *shb_hardware;
    const char *shb_os;
    const char *shb_userappl;
} ws_metadata_t;

void     _ws_get_metadata  (wtap *wth, ws_metadata_t *out);
uint32_t _ws_get_idb_count (wtap *wth);
void     _ws_get_idb_strings(wtap *wth, uint32_t idx,
                              const char **name_out, const char **desc_out);

/* GLib memory */
void g_free(void *mem);

/* Capture-file accessors (stable wtap APIs, no version gate needed) */
uint32_t    _ws_snaplen       (wtap *wth);
const char *_ws_file_type_name(wtap *wth);

/* Compile-time version accessors */
int _ws_version_major(void);
int _ws_version_minor(void);
""")

# C source - loaded from _ws_impl.c so the file can be edited with normal C tooling.

_C_SOURCE = pathlib.Path(__file__).with_name("_ws_impl.c").read_text()

# Path detection

def _pkg(*args):
    try:
        out = subprocess.check_output(["pkg-config", *args], stderr=subprocess.DEVNULL)
        return out.decode().split()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def _ws_paths():
    for name in ("wireshark", "wireshark4", "wireshark3"):
        cf = _pkg("--cflags", name)
        lf = _pkg("--libs",   name)
        if cf or lf:
            inc  = [f[2:] for f in cf if f.startswith("-I")]
            ldir = [f[2:] for f in lf if f.startswith("-L")]
            libs = [f[2:] for f in lf if f.startswith("-l")] or ["wireshark", "wiretap", "wsutil"]
            return inc, ldir, libs

    fallback_inc  = ["/usr/include/wireshark", "/usr/local/include/wireshark",
                     "/opt/homebrew/include/wireshark"]
    fallback_ldir = ["/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
                     "/usr/local/lib", "/opt/homebrew/lib"]
    inc  = [p for p in fallback_inc  if os.path.isdir(p)]
    ldir = [p for p in fallback_ldir if os.path.isdir(p)]
    if not inc:
        raise RuntimeError(
            "wireshark headers not found - install libwireshark-dev "
            "(Ubuntu/Debian: sudo apt install libwireshark-dev libglib2.0-dev pkg-config)"
        )
    return inc, ldir, ["wireshark", "wiretap", "wsutil"]


def _glib_paths():
    cf = _pkg("--cflags", "glib-2.0")
    lf = _pkg("--libs",   "glib-2.0")
    if cf or lf:
        return ([f[2:] for f in cf if f.startswith("-I")],
                [f[2:] for f in lf if f.startswith("-L")])

    # pkg-config not available - probe the standard locations directly.
    # GLib splits headers across two directories: the arch-independent
    # glib-2.0/ tree and an arch-specific include dir that contains glibconfig.h.
    candidates_inc = [
        "/usr/include/glib-2.0",
        "/usr/local/include/glib-2.0",
        "/opt/homebrew/include/glib-2.0",
    ]
    candidates_glibconfig = [
        "/usr/lib/x86_64-linux-gnu/glib-2.0/include",
        "/usr/lib/aarch64-linux-gnu/glib-2.0/include",
        "/usr/lib/arm-linux-gnueabihf/glib-2.0/include",
        "/usr/local/lib/glib-2.0/include",
        "/opt/homebrew/lib/glib-2.0/include",
    ]
    inc = [p for p in candidates_inc        if os.path.isdir(p)]
    inc += [p for p in candidates_glibconfig if os.path.isdir(p)]
    if not inc:
        raise RuntimeError(
            "GLib headers not found - install libglib2.0-dev "
            "(Ubuntu/Debian: sudo apt install libglib2.0-dev pkg-config)"
        )
    return inc, []


# set_source

_ws_inc, _ws_ldir, _ws_libs = _ws_paths()
_gl_inc, _gl_ldir            = _glib_paths()

ffi.set_source(
    "wiresharkffi._ws",
    _C_SOURCE,
    include_dirs       = _ws_inc + _gl_inc,
    library_dirs       = _ws_ldir + _gl_ldir,
    libraries          = _ws_libs,
    extra_compile_args = ["-Wno-deprecated-declarations", "-Wno-unused-function"],
)

# Standalone compile

if __name__ == "__main__":
    out_dir = str(pathlib.Path(__file__).parent.parent)
    ffi.compile(tmpdir=out_dir, verbose=True)
    print("wiresharkffi._ws compiled successfully.")
