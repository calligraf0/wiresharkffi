"""
_constants.py - Shared constants for buffer sizing and stream-field mapping.
"""

# Pre-allocated C buffer sizes.
# CAP_BUF_SIZE: initial wtap capture buffer (grows automatically if needed).
# LABEL_BUF_SIZE: safety net for fill_label fallbacks; pre-rendered rep covers almost all nodes.
MAX_FIELDS     = 50000
LABEL_BUF_SIZE = 65536
CAP_BUF_SIZE   = 65536

# wtap_rec.rec_type value for normal packet records (REC_TYPE_PACKET = 0 in wtap.h).
REC_TYPE_PACKET = 0

# Maps Wireshark field abbreviations to logical stream/conversation key names
# used to populate the "_streams" entry in each packet dict.
STREAM_FIELDS: dict[str, str] = {
    "tcp.stream":          "tcp",
    "udp.stream":          "udp",
    "http2.streamid":      "http2",
    "quic.stream_id":      "quic",
    "sctp.assoc_index":    "sctp",
    "dcerpc.cn_call_id":   "dcerpc",
    "diameter.Session-Id": "diameter",
    "smb.uid":             "smb",
    "smb2.sesid":          "smb2",
}
