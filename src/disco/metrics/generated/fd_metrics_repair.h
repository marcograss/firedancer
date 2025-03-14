/* THIS FILE IS GENERATED BY gen_metrics.py. DO NOT HAND EDIT. */

#include "../fd_metrics_base.h"
#include "fd_metrics_enums.h"

#define FD_METRICS_COUNTER_REPAIR_RECV_CLNT_PKT_OFF  (16UL)
#define FD_METRICS_COUNTER_REPAIR_RECV_CLNT_PKT_NAME "repair_recv_clnt_pkt"
#define FD_METRICS_COUNTER_REPAIR_RECV_CLNT_PKT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_REPAIR_RECV_CLNT_PKT_DESC "Now many client packets have we received"
#define FD_METRICS_COUNTER_REPAIR_RECV_CLNT_PKT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_OFF  (17UL)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_NAME "repair_recv_serv_pkt"
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_DESC "How many server packets have we received"
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_CORRUPT_PKT_OFF  (18UL)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_CORRUPT_PKT_NAME "repair_recv_serv_corrupt_pkt"
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_CORRUPT_PKT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_CORRUPT_PKT_DESC "How many corrupt server packets have we received"
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_CORRUPT_PKT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_INVALID_SIGNATURE_OFF  (19UL)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_INVALID_SIGNATURE_NAME "repair_recv_serv_invalid_signature"
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_INVALID_SIGNATURE_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_INVALID_SIGNATURE_DESC "How many invalid signatures have we received"
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_INVALID_SIGNATURE_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_FULL_PING_TABLE_OFF  (20UL)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_FULL_PING_TABLE_NAME "repair_recv_serv_full_ping_table"
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_FULL_PING_TABLE_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_FULL_PING_TABLE_DESC "Is our ping table full and causing packet drops"
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_FULL_PING_TABLE_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_TYPES_OFF  (21UL)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_TYPES_NAME "repair_recv_serv_pkt_types"
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_TYPES_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_TYPES_DESC "Server messages received"
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_TYPES_CVT  (FD_METRICS_CONVERTER_NONE)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_TYPES_CNT  (5UL)

#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_TYPES_PONG_OFF (21UL)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_TYPES_WINDOW_OFF (22UL)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_TYPES_HIGHEST_WINDOW_OFF (23UL)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_TYPES_ORPHAN_OFF (24UL)
#define FD_METRICS_COUNTER_REPAIR_RECV_SERV_PKT_TYPES_UNKNOWN_OFF (25UL)

#define FD_METRICS_COUNTER_REPAIR_RECV_PKT_CORRUPTED_MSG_OFF  (26UL)
#define FD_METRICS_COUNTER_REPAIR_RECV_PKT_CORRUPTED_MSG_NAME "repair_recv_pkt_corrupted_msg"
#define FD_METRICS_COUNTER_REPAIR_RECV_PKT_CORRUPTED_MSG_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_REPAIR_RECV_PKT_CORRUPTED_MSG_DESC "How many corrupt messages have we received"
#define FD_METRICS_COUNTER_REPAIR_RECV_PKT_CORRUPTED_MSG_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_REPAIR_SEND_PKT_CNT_OFF  (27UL)
#define FD_METRICS_COUNTER_REPAIR_SEND_PKT_CNT_NAME "repair_send_pkt_cnt"
#define FD_METRICS_COUNTER_REPAIR_SEND_PKT_CNT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_REPAIR_SEND_PKT_CNT_DESC "How many packets have sent"
#define FD_METRICS_COUNTER_REPAIR_SEND_PKT_CNT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_REPAIR_SENT_PKT_TYPES_OFF  (28UL)
#define FD_METRICS_COUNTER_REPAIR_SENT_PKT_TYPES_NAME "repair_sent_pkt_types"
#define FD_METRICS_COUNTER_REPAIR_SENT_PKT_TYPES_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_REPAIR_SENT_PKT_TYPES_DESC "What types of client messages are we sending"
#define FD_METRICS_COUNTER_REPAIR_SENT_PKT_TYPES_CVT  (FD_METRICS_CONVERTER_NONE)
#define FD_METRICS_COUNTER_REPAIR_SENT_PKT_TYPES_CNT  (3UL)

#define FD_METRICS_COUNTER_REPAIR_SENT_PKT_TYPES_NEEDED_WINDOW_OFF (28UL)
#define FD_METRICS_COUNTER_REPAIR_SENT_PKT_TYPES_NEEDED_HIGHEST_WINDOW_OFF (29UL)
#define FD_METRICS_COUNTER_REPAIR_SENT_PKT_TYPES_NEEDED_ORPHAN_OFF (30UL)

#define FD_METRICS_REPAIR_TOTAL (15UL)
extern const fd_metrics_meta_t FD_METRICS_REPAIR[FD_METRICS_REPAIR_TOTAL];
