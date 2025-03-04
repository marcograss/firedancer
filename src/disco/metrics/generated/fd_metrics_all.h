/* THIS FILE IS GENERATED BY gen_metrics.py. DO NOT HAND EDIT. */

#include "../fd_metrics_base.h"

#include "fd_metrics_net.h"
#include "fd_metrics_quic.h"
#include "fd_metrics_bundle.h"
#include "fd_metrics_verify.h"
#include "fd_metrics_dedup.h"
#include "fd_metrics_resolv.h"
#include "fd_metrics_pack.h"
#include "fd_metrics_bank.h"
#include "fd_metrics_poh.h"
#include "fd_metrics_shred.h"
#include "fd_metrics_store.h"
#include "fd_metrics_replay.h"
#include "fd_metrics_storei.h"
#include "fd_metrics_gossip.h"
#include "fd_metrics_netlnk.h"
/* Start of LINK OUT metrics */

#define FD_METRICS_COUNTER_LINK_SLOW_COUNT_OFF  (0UL)
#define FD_METRICS_COUNTER_LINK_SLOW_COUNT_NAME "link_slow_count"
#define FD_METRICS_COUNTER_LINK_SLOW_COUNT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_LINK_SLOW_COUNT_DESC "The number of times the consumer was detected as rate limiting consumer by the producer."
#define FD_METRICS_COUNTER_LINK_SLOW_COUNT_CVT  (FD_METRICS_CONVERTER_NONE)

/* Start of LINK IN metrics */

#define FD_METRICS_COUNTER_LINK_CONSUMED_COUNT_OFF  (0UL)
#define FD_METRICS_COUNTER_LINK_CONSUMED_COUNT_NAME "link_consumed_count"
#define FD_METRICS_COUNTER_LINK_CONSUMED_COUNT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_LINK_CONSUMED_COUNT_DESC "The number of times the link reader has consumed a fragment."
#define FD_METRICS_COUNTER_LINK_CONSUMED_COUNT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF  (1UL)
#define FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_NAME "link_consumed_size_bytes"
#define FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_DESC "The total number of bytes read by the link consumer."
#define FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_LINK_FILTERED_COUNT_OFF  (2UL)
#define FD_METRICS_COUNTER_LINK_FILTERED_COUNT_NAME "link_filtered_count"
#define FD_METRICS_COUNTER_LINK_FILTERED_COUNT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_LINK_FILTERED_COUNT_DESC "The number of fragments that were filtered and not consumed."
#define FD_METRICS_COUNTER_LINK_FILTERED_COUNT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_LINK_FILTERED_SIZE_BYTES_OFF  (3UL)
#define FD_METRICS_COUNTER_LINK_FILTERED_SIZE_BYTES_NAME "link_filtered_size_bytes"
#define FD_METRICS_COUNTER_LINK_FILTERED_SIZE_BYTES_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_LINK_FILTERED_SIZE_BYTES_DESC "The total number of bytes read by the link consumer that were filtered."
#define FD_METRICS_COUNTER_LINK_FILTERED_SIZE_BYTES_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_OFF  (4UL)
#define FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_NAME "link_overrun_polling_count"
#define FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_DESC "The number of times the link has been overrun while polling."
#define FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF  (5UL)
#define FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_NAME "link_overrun_polling_frag_count"
#define FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_DESC "The number of fragments the link has not processed because it was overrun while polling."
#define FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_LINK_OVERRUN_READING_COUNT_OFF  (6UL)
#define FD_METRICS_COUNTER_LINK_OVERRUN_READING_COUNT_NAME "link_overrun_reading_count"
#define FD_METRICS_COUNTER_LINK_OVERRUN_READING_COUNT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_LINK_OVERRUN_READING_COUNT_DESC "The number of input overruns detected while reading metadata by the consumer."
#define FD_METRICS_COUNTER_LINK_OVERRUN_READING_COUNT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF  (7UL)
#define FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_NAME "link_overrun_reading_frag_count"
#define FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_DESC "The number of fragments the link has not processed because it was overrun while reading."
#define FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_CVT  (FD_METRICS_CONVERTER_NONE)

/* Start of TILE metrics */

#define FD_METRICS_GAUGE_TILE_PID_OFF  (0UL)
#define FD_METRICS_GAUGE_TILE_PID_NAME "tile_pid"
#define FD_METRICS_GAUGE_TILE_PID_TYPE (FD_METRICS_TYPE_GAUGE)
#define FD_METRICS_GAUGE_TILE_PID_DESC "The process ID of the tile."
#define FD_METRICS_GAUGE_TILE_PID_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_GAUGE_TILE_TID_OFF  (1UL)
#define FD_METRICS_GAUGE_TILE_TID_NAME "tile_tid"
#define FD_METRICS_GAUGE_TILE_TID_TYPE (FD_METRICS_TYPE_GAUGE)
#define FD_METRICS_GAUGE_TILE_TID_DESC "The thread ID of the tile. Always the same as the Pid in production, but might be different in development."
#define FD_METRICS_GAUGE_TILE_TID_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_INVOLUNTARY_COUNT_OFF  (2UL)
#define FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_INVOLUNTARY_COUNT_NAME "tile_context_switch_involuntary_count"
#define FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_INVOLUNTARY_COUNT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_INVOLUNTARY_COUNT_DESC "The number of involuntary context switches."
#define FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_INVOLUNTARY_COUNT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_VOLUNTARY_COUNT_OFF  (3UL)
#define FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_VOLUNTARY_COUNT_NAME "tile_context_switch_voluntary_count"
#define FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_VOLUNTARY_COUNT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_VOLUNTARY_COUNT_DESC "The number of voluntary context switches."
#define FD_METRICS_COUNTER_TILE_CONTEXT_SWITCH_VOLUNTARY_COUNT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_GAUGE_TILE_STATUS_OFF  (4UL)
#define FD_METRICS_GAUGE_TILE_STATUS_NAME "tile_status"
#define FD_METRICS_GAUGE_TILE_STATUS_TYPE (FD_METRICS_TYPE_GAUGE)
#define FD_METRICS_GAUGE_TILE_STATUS_DESC "The current status of the tile. 0 is booting, 1 is running."
#define FD_METRICS_GAUGE_TILE_STATUS_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_GAUGE_TILE_HEARTBEAT_OFF  (5UL)
#define FD_METRICS_GAUGE_TILE_HEARTBEAT_NAME "tile_heartbeat"
#define FD_METRICS_GAUGE_TILE_HEARTBEAT_TYPE (FD_METRICS_TYPE_GAUGE)
#define FD_METRICS_GAUGE_TILE_HEARTBEAT_DESC "The last UNIX timestamp in nanoseconds that the tile heartbeated."
#define FD_METRICS_GAUGE_TILE_HEARTBEAT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_GAUGE_TILE_IN_BACKPRESSURE_OFF  (6UL)
#define FD_METRICS_GAUGE_TILE_IN_BACKPRESSURE_NAME "tile_in_backpressure"
#define FD_METRICS_GAUGE_TILE_IN_BACKPRESSURE_TYPE (FD_METRICS_TYPE_GAUGE)
#define FD_METRICS_GAUGE_TILE_IN_BACKPRESSURE_DESC "Whether the tile is currently backpressured or not, either 1 or 0."
#define FD_METRICS_GAUGE_TILE_IN_BACKPRESSURE_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_TILE_BACKPRESSURE_COUNT_OFF  (7UL)
#define FD_METRICS_COUNTER_TILE_BACKPRESSURE_COUNT_NAME "tile_backpressure_count"
#define FD_METRICS_COUNTER_TILE_BACKPRESSURE_COUNT_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_TILE_BACKPRESSURE_COUNT_DESC "Number of times the times the tile has had to wait for one of more consumers to catch up to resume publishing."
#define FD_METRICS_COUNTER_TILE_BACKPRESSURE_COUNT_CVT  (FD_METRICS_CONVERTER_NONE)

#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_OFF  (8UL)
#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_NAME "tile_regime_duration_nanos"
#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_TYPE (FD_METRICS_TYPE_COUNTER)
#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_DESC "Mutually exclusive and exhaustive duration of time the tile spent in each of the regimes."
#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_CVT  (FD_METRICS_CONVERTER_NONE)
#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_CNT  (8UL)

#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_CAUGHT_UP_HOUSEKEEPING_OFF (8UL)
#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_PROCESSING_HOUSEKEEPING_OFF (9UL)
#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_BACKPRESSURE_HOUSEKEEPING_OFF (10UL)
#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_CAUGHT_UP_PREFRAG_OFF (11UL)
#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_PROCESSING_PREFRAG_OFF (12UL)
#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_BACKPRESSURE_PREFRAG_OFF (13UL)
#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_CAUGHT_UP_POSTFRAG_OFF (14UL)
#define FD_METRICS_COUNTER_TILE_REGIME_DURATION_NANOS_PROCESSING_POSTFRAG_OFF (15UL)


#define FD_METRICS_ALL_TOTAL (16UL)
extern const fd_metrics_meta_t FD_METRICS_ALL[FD_METRICS_ALL_TOTAL];

#define FD_METRICS_ALL_LINK_IN_TOTAL (8UL)
extern const fd_metrics_meta_t FD_METRICS_ALL_LINK_IN[FD_METRICS_ALL_LINK_IN_TOTAL];

#define FD_METRICS_ALL_LINK_OUT_TOTAL (1UL)
extern const fd_metrics_meta_t FD_METRICS_ALL_LINK_OUT[FD_METRICS_ALL_LINK_OUT_TOTAL];

#define FD_METRICS_TOTAL_SZ (8UL*229UL)

#define FD_METRICS_TILE_KIND_CNT 15
extern const char * FD_METRICS_TILE_KIND_NAMES[FD_METRICS_TILE_KIND_CNT];
extern const ulong FD_METRICS_TILE_KIND_SIZES[FD_METRICS_TILE_KIND_CNT];
extern const fd_metrics_meta_t * FD_METRICS_TILE_KIND_METRICS[FD_METRICS_TILE_KIND_CNT];
