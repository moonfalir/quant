// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2019, NetApp, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>

#include <ev.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "frame.h"


// #define DEBUG_BUFFERS ///< Set to log buffer use details.
// #define DEBUG_EXTRA   ///< Set to log various extra details.
// #define DEBUG_STREAMS ///< Set to log stream scheduling details.
// #define DEBUG_TIMERS  ///< Set to log timer details.

#define DATA_OFFSET 48 ///< Offsets of stream frame payload data we TX.

#define MSECS_PER_SEC 1000    ///< Milliseconds per second.
#define USECS_PER_SEC 1000000 ///< Microseconds per second.

#define CID_LEN_MIN 4   ///< Minimum CID length allowed by spec.
#define CID_LEN_MAX 18  ///< Maximum CID length allowed by spec.
#define SCID_LEN_CLNT 4 ///< Default client source CID length.
#define SCID_LEN_SERV 8 ///< Default server source CID length.
#define SRT_LEN 16      ///< Stateless reset token length allowed by spec.


// Maximum reordering in packets before packet threshold loss detection
// considers a packet lost. The RECOMMENDED value is 3.
#define kPacketThreshold 3

// Maximum reordering in time before time threshold loss detection considers a
// packet lost. Specified as an RTT multiplier. The RECOMMENDED value is 9/8.
#define kTimeThreshold 1.125

// Timer granularity. This is a system-dependent value. However, implementations
// SHOULD use a value no smaller than 1ms.
#define kGranularity 0.001

// The RTT used before an RTT sample is taken. The RECOMMENDED value is 100ms.
#define kInitialRtt 0.5

/// The sender's maximum payload size. Does not include UDP or IP overhead. The
/// max packet size is used for calculating initial and minimum congestion
/// windows.
#define kMaxDatagramSize 1200

/// Default limit on the initial amount of outstanding data in flight, in bytes.
/// Taken from [RFC6928]. The RECOMMENDED value is the minimum of 10 *
/// kMaxDatagramSize and max(2* kMaxDatagramSize, 14720)).
#define kInitialWindow                                                         \
    MIN(10 * kMaxDatagramSize, MAX(2 * kMaxDatagramSize, 14720))

/// Minimum congestion window in bytes.
#define kMinimumWindow (2 * kMaxDatagramSize)

/// Reduction in congestion window when a new loss event is detected.
#define kLossReductionDivisor 2 // kLossReductionFactor

/// Number of consecutive PTOs after which network is considered to be
/// experiencing persistent congestion. The RECOMMENDED value for
/// kPersistentCongestionThreshold is 3, which is equivalent to having two TLPs
/// before an RTO in TCP.
#define kPersistentCongestionThreshold 3


#define NRM "\x1B[0m" ///< ANSI escape sequence: reset all to normal
#define BLD "\x1B[1m" ///< ANSI escape sequence: bold
// #define DIM "\x1B[2m"   ///< ANSI escape sequence: dim
// #define ULN "\x1B[3m"   ///< ANSI escape sequence: underline
// #define BLN "\x1B[5m"   ///< ANSI escape sequence: blink
#define REV "\x1B[7m" ///< ANSI escape sequence: reverse
// #define HID "\x1B[8m"   ///< ANSI escape sequence: hidden
// #define BLK "\x1B[30m"  ///< ANSI escape sequence: black
#define RED "\x1B[31m" ///< ANSI escape sequence: red
#define GRN "\x1B[32m" ///< ANSI escape sequence: green
#define YEL "\x1B[33m" ///< ANSI escape sequence: yellow
#define BLU "\x1B[34m" ///< ANSI escape sequence: blue
#define MAG "\x1B[35m" ///< ANSI escape sequence: magenta
#define CYN "\x1B[36m" ///< ANSI escape sequence: cyan
// #define WHT "\x1B[37m"  ///< ANSI escape sequence: white

#define FMT_PNR_IN BLU "%" PRIu64 NRM
#define FMT_PNR_OUT GRN "%" PRIu64 NRM
#define FMT_SID BLD YEL "%" PRId64 NRM


struct cid {
    splay_entry(cid) node_seq;
    uint64_t seq; ///< Connection ID sequence number
    /// XXX len must precede id for cid_cmp() over both to work
    uint8_t len; ///< Connection ID length
    /// XXX id must precede srt for rand_bytes() over both to work
    uint8_t id[CID_LEN_MAX]; ///< Connection ID
    uint8_t srt[SRT_LEN];    ///< Stateless Reset Token
    uint8_t retired : 1;     ///< Did we retire this CID?
    uint8_t has_srt : 1;     ///< Is the SRT field valid?
    uint8_t : 6;
    uint8_t _unused[4];
};


struct pkt_hdr {
    uint64_t nr;      ///< Packet number.
    uint16_t len;     ///< Content of length field in long header.
    uint16_t hdr_len; ///< Length of entire QUIC header.
    uint32_t vers;    ///< QUIC version in long header.
    struct cid dcid;  ///< Destination CID.
    struct cid scid;  ///< Source CID.
    uint8_t flags;    ///< First (raw) byte of packet.
    uint8_t type;     ///< Parsed packet type.
    uint8_t _unused[6];
    // we do not store any token of LH packets in the metadata anymore
};


/// Packet meta-data information associated with w_iov buffers
struct pkt_meta {
    // XXX need to potentially change pm_cpy() below if fields are reordered
    splay_entry(pkt_meta) off_node;
    sl_entry(pkt_meta) rtx_next;
    sl_head(pm_sl, pkt_meta) rtx; ///< List of pkt_meta structs of previous TXs.

    // pm_cpy(true) starts copying from here:
    struct q_stream * stream;   ///< Stream this data was written on.
    uint64_t stream_off;        ///< Stream data offset.
    uint16_t stream_header_pos; ///< Offset of stream frame header.
    uint16_t stream_data_start; ///< Offset of first byte of stream frame data.
    uint16_t stream_data_len;   ///< Length of last stream frame data.

    uint16_t ack_block_pos; ///< Offset of first ACK block (for TX'ed pkt).
    uint64_t lg_acked; ///< "Largest Acknowledged" in ACK block (for TX'ed pkt).
    uint64_t ack_block_cnt; ///< "ACK Block Count" in ACK block (for TX'ed pkt).

    int64_t max_stream_data_sid;  ///< MAX_STREAM_DATA sid, if sent.
    uint64_t max_stream_data;     ///< MAX_STREAM_DATA limit, if sent.
    uint64_t max_data;            ///< MAX_DATA limit, if sent.
    int64_t max_streams_bidi;     ///< MAX_STREAM_ID bidir limit, if sent.
    int64_t max_streams_uni;      ///< MAX_STREAM_ID unidir limit, if sent.
    uint64_t stream_data_blocked; ///< STREAM_DATA_BLOCKED value, if sent.
    uint64_t data_blocked;        ///< DATA_BLOCKED value, if sent.
    uint64_t min_cid_seq; ///< Smallest NEW_CONNECTION_ID seq in pkt, if sent.

    struct frames frames; ///< Frames present in pkt.

    // pm_cpy(false) starts copying from here:
    ev_tstamp tx_t;       ///< Transmission timestamp; only set on TX.
    struct pn_space * pn; ///< Packet number space.
    struct pkt_hdr hdr;   ///< Parsed packet header.

    uint16_t udp_len;          ///< Length of protected UDP packet at TX/RX.
    uint8_t has_rtx : 1;       ///< Does the w_iov hold truncated data?
    uint8_t is_reset : 1;      ///< This packet is a stateless reset.
    uint8_t is_fin : 1;        ///< This packet has a stream FIN bit.
    uint8_t in_flight : 1;     ///< Does this pkt count towards in_flight?
    uint8_t ack_eliciting : 1; ///< Is this packet ACK-eliciting?

    uint8_t acked : 1; ///< Was this packet ACKed?
    uint8_t lost : 1;  ///< Have we marked this packet as lost?
    uint8_t txed : 1;  ///< Did we TX this pkt?

    uint8_t _unused[5];
};


extern struct pkt_meta * pkt_meta;
extern struct ev_loop * loop;
extern struct q_conn_sl accept_queue;

/// The versions of QUIC supported by this implementation
extern const uint32_t ok_vers[];
extern const uint8_t ok_vers_len;

typedef void (*func_ptr)(void);
extern func_ptr api_func;
extern void *api_conn, *api_strm;

extern void __attribute__((nonnull)) alloc_off(struct w_engine * const w,
                                               struct w_iov_sq * const q,
                                               const uint32_t len,
                                               const uint16_t off);

extern void __attribute__((nonnull))
free_iov(struct w_iov * const v, struct pkt_meta * const m);


extern struct w_iov * __attribute__((nonnull))
alloc_iov(struct w_engine * const w,
          const uint16_t len,
          const uint16_t off,
          struct pkt_meta ** const m);


extern struct w_iov * __attribute__((nonnull(1)))
w_iov_dup(const struct w_iov * const v,
          struct pkt_meta ** const mdup,
          const uint16_t off);


#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
extern int corpus_pkt_dir, corpus_frm_dir;

extern void __attribute__((nonnull))
write_to_corpus(const int dir, const void * const data, const size_t len);
#endif


/// Is flag @p f set in flags variable @p v?
///
/// @param      f     Flag.
/// @param      v     Variable.
///
/// @return     True if set, false otherwise.
///
#define is_set(f, v) (((v) & (f)) == (f))


/// Return the pkt_meta entry for a given w_iov.
///
/// @param      v     Pointer to a w_iov.
///
/// @return     Pointer to the pkt_meta entry for the w_iov.
///
#define meta(v) pkt_meta[w_iov_idx(v)]


/// Return the w_iov index of a given pkt_meta.
///
/// @param      m     Pointer to a pkt_meta entry.
///
/// @return     Index of the struct w_iov the struct pkt_meta holds meta data
///             for.
///
#define pm_idx(m) (uint32_t)((m)-pkt_meta)


#define hex2str(buf, len)                                                      \
    __extension__({                                                            \
        static char _str[2 * 64 + 1] = "0";                                    \
        static const char _hex_str[] = "0123456789abcdef";                     \
        int _j;                                                                \
        for (_j = 0; (unsigned long)_j < (unsigned long)(len) && _j < 64;      \
             _j++) {                                                           \
            _str[_j * 2] =                                                     \
                _hex_str[(((const uint8_t *)(buf))[_j] >> 4) & 0x0f];          \
            _str[_j * 2 + 1] = _hex_str[((const uint8_t *)(buf))[_j] & 0x0f];  \
        }                                                                      \
        if (_j == 64)                                                          \
            _str[_j * 2 - 1] = _str[_j * 2 - 2] = _str[_j * 2 - 3] = '.';      \
        _str[_j * 2] = 0;                                                      \
        _str;                                                                  \
    })


#define has_stream_data(p) (p)->stream_header_pos


#ifndef NDEBUG
#define EV_VERIFY(l) ev_verify(l)
#else
#define EV_VERIFY(l)                                                           \
    do {                                                                       \
    } while (0)
#endif


// see https://stackoverflow.com/a/45600545/2240756
//
#define OVERLOADED_MACRO(M, ...) OVR(M, CNT_ARGS(__VA_ARGS__))(__VA_ARGS__)
#define OVR(macro_name, nargs) OVR_EXPAND(macro_name, nargs)
#define OVR_EXPAND(macro_name, nargs) macro_name##nargs
#define CNT_ARGS(...) ARG_MATCH(__VA_ARGS__, 9, 8, 7, 6, 5, 4, 3, 2, 1)
#define ARG_MATCH(_1, _2, _3, _4, _5, _6, _7, _8, _9, N, ...) N


#define maybe_api_return(...)                                                  \
    __extension__(OVERLOADED_MACRO(maybe_api_return, __VA_ARGS__))


#ifdef DEBUG_EXTRA
#define DEBUG_EXTRA_warn warn
#else
#define DEBUG_EXTRA_warn(...)
#endif


/// If current API function and argument match @p func and @p arg - and @p strm
/// if it is non-zero - exit the event loop.
///
/// @param      func  The API function to potentially return to.
/// @param      conn  The connection to check API activity on.
/// @param      strm  The stream to check API activity on.
///
/// @return     True if the event loop was exited.
///
#define maybe_api_return3(func, conn, strm)                                    \
    __extension__({                                                            \
        EV_VERIFY(loop);                                                       \
        if (unlikely(api_func == (func_ptr)(&(func)) && api_conn == (conn) &&  \
                     ((strm) == 0 || api_strm == (strm)))) {                   \
            ev_break(loop, EVBREAK_ALL);                                       \
            DEBUG_EXTRA_warn(DBG, #func "(" #conn ", " #strm                   \
                                        ") done, exiting event loop");         \
            api_func = api_conn = api_strm = 0;                                \
        }                                                                      \
        api_func == 0;                                                         \
    })


/// If current API argument matches @p arg - and @p strm if it is non-zero -
/// exit the event loop (for any active API function).
///
/// @param      conn  The connection to check API activity on.
/// @param      strm  The stream to check API activity on.
///
/// @return     True if the event loop was exited.
///
#define maybe_api_return2(conn, strm)                                          \
    __extension__({                                                            \
        EV_VERIFY(loop);                                                       \
        if (unlikely(api_conn == (conn) &&                                     \
                     ((strm) == 0 || api_strm == (strm)))) {                   \
            ev_break(loop, EVBREAK_ALL);                                       \
            DEBUG_EXTRA_warn(DBG, "<any>(" #conn ", " #strm                    \
                                  ") done, exiting event loop");               \
            api_func = api_conn = api_strm = 0;                                \
        }                                                                      \
        api_func == 0;                                                         \
    })


extern int __attribute__((nonnull))
cids_by_seq_cmp(const struct cid * const a, const struct cid * const b);

extern void __attribute__((nonnull))
cid_cpy(struct cid * const dst, const struct cid * const src);

extern void __attribute__((nonnull)) pm_cpy(struct pkt_meta * const dst,
                                            const struct pkt_meta * const src,
                                            const bool also_frame_info);

extern int __attribute__((nonnull))
ooo_by_off_cmp(const struct pkt_meta * const a,
               const struct pkt_meta * const b);

extern void __attribute__((nonnull))
adj_iov_to_start(struct w_iov * const v, const struct pkt_meta * const m);

extern void __attribute__((nonnull))
adj_iov_to_data(struct w_iov * const v, const struct pkt_meta * const m);


splay_head(ooo_by_off, pkt_meta);

SPLAY_PROTOTYPE(ooo_by_off, pkt_meta, off_node, ooo_by_off_cmp)
