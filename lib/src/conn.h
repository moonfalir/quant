// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2020, NetApp, Inc.
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

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifndef NO_MIGRATION
#include <sys/param.h>
#endif

#include <quant/quant.h>
#include <timeout.h>

#include "diet.h"
#include "pn.h"
#include "quic.h"
#include "recovery.h"
#include "tls.h"


KHASH_MAP_INIT_INT64(strms_by_id, struct q_stream *)


static inline int __attribute__((nonnull, no_instrument_function))
cid_cmp(const struct cid * const a, const struct cid * const b)
{
    // if the lengths are different, memcmp will fail on the first byte
    return memcmp(&a->len, &b->len, a->len + sizeof(a->len));
}


#ifndef NO_MIGRATION
static inline khint_t __attribute__((nonnull, no_instrument_function))
hash_cid(const struct cid * const id)
{
    return fnv1a_32(id->id, id->len);
}


static inline int __attribute__((nonnull, no_instrument_function))
kh_cid_cmp(const struct cid * const a, const struct cid * const b)
{
    return cid_cmp(a, b) == 0;
}


KHASH_INIT(conns_by_id, struct cid *, struct q_conn *, 1, hash_cid, kh_cid_cmp)

extern khash_t(conns_by_id) conns_by_id;
#endif


#ifndef NO_SRT_MATCHING
static inline khint_t __attribute__((nonnull, no_instrument_function))
hash_srt(const uint8_t * const srt)
{
    return fnv1a_32(srt, SRT_LEN);
}


static inline int __attribute__((nonnull, no_instrument_function))
kh_srt_cmp(const uint8_t * const a, const uint8_t * const b)
{
    return memcmp(a, b, SRT_LEN) == 0;
}


KHASH_INIT(conns_by_srt, uint8_t *, struct q_conn *, 1, hash_srt, kh_srt_cmp)

extern khash_t(conns_by_srt) conns_by_srt;
#endif


struct pref_addr {
    struct w_sockaddr addr4;
    struct w_sockaddr addr6;
    struct cid cid;
    uint8_t _unused[8];
};


struct transport_params {
    uint_t max_strm_data_uni;
    uint_t max_strm_data_bidi_local;
    uint_t max_strm_data_bidi_remote;
    uint_t max_data;
    uint_t max_strms_uni;
    uint_t max_strms_bidi;
    uint_t max_idle_to;
    uint_t max_ack_del;
    uint_t max_pkt;
    uint_t act_cid_lim;
    uint_t ack_del_exp;
    struct pref_addr pref_addr;
    struct cid orig_cid;
    bool disable_active_migration;
    uint8_t _unused[7];
};


sl_head(q_conn_sl, q_conn);


#define CONN_STATE(k, v) k = v
#define CONN_STATES                                                            \
    CONN_STATE(conn_clsd, 0), CONN_STATE(conn_idle, 1),                        \
        CONN_STATE(conn_opng, 2), CONN_STATE(conn_estb, 3),                    \
        CONN_STATE(conn_qlse, 4), CONN_STATE(conn_clsg, 5),                    \
        CONN_STATE(conn_drng, 6),


/// Define connection states.
/// \dotfile conn-states.dot "Connection state diagram."
typedef enum { CONN_STATES } conn_state_t;

extern const char * const conn_state_str[];

#define MAX_ERR_REASON_LEN 32 // keep < 256, since err_reason_len is uint8_t

#define DEF_ACK_DEL_EXP 3
#define DEF_MAX_ACK_DEL 25 // ms

#ifndef NO_MIGRATION
splay_head(cids_by_seq, cid);

KHASH_INIT(cids_by_id, struct cid *, struct cid *, 1, hash_cid, kh_cid_cmp)
#endif

/// A QUIC connection.
struct q_conn {
    sl_entry(q_conn) node_rx_int;   ///< For maintaining the internal RX queue.
    sl_entry(q_conn) node_rx_ext;   ///< For maintaining the external RX queue.
    sl_entry(q_conn) node_zcid_int; ///< Zero-CID client connections.
#ifndef NO_SERVER
    sl_entry(q_conn) node_aq;   ///< For maintaining the accept queue.
    sl_entry(q_conn) node_embr; ///< For bound but unconnected connections.
#endif
#ifndef NO_MIGRATION
    struct cids_by_seq dcids_by_seq; ///< Destination CID hash by sequence.
    struct cids_by_seq scids_by_seq; ///< Source CID hash by sequence.
    khash_t(cids_by_id) scids_by_id; ///< Source CID hash by ID.
    struct w_sockaddr migr_peer;     ///< Peer's desired migration address.
    struct w_sock * migr_sock;
    struct w_iov_sq migr_txq;
#endif
    struct cid * dcid; ///< Active destination CID.
    struct cid * scid; ///< Active source CID.

    uint32_t holds_sock : 1; ///< Connection manages a warpcore socket.
#ifndef NO_SERVER
    uint32_t is_clnt : 1; ///< We are the client on this connection.
#else
    uint32_t _unused_is_clnt : 1;
#endif
    uint32_t had_rx : 1;           ///< We had an RX event on this connection.
    uint32_t needs_tx : 1;         ///< We have a pending TX on this connection.
    uint32_t tx_max_data : 1;      ///< Sent a MAX_DATA frame.
    uint32_t blocked : 1;          ///< We are receive-window-blocked.
    uint32_t sid_blocked_bidi : 1; ///< We are out of bidi stream IDs.
    uint32_t sid_blocked_uni : 1;  ///< We are out of unidir stream IDs.
    uint32_t tx_max_sid_bidi : 1;  ///< Send MAX_STREAM_ID frame for bidi.
    uint32_t tx_max_sid_uni : 1;   ///< Send MAX_STREAM_ID frame for unidir.
    uint32_t try_0rtt : 1;         ///< Try 0-RTT handshake.
    uint32_t did_0rtt : 1;         ///< 0-RTT handshake succeeded;
    uint32_t tx_path_resp : 1;     ///< Send PATH_RESPONSE.
#ifndef NO_MIGRATION
    uint32_t tx_path_chlg : 1;  ///< Send PATH_CHALLENGE.
    uint32_t tx_retire_cid : 1; ///< Send RETIRE_CONNECTION_ID.
    uint32_t do_migration : 1;  ///< Perform a CID migration when possible.
    uint32_t tx_ncid : 1;       ///< Send NEW_CONNECTION_ID.
#else
    uint32_t _unused_tx_path_chlg : 1;
    uint32_t _unused_tx_retire_cid : 1;
    uint32_t _unused_do_migration : 1;
    uint32_t _unused_tx_ncid : 1;
#endif
    uint32_t have_new_data : 1; ///< New stream data was enqueued.
    uint32_t in_c_ready : 1;    ///< Connection is listed in c_ready.
#ifndef NO_SERVER
    uint32_t tx_rtry : 1;      ///< We need to send a RETRY.
    uint32_t needs_accept : 1; ///< Need to call q_accept() for connection.
#else
    uint32_t _unused_tx_rtry : 1;
    uint32_t _unused_needs_accept : 1;
#endif
    uint32_t key_flips_enabled : 1; ///< Are TLS key updates enabled?
    uint32_t do_key_flip : 1;       ///< Perform a TLS key update.
    uint32_t spin_enabled : 1;      ///< Is the spinbit enabled?
    uint32_t spin : 1;              ///< Spin value to set on next packet sent.
    uint32_t no_wnd : 1;            ///< TX is stalled by lack of window.
    uint32_t do_qr_test : 1;        ///< Perform quantum-readiness test.
    uint32_t tx_hshk_done : 1;      ///< Send HANDSHAKE_DONE.
    uint32_t in_c_zcid : 1;
    uint32_t tx_new_tok : 1; ///< Send NEW_TOKEN.
    uint32_t : 2;

    conn_state_t state; ///< State of the connection.

    struct w_engine * w; ///< Underlying warpcore engine.

    struct timeout tx_w; ///< TX watcher.

    uint32_t vers;         ///< QUIC version in use for this connection.
    uint32_t vers_initial; ///< QUIC version first negotiated.

    struct pn_space pns[pn_data + 1];

    struct timeout idle_alarm;
    struct timeout closing_alarm;
    struct timeout key_flip_alarm;
    struct timeout ack_alarm;

    struct w_sockaddr peer; ///< Address of our peer.

    struct q_stream * cstrms[ep_data + 1]; ///< Crypto "streams".
    khash_t(strms_by_id) strms_by_id;      ///< Regular streams.
    struct diet clsd_strms;
    sl_head(q_stream_head, q_stream) need_ctrl;

    struct w_sock * sock; ///< File descriptor (socket) for the connection.

    timeout_t tls_key_update_frequency;

    struct transport_params tp_mine; ///< Local transport parameters.
    struct transport_params tp_peer; ///< Remote transport parameters.

    struct recovery rec; ///< Loss recovery state.
    struct tls tls;      ///< TLS state.

    dint_t next_sid_bidi; ///< Next unidir stream ID to use on q_rsv_stream().
    dint_t next_sid_uni;  ///< Next bidi stream ID to use on q_rsv_stream().

    uint_t cnt_bidi; ///< Number of unidir stream IDs in use.
    uint_t cnt_uni;  ///< Number of bidi stream IDs in use.

    uint_t in_data_str;  ///< Current inbound aggregate stream data.
    uint_t out_data_str; ///< Current outbound aggregate stream data.

    uint_t path_val_win; ///< Window for path validation.
    uint_t in_data;      ///< Current inbound connection data.
    uint_t out_data;     ///< Current outbound connection data.

    epoch_t min_rx_epoch;

    uint8_t path_chlg_in[PATH_CHLG_LEN];
    uint8_t path_resp_out[PATH_CHLG_LEN];

#ifndef NO_MIGRATION
    uint8_t path_chlg_out[PATH_CHLG_LEN];
    uint8_t path_resp_in[PATH_CHLG_LEN];
#endif

    struct w_sockopt sockopt; ///< Socket options.
    uint_t max_cid_seq_out;

    struct cid odcid; ///< Original destination CID of first Initial.

    struct w_iov_sq txq;

#ifndef NO_QINFO
    struct q_conn_info i;
#endif

    uint_t err_code;
    uint8_t err_frm;
#ifndef NO_ERR_REASONS
    uint8_t err_reason_len;
    char err_reason[MAX_ERR_REASON_LEN];
#else
    uint8_t _unused;
#endif

    uint16_t tok_len;
    uint8_t tok[MAX_TOK_LEN]; // some stacks send ungodly large tokens

    uint32_t tx_limit;
    uint_t pmtud_pkt_nr;
};


#ifndef NO_SERVER
#define is_clnt(c) (c)->is_clnt
extern struct q_conn_sl c_embr;
#else
#define is_clnt(c) 1
#endif


extern struct q_conn_sl c_ready;
extern struct q_conn_sl c_zcid;

#if !defined(NDEBUG) && defined(DEBUG_EXTRA) && !defined(FUZZING)
#define conn_to_state(c, s)                                                    \
    do {                                                                       \
        warn(DBG, "%s%s conn %s state %s -> " RED "%s" NRM,                    \
             (c)->state == (s) ? RED BLD "useless transition: " NRM : "",      \
             conn_type(c), (c)->scid ? cid_str((c)->scid) : "?",               \
             conn_state_str[(c)->state], conn_state_str[(s)]);                 \
        (c)->state = (s);                                                      \
    } while (0)
#else
#define conn_to_state(c, s) (c)->state = (s)
#endif


extern void __attribute__((nonnull)) tx(struct q_conn * const c);


#ifdef NO_ERR_REASONS
#define err_close(c, code, frm, ...) err_close_noreason(c, code, frm)
#endif

extern void __attribute__((nonnull))
#ifndef NO_ERR_REASONS
err_close
#else
err_close_noreason
#endif
    (struct q_conn * const c,
     const uint_t code,
     const uint8_t frm
#ifndef NO_ERR_REASONS
     ,
     const char * const fmt,
     ...
#endif
    );

extern void __attribute__((nonnull)) enter_closing(struct q_conn * const c);

extern struct q_conn * new_conn(struct w_engine * const w,
                                const uint16_t addr_idx,
                                const struct cid * const dcid,
                                const struct cid * const scid,
                                const struct w_sockaddr * const peer,
                                const char * const peer_name,
                                const uint16_t port,
                                const struct q_conn_conf * const conf);

extern void __attribute__((nonnull)) free_conn(struct q_conn * const c);

extern void __attribute__((nonnull))
add_scid(struct q_conn * const c, struct cid * const id);

extern void __attribute__((nonnull))
add_dcid(struct q_conn * const c, const struct cid * const id);

extern void __attribute__((nonnull))
do_conn_fc(struct q_conn * const c, const uint16_t len);

extern void __attribute__((nonnull))
free_scid(struct q_conn * const c, struct cid * const id);

extern void __attribute__((nonnull))
free_dcid(struct q_conn * const c, struct cid * const id);

extern void __attribute__((nonnull(1)))
update_conf(struct q_conn * const c, const struct q_conn_conf * const conf);

#ifndef NO_SRT_MATCHING
extern struct q_conn * __attribute__((nonnull))
get_conn_by_srt(uint8_t * const srt);

extern void __attribute__((nonnull))
conns_by_srt_ins(struct q_conn * const c, uint8_t * const srt);
#endif

extern void __attribute__((nonnull)) rx(struct w_sock * const ws);

extern void __attribute__((nonnull))
conn_info_populate(struct q_conn * const c);

extern void __attribute__((nonnull)) use_next_dcid(struct q_conn * const c);

extern void __attribute__((nonnull))
restart_idle_alarm(struct q_conn * const c);

#ifdef FUZZING
extern void __attribute__((nonnull)) rx_pkts(struct w_iov_sq * const x,
                                             struct q_conn_sl * const crx,
                                             const struct w_sock * const ws);
#endif

static inline struct pn_space * __attribute__((nonnull, no_instrument_function))
pn_for_epoch(struct q_conn * const c, const epoch_t e)
{
    switch (e) {
    case ep_init:
        return &c->pns[pn_init];
    case ep_hshk:
        return &c->pns[pn_hshk];
    case ep_0rtt:
    case ep_data:
        return &c->pns[pn_data];
    }
    die("unhandled epoch %u", e);
    return 0;
}


static inline int __attribute__((nonnull, no_instrument_function))
cids_by_seq_cmp(const struct cid * const a, const struct cid * const b)
{
    return (a->seq > b->seq) - (a->seq < b->seq);
}

#ifndef NO_MIGRATION
SPLAY_PROTOTYPE(cids_by_seq, cid, node_seq, cids_by_seq_cmp)
#endif

#ifndef NO_OOO_0RTT
struct ooo_0rtt {
    splay_entry(ooo_0rtt) node;
    struct cid cid;   ///< CID of 0-RTT pkt
    struct w_iov * v; ///< the buffer containing the 0-RTT pkt
};


extern splay_head(ooo_0rtt_by_cid, ooo_0rtt) ooo_0rtt_by_cid;


static inline int __attribute__((nonnull, no_instrument_function))
ooo_0rtt_by_cid_cmp(const struct ooo_0rtt * const a,
                    const struct ooo_0rtt * const b)
{
    return cid_cmp(&a->cid, &b->cid);
}


SPLAY_PROTOTYPE(ooo_0rtt_by_cid, ooo_0rtt, node, ooo_0rtt_by_cid_cmp)
#endif

static inline __attribute__((nonnull, no_instrument_function)) const char *
conn_type(const struct q_conn * const c
#ifdef NO_SERVER
          __attribute__((unused))
#endif
)
{
    return is_clnt(c) ? "clnt" : "serv";
}


static inline bool __attribute__((nonnull, no_instrument_function))
has_pval_wnd(const struct q_conn * const c, const uint16_t len)
{
    if (unlikely(c->out_data + len >= c->path_val_win)) {
        warn(DBG, "%s conn %s path val lim reached: %" PRIu " + %u >= %" PRIu,
             conn_type(c), cid_str(c->scid), c->out_data, len, c->path_val_win);
        return false;
    }

    return true;
}


static inline bool __attribute__((nonnull, no_instrument_function))
has_wnd(const struct q_conn * const c, const uint16_t len)
{
    if (unlikely(c->blocked)) {
        warn(DBG, "%s conn %s is blocked", conn_type(c), cid_str(c->scid));
        return false;
    }

    if (unlikely(c->rec.cur.in_flight + len >= c->rec.cur.cwnd)) {
        warn(DBG,
             "%s conn %s cwnd lim reached: in_flight %" PRIu " + %u >= %" PRIu,
             conn_type(c), cid_str(c->scid), c->rec.cur.in_flight, len,
             c->rec.cur.cwnd);
        return false;
    }

    return is_clnt(c) ? true : has_pval_wnd(c, len);
}


static inline bool __attribute__((no_instrument_function,
#ifndef NO_MIGRATION
                                  nonnull
#else
                                  const
#endif
                                  )) needs_more_ncids(struct q_conn * const c
#ifdef NO_MIGRATION
                                                      __attribute__((unused))
#endif
)
{
#ifndef NO_MIGRATION
    const struct cid * const max_scid =
        splay_max(cids_by_seq, &c->scids_by_seq);
    return splay_count(&c->scids_by_seq) <
               MIN(c->tp_peer.act_cid_lim, c->tp_mine.act_cid_lim) ||
           (max_scid && c->max_cid_seq_out < max_scid->seq);
#else
    return false;
#endif
}
