// Copyright (c) 2016-2017, NetApp, Inc.
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

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sanitizer/asan_interface.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <ev.h>
#include <picotls.h>

#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "conn.h"
#include "diet.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"
#include "tls.h"


struct ipnp_splay conns_by_ipnp = splay_initializer(&conns_by_ipnp);
struct cid_splay conns_by_cid = splay_initializer(&conns_by_cid);


uint16_t initial_idle_timeout = kIdleTimeout;
uint64_t initial_max_data = 0xFFFF;        // <= uint32_t for trans param
uint64_t initial_max_stream_data = 0x1000; // <= uint32_t for trans param
uint32_t initial_max_stream_id = 0xFF;


int ipnp_splay_cmp(const struct q_conn * const a, const struct q_conn * const b)
{
    ensure((a->peer.sin_family == AF_INET || a->peer.sin_family == 0) &&
               (b->peer.sin_family == AF_INET || b->peer.sin_family == 0),
           "limited to AF_INET");

    int diff = memcmp(&a->peer.sin_addr.s_addr, &b->peer.sin_addr.s_addr,
                      sizeof(a->peer.sin_addr.s_addr));
    if (likely(diff))
        return diff;

    diff = (a->peer.sin_port > b->peer.sin_port) -
           (a->peer.sin_port < b->peer.sin_port);
    if (likely(diff))
        return diff;

    // include only the client flag in the comparison
    return a->is_clnt - b->is_clnt;
}


int cid_splay_cmp(const struct q_conn * const a, const struct q_conn * const b)
{
    const int diff = (a->id > b->id) - (a->id < b->id);
    if (likely(diff))
        return diff;
    // include only the client flags in the comparison
    return a->is_clnt - b->is_clnt;
}


SPLAY_GENERATE(ipnp_splay, q_conn, node_ipnp, ipnp_splay_cmp)
SPLAY_GENERATE(cid_splay, q_conn, node_cid, cid_splay_cmp)


static bool __attribute__((const)) vers_supported(const uint32_t v)
{
    for (uint8_t i = 0; i < ok_vers_len; i++)
        if (v == ok_vers[i])
            return true;

    // we're out of matching candidates
    warn(INF, "no vers in common with clnt");
    return false;
}


static uint32_t __attribute__((nonnull))
pick_from_server_vers(const void * const buf, const uint16_t len)
{
    const uint16_t pos = pkt_hdr_len(buf, len);
    for (uint8_t i = 0; i < ok_vers_len; i++)
        for (uint8_t j = 0; j < len - pos; j += sizeof(uint32_t)) {
            uint32_t vers = 0;
            uint16_t x = j + pos;
            dec(vers, buf, len, x, 0, "0x%08x");
            warn(DBG, "serv prio %ld = 0x%08x; our prio %u = 0x%08x",
                 j / sizeof(uint32_t), vers, i, ok_vers[i]);
            if (ok_vers[i] == vers)
                return vers;
        }

    // we're out of matching candidates
    warn(INF, "no vers in common with serv");
    return 0;
}


struct q_conn * get_conn_by_ipnp(const struct sockaddr_in * const peer,
                                 const bool is_clnt)
{
    struct q_conn which = {.peer = *peer, .is_clnt = is_clnt};
    return splay_find(ipnp_splay, &conns_by_ipnp, &which);
}


struct q_conn * get_conn_by_cid(const uint64_t id, const bool is_clnt)
{
    struct q_conn which = {.id = id, .is_clnt = is_clnt};
    return splay_find(cid_splay, &conns_by_cid, &which);
}


static void log_sent_pkts(struct q_conn * const c)
{
    char sent_pkts_buf[1024] = "";
    for (struct pkt_meta * p = splay_min(pm_nr_splay, &c->rec.sent_pkts); p;
         p = splay_next(pm_nr_splay, &c->rec.sent_pkts, p)) {
        char tmp[1024] = "";
        snprintf(tmp, sizeof(tmp), "%" PRIu64 " ", p->nr);
        strncat(sent_pkts_buf, tmp,
                sizeof(sent_pkts_buf) - strlen(sent_pkts_buf) - 1);
    }
    warn(CRT, "unacked: %s", sent_pkts_buf);
}


static uint32_t __attribute__((nonnull(1))) tx_stream(struct q_stream * const s,
                                                      const bool rtx,
                                                      const uint32_t limit,
                                                      struct w_iov * const from)
{
    struct q_conn * const c = s->c;

    struct w_iov_sq x = sq_head_initializer(x);
    uint32_t encoded = 0;
    struct w_iov * v = from;
    sq_foreach_from (v, &s->out, next) {
        if (meta(v).is_acked) {
            warn(DBG,
                 "skipping ACKed pkt %" PRIu64 " idx %u on str %u during %s",
                 meta(v).nr, v->idx, s->id, rtx ? "RTX" : "TX");
            continue;
        }

        if (rtx != (meta(v).tx_len > 0)) {
            warn(DBG, "skipping %s pkt %" PRIu64 " idx %u on str %u during %s",
                 meta(v).tx_len ? "already-tx'ed" : "fresh", meta(v).nr, v->idx,
                 s->id, rtx ? "RTX" : "TX");
            continue;
        }

        if (rtx) {
            ensure(meta(v).is_rtxed == false, "cannot RTX an RTX");
            // on RTX, remember orig pkt meta data
            struct w_iov * const r =
                q_alloc_iov(w_engine(c->sock), Q_OFFSET, 0);
            pm_cpy(&meta(r), &meta(v));                  // copy pkt meta data
            memcpy(r->buf, v->buf - Q_OFFSET, Q_OFFSET); // copy pkt data
            meta(r).is_rtxed = true;

            // we reinsert meta(v) with its new pkt nr in on_pkt_sent()
            splay_remove(pm_nr_splay, &c->rec.sent_pkts, &meta(v));
            splay_insert(pm_nr_splay, &c->rec.sent_pkts, &meta(r));
        }

        enc_pkt(s, rtx, v, &x);
        on_pkt_sent(c, v);
        encoded++;

        log_sent_pkts(c);

        if (limit && encoded == limit) {
            warn(NTE, "tx limit %u reached", limit);
            break;
        }
    }

    if (encoded) {
        set_ld_alarm(c);
        // transmit encrypted/protected packets and then free the chain
        if (!c->is_clnt)
            w_connect(c->sock, c->peer.sin_addr.s_addr, c->peer.sin_port);
        w_tx(c->sock, &x);
        w_nic_tx(w_engine(c->sock));
        if (!c->is_clnt)
            w_disconnect(c->sock);
        q_free(w_engine(c->sock), &x);
    }
    return encoded;
}


static uint32_t
tx_other(struct q_stream * const s, const bool rtx, const uint32_t limit)
{
    warn(DBG,
         "other %s on %s conn %" PRIx64 " str %u w/%" PRIu64 " pkt%s in queue",
         rtx ? "RTX" : "TX", conn_type(s->c), s->c->id, s->id, sq_len(&s->out),
         plural(sq_len(&s->out)));

    struct w_iov *v = 0, *last = 0;
    if (!rtx) {
        v = q_alloc_iov(w_engine(s->c->sock), Q_OFFSET, Q_OFFSET);
        last = sq_last(&s->out, w_iov, next);
        sq_insert_tail(&s->out, v, next);
    }

    const bool did_tx = tx_stream(s, rtx, limit, v);

    if (!rtx && !meta(v).is_rtxable) {
        ensure(sq_last(&s->out, w_iov, next) == v, "queue mixed up");
        if (last)
            sq_remove_after(&s->out, last, next);
        else
            sq_remove_head(&s->out, next);
    }

    return did_tx;
}


void tx(struct q_conn * const c, const bool rtx, const uint32_t limit)
{
    bool did_tx = false;
    struct q_stream * s;
    splay_foreach (s, stream, &c->streams) {
        if (s->state != STRM_STAT_CLSD && !sq_empty(&s->out) &&
            sq_len(&s->out) > s->out_ack_cnt) {
            warn(DBG,
                 "data %s on %s conn %" PRIx64 " str %u w/%" PRIu64
                 " pkt%s in queue",
                 rtx ? "RTX" : "TX", conn_type(c), c->id, s->id,
                 sq_len(&s->out), plural(sq_len(&s->out)));
            did_tx |= tx_stream(s, rtx, limit, 0);
        } else if (((s->state == STRM_STAT_HCLO ||
                     s->state == STRM_STAT_CLSD) &&
                    !s->fin_sent) ||
                   s->open_win)
            did_tx |= tx_other(s, rtx, limit);
    }

    if (did_tx == false) {
        // need to ACK w/o any stream data to piggyback on, so abuse stream 0
        s = get_stream(c, 0);
        ensure(s, "no stream 0");
        tx_other(s, rtx, limit);
    }
}


void tx_w(struct ev_loop * const l __attribute__((unused)),
          ev_async * const w,
          int e __attribute__((unused)))
{
    tx(w->data, false, 0);
}


static void __attribute__((nonnull))
update_cid(struct q_conn * const c, const uint64_t cid)
{
    splay_remove(cid_splay, &conns_by_cid, c);
    c->id = cid;
    splay_insert(cid_splay, &conns_by_cid, c);
}


static void __attribute__((nonnull))
update_ipnp(struct q_conn * const c, const struct sockaddr_in * const peer)
{
    splay_remove(ipnp_splay, &conns_by_ipnp, c);
    c->peer = *peer;
    splay_insert(ipnp_splay, &conns_by_ipnp, c);
}


static void __attribute__((nonnull)) process_pkt(struct q_conn * const c,
                                                 struct w_iov * const v,
                                                 const uint16_t prot_len)
{
    const uint8_t flags = pkt_flags(v->buf);

    switch (c->state) {
    case CONN_STAT_IDLE:
    case CONN_STAT_VERS_REJ: {
        // validate minimum packet size
        if (v->len + prot_len < MIN_INI_LEN) {
            warn(ERR, "initial %u-byte pkt too short (< %u)", v->len + prot_len,
                 MIN_INI_LEN);
#ifndef NDEBUG
            if (util_dlevel == DBG)
                hexdump(v->buf, v->len);
#endif
            q_free_iov(w_engine(c->sock), v);
            return;
        }

        ensure(is_set(F_LONG_HDR, flags), "have a long header");

        // respond to the version negotiation packet
        c->vers = pkt_vers(v->buf, v->len);
        c->needs_tx = true;
        diet_insert(&c->recv, meta(v).nr);
        if (c->vers_initial == 0)
            c->vers_initial = c->vers;
        if (vers_supported(c->vers) && !is_force_neg_vers(c->vers)) {
            warn(INF, "supporting clnt-requested vers 0x%08x", c->vers);

            // this is a new connection; server picks a new random cid
            uint64_t cid;
            tls_ctx.random_bytes(&cid, sizeof(cid));
            warn(NTE, "picked new cid %" PRIx64 " for %s conn %" PRIx64, cid,
                 conn_type(c), c->id);
            update_cid(c, cid);
            init_tls(c);
            dec_frames(c, v);

        } else {
            c->state = CONN_STAT_VERS_REJ;
            warn(WRN,
                 "%s conn %" PRIx64
                 " clnt-requested vers 0x%08x not supported ",
                 conn_type(c), c->id, c->vers);
        }
        break;
    }

    case CONN_STAT_VERS_SENT: {
        if (is_set(F_LH_TYPE_VNEG, flags)) {
            // XXX this doesn't work, since we're flushing CH state on retry
            // ensure(find_sent_pkt(c, meta(v).nr), "did not send pkt %" PRIu64,
            //        meta(v).nr);

            const uint32_t vers = pkt_vers(v->buf, v->len);
            if (c->vers != vers) {
                warn(NTE,
                     "ignoring vers neg response for 0x%08x "
                     "since we're trying 0x%08x",
                     vers, c->vers);
                break;
            }

            warn(INF, "serv didn't like our vers 0x%08x", vers);
            ensure(vers_supported(vers), "vers 0x%08x not one of ours", vers);

            if (c->vers_initial == 0)
                c->vers_initial = c->vers;
            c->vers = pick_from_server_vers(v->buf, v->len);
            if (c->vers)
                warn(INF, "retrying with vers 0x%08x", c->vers);
            else
                die("no vers in common with serv");

            // retransmit the ClientHello
            init_tls(c);
            // free the previous ClientHello
            struct pkt_meta *ch, *nxt;
            for (ch = splay_min(pm_nr_splay, &c->rec.sent_pkts); ch; ch = nxt) {
                nxt = splay_next(pm_nr_splay, &c->rec.sent_pkts, ch);
                c->rec.in_flight -= ch->tx_len;
                splay_remove(pm_nr_splay, &c->rec.sent_pkts, ch);
            }
            struct q_stream * s = get_stream(c, 0);
            q_free(w_engine(c->sock), &s->out);
            s->out_off = 0;
            tls_handshake(s);
            c->needs_tx = true;

        } else {
            warn(INF, "serv accepted vers 0x%08x", c->vers);
            diet_insert(&c->recv, meta(v).nr);
            c->state = CONN_STAT_VERS_OK;
            dec_frames(c, v);
        }
        break;
    }

    case CONN_STAT_VERS_OK: {
        // pass any further data received on stream 0 to TLS and check
        // whether that completes the client handshake
        if (!is_set(F_LONG_HDR, flags) || pkt_type(flags) >= F_LH_CLNT_CTXT) {
            maybe_api_return(q_accept, c);
            c->state = CONN_STAT_ESTB;
        }
        diet_insert(&c->recv, meta(v).nr);
        dec_frames(c, v);
        break;
    }

    case CONN_STAT_ESTB:
    case CONN_STAT_CLSD:
        diet_insert(&c->recv, meta(v).nr);
        dec_frames(c, v);
        break;

    default:
        die("TODO: state %u", c->state);
    }
}


void rx(struct ev_loop * const l,
        ev_io * const rx_w,
        int e __attribute__((unused)))
{
    // read from NIC
    struct w_sock * const ws = rx_w->data;
    struct w_engine * const w = w_engine(ws);
    w_nic_rx(w, -1);
    struct w_iov_sq i = sq_head_initializer(i);
    sl_head(, q_conn) crx = sl_head_initializer();
    w_rx(ws, &i);

    while (!sq_empty(&i)) {
        warn(DBG, "----------------------------------------------------------");
        struct w_iov * const v = sq_first(&i);
        ASAN_UNPOISON_MEMORY_REGION(&meta(v), sizeof(meta(v)));
        sq_remove_head(&i, next);
        if (v->len > MAX_PKT_LEN)
            warn(WRN, "received %u-byte pkt (> %u max)", v->len, MAX_PKT_LEN);
        const uint16_t hdr_len = pkt_hdr_len(v->buf, v->len);
        if (v->len < hdr_len) {
            warn(ERR, "%u-byte pkt < %u-byte hdr; ignoring", v->len, hdr_len);
#ifndef NDEBUG
            if (util_dlevel == DBG)
                hexdump(v->buf, v->len);
#endif
            q_free_iov(w, v);
            continue;
        }

        const uint8_t flags = pkt_flags(v->buf);
        const bool is_clnt = w_connected(ws);
        uint64_t cid = 0;
        struct q_conn * c = 0;

        if (is_set(F_LONG_HDR, flags) || is_set(F_SH_CID, flags)) {
            cid = pkt_cid(v->buf, v->len);
            c = get_conn_by_cid(cid, is_clnt);
        }

        if (c == 0) {
            const struct sockaddr_in peer = {.sin_family = AF_INET,
                                             .sin_port = v->port,
                                             .sin_addr = {.s_addr = v->ip}};
            if (is_set(F_LONG_HDR, flags)) {
                if (is_clnt) {
                    // server may have picked a new cid
                    c = get_conn_by_ipnp(&peer, is_clnt);
                    warn(DBG, "got new cid %" PRIx64 " for %s conn %" PRIx64,
                         cid, conn_type(c), c->id);
                    update_cid(c, cid);
                } else {
                    warn(CRT, "new serv conn from %s:%u",
                         inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
                    const struct sockaddr_in none = {0};
                    c = get_conn_by_ipnp(&none, is_clnt);
                    if (c == 0) {
                        // TODO: maintain accept queue
                        warn(CRT, "app is not in q_accept(), ignoring");
                        q_free_iov(w, v);
                        continue;
                    }
                    update_ipnp(c, &peer);
                    update_cid(c, cid);
                    init_cleartext_prot(c);
                    new_stream(c, 0);
                }

            } else
                c = get_conn_by_ipnp(&peer, is_clnt);
        }
        ensure(c, "managed to find conn");

        meta(v).nr = pkt_nr(v->buf, v->len, c);
        uint16_t prot_len = 0;
        if (is_set(F_LONG_HDR, flags) && pkt_type(flags) == F_LH_TYPE_VNEG)
            // version negotiation responses do not carry protection
            prot_len = UINT16_MAX;
        else {
            const uint16_t len = dec_aead(c, v, hdr_len);
            prot_len = len != 0 ? v->len - len : 0;
        }

        if (prot_len == 0) {
            warn(ERR, "AEAD decrypt error; ignoring pkt");
#ifndef NDEBUG
            if (util_dlevel == DBG)
                hexdump(v->buf, v->len);
#endif
            q_free_iov(w, v);
            continue;
        }

        // remember that we had a RX event on this connection
        if (!c->had_rx) {
            c->had_rx = true;
            sl_insert_head(&crx, c, next);
        }

        warn(NTE,
             "rx pkt %" PRIu64 " (len %u, idx %u, type 0x%02x = " bitstring_fmt
             ") on %s conn %" PRIx64,
             meta(v).nr, v->len, v->idx, flags, to_bitstring(flags),
             conn_type(c), cid);
        v->len -= prot_len == UINT16_MAX ? 0 : prot_len;

        process_pkt(c, v, prot_len);
    }

    // for all connections that had RX events, reset idle timeout and check
    // if we need to do a TX
    while (!sl_empty(&crx)) {
        struct q_conn * const c = sl_first(&crx);
        sl_remove_head(&crx, next);

        // reset idle timeout
        ev_timer_again(l, &c->idle_alarm);

        // any stream-0 data will have been consumed by tls_handshake
        struct q_stream * s = get_stream(c, 0);
        q_free(w_engine(c->sock), &s->in);

        // is a TX needed for this connection?
        if (c->needs_tx)
            tx(c, false, 0);

        // clear the helper flags set above
        c->needs_tx = c->had_rx = false;

        log_sent_pkts(c);
    }
}
