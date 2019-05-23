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

#include <inttypes.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

// IWYU pragma: no_include <picotls/../picotls.h>

#include <picotls.h> // IWYU pragma: keep
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "bitset.h"
#include "conn.h"
#include "diet.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "pn.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"
#include "tls.h"


#define MAX_PKT_NR_LEN 4 ///< Maximum packet number length allowed by spec.


#ifndef NDEBUG
// local version of cid2str that is just hex2str (omits the seq)
#define c2s(i) hex2str((i)->id, (i)->len)

void log_pkt(const char * const dir,
             const struct w_iov * const v,
             const struct sockaddr * const addr,
             const struct cid * const odcid,
             const uint8_t * const tok,
             const uint16_t tok_len)
{
    if (util_dlevel < NTE)
        return;

    char ip[NI_MAXHOST];
    char port[NI_MAXSERV];
    ensure(getnameinfo(addr, sizeof(*addr), ip, sizeof(ip), port, sizeof(port),
                       NI_NUMERICHOST | NI_NUMERICSERV) == 0,
           "getnameinfo");

    const struct pkt_meta * const m = &meta(v);
    const char * const pts = pkt_type_str(m->hdr.flags, &m->hdr.vers);
    if (*dir == 'R') {
        if (is_lh(m->hdr.flags)) {
            if (m->hdr.vers == 0)
                twarn(NTE,
                      BLD BLU "RX" NRM " from=%s:%s len=%u 0x%02x=" BLU
                              "%s " NRM "vers=0x%08x dcid=%s scid=%s",
                      ip, port, v->len, m->hdr.flags, pts, m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid));
            else if (m->hdr.type == LH_RTRY)
                twarn(NTE,
                      BLD BLU "RX" NRM " from=%s:%s len=%u 0x%02x=" BLU
                              "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s odcid=%s tok=%s",
                      ip, port, v->len, m->hdr.flags, pts, m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid), c2s(odcid),
                      hex2str(tok, tok_len));
            else if (m->hdr.type == LH_INIT)
                twarn(NTE,
                      BLD BLU
                      "RX" NRM " from=%s:%s len=%u 0x%02x=" BLU "%s " NRM
                      "vers=0x%08x dcid=%s scid=%s tok=%s len=%u nr=" BLU
                      "%" PRIu64,
                      ip, port, v->len, m->hdr.flags, pts, m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid),
                      hex2str(tok, tok_len), m->hdr.len, m->hdr.nr);
            else
                twarn(NTE,
                      BLD BLU
                      "RX" NRM " from=%s:%s len=%u 0x%02x=" BLU "%s " NRM
                      "vers=0x%08x dcid=%s scid=%s len=%u nr=" BLU "%" PRIu64,
                      ip, port, v->len, m->hdr.flags, pts, m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid), m->hdr.len,
                      m->hdr.nr);
        } else
            twarn(NTE,
                  BLD BLU "RX" NRM " from=%s:%s len=%u 0x%02x=" BLU "%s " NRM
                          "kyph=%u spin=%u dcid=%s nr=" BLU "%" PRIu64,
                  ip, port, v->len, m->hdr.flags, pts,
                  is_set(SH_KYPH, m->hdr.flags), is_set(SH_SPIN, m->hdr.flags),
                  c2s(&m->hdr.dcid), m->hdr.nr);

    } else {
        // on TX, v->len is not yet final/correct, so don't print it
        if (is_lh(m->hdr.flags)) {
            if (m->hdr.vers == 0)
                twarn(NTE,
                      BLD GRN "TX" NRM " to=%s:%s 0x%02x=" GRN "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s",
                      ip, port, m->hdr.flags, pts, m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid));
            else if (m->hdr.type == LH_RTRY)
                twarn(NTE,
                      BLD GRN "TX" NRM " to=%s:%s 0x%02x=" GRN "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s odcid=%s tok=%s",
                      ip, port, m->hdr.flags, pts, m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid), c2s(odcid),
                      hex2str(tok, tok_len));
            else if (m->hdr.type == LH_INIT)
                twarn(NTE,
                      BLD GRN
                      "TX" NRM " to=%s:%s 0x%02x=" GRN "%s " NRM
                      "vers=0x%08x dcid=%s scid=%s tok=%s len=%u nr=" GRN
                      "%" PRIu64,
                      ip, port, m->hdr.flags, pts, m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid),
                      hex2str(tok, tok_len), m->hdr.len, m->hdr.nr);
            else
                twarn(NTE,
                      BLD GRN "TX" NRM " to=%s:%s 0x%02x=" GRN "%s " NRM
                              "vers=0x%08x dcid=%s scid=%s len=%u nr=" GRN
                              "%" PRIu64,
                      ip, port, m->hdr.flags, pts, m->hdr.vers,
                      c2s(&m->hdr.dcid), c2s(&m->hdr.scid), m->hdr.len,
                      m->hdr.nr);
        } else
            twarn(NTE,
                  BLD GRN "TX" NRM " to=%s:%s 0x%02x=" GRN "%s " NRM
                          "kyph=%u spin=%u dcid=%s nr=" GRN "%" PRIu64,
                  ip, port, m->hdr.flags, pts, is_set(SH_KYPH, m->hdr.flags),
                  is_set(SH_SPIN, m->hdr.flags), c2s(&m->hdr.dcid), m->hdr.nr);
    }
}
#endif


static bool __attribute__((const))
can_coalesce_pkt_types(const uint8_t a, const uint8_t b)
{
    return (a == LH_INIT && (b == LH_0RTT || b == LH_HSHK)) ||
           (a == LH_HSHK && b == SH) || (a == LH_0RTT && b == LH_HSHK);
}


void coalesce(struct w_iov_sq * const q)
{
    struct w_iov * v = sq_first(q);
    while (v) {
        struct w_iov * next = sq_next(v, next);
        struct w_iov * prev = v;
        while (next) {
            struct w_iov * const next_next = sq_next(next, next);
            // do we have space? do the packet types make sense to coalesce?
            if (v->len + next->len <= kMaxDatagramSize &&
                can_coalesce_pkt_types(pkt_type(*v->buf),
                                       pkt_type(*next->buf))) {
                // we can coalesce
                warn(DBG, "coalescing %u-byte %s pkt behind %u-byte %s pkt",
                     next->len, pkt_type_str(*next->buf, next->buf + 1), v->len,
                     pkt_type_str(*v->buf, v->buf + 1));
                memcpy(v->buf + v->len, next->buf, next->len);
                v->len += next->len;
                sq_remove_after(q, prev, next);

#ifdef DEBUG_BUFFERS
                warn(DBG, "w_free_iov idx %u (avail %" PRIu64 ")",
                     w_iov_idx(next), sq_len(&next->w->iov) + 1);
#endif
                w_free_iov(next);
            } else
                prev = next;
            next = next_next;
        }
        v = sq_next(v, next);
    }
}


static inline uint8_t __attribute__((const))
needed_pkt_nr_len(const uint64_t lg_acked, const uint64_t n)
{
    const uint64_t d =
        (n - (unlikely(lg_acked == UINT64_MAX) ? 0 : lg_acked)) * 2;
    if (d <= UINT8_MAX)
        return 1;
    if (d <= UINT16_MAX)
        return 2;
    if (d <= (UINT32_MAX >> 8))
        return 3;
    return 4;
}


void enc_lh_cids(uint8_t ** pos,
                 const uint8_t * const end,
                 struct pkt_meta * const m,
                 const struct cid * const dcid,
                 const struct cid * const scid)
{
    cid_cpy(&m->hdr.dcid, dcid);
    if (scid)
        cid_cpy(&m->hdr.scid, scid);
    const uint8_t cil =
        (uint8_t)((m->hdr.dcid.len ? m->hdr.dcid.len - 3 : 0) << 4) |
        (uint8_t)(m->hdr.scid.len ? m->hdr.scid.len - 3 : 0);
    enc1(pos, end, cil);
    if (m->hdr.dcid.len)
        encb(pos, end, m->hdr.dcid.id, m->hdr.dcid.len);
    if (m->hdr.scid.len)
        encb(pos, end, m->hdr.scid.id, m->hdr.scid.len);
}


static bool __attribute__((nonnull)) can_enc(uint8_t ** const pos,
                                             const uint8_t * const end,
                                             const struct pkt_meta * const m,
                                             const uint8_t type,
                                             const bool one_per_pkt)
{
    const bool has_space = *pos + max_frame_len(type) <= end;
    return (one_per_pkt && has_frame(m->frames, type)) == false && has_space;
}


static void __attribute__((nonnull)) enc_other_frames(uint8_t ** pos,
                                                      const uint8_t * const end,
                                                      struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;

    // encode connection control frames
    if (!c->is_clnt && c->tok_len && can_enc(pos, end, m, FRM_TOK, true)) {
        enc_new_token_frame(pos, end, m);
        c->tok_len = 0;
    }

    if (c->tx_path_resp && can_enc(pos, end, m, FRM_PRP, true)) {
        enc_path_response_frame(pos, end, m);
        c->tx_path_resp = false;
    }

    if (c->tx_retire_cid && can_enc(pos, end, m, FRM_RTR, true)) {
        struct cid * rcid = splay_min(cids_by_seq, &c->dcids_by_seq);
        while (rcid && rcid->seq < c->dcid->seq) {
            struct cid * const next =
                splay_next(cids_by_seq, &c->dcids_by_seq, rcid);
            if (rcid->retired) {
                enc_retire_cid_frame(pos, end, m, rcid);
                free_dcid(c, rcid);
            }
            rcid = next;
        }
    }

    if (c->tx_path_chlg && can_enc(pos, end, m, FRM_PCL, true))
        enc_path_challenge_frame(pos, end, m);

    while (c->tx_ncid && can_enc(pos, end, m, FRM_CID, false)) {
        enc_new_cid_frame(pos, end, m);
        c->tx_ncid = needs_more_ncids(c);
    }

    if (c->blocked && can_enc(pos, end, m, FRM_CDB, true))
        enc_data_blocked_frame(pos, end, m);

    if (c->tx_max_data && can_enc(pos, end, m, FRM_MCD, true))
        enc_max_data_frame(pos, end, m);

    if (c->sid_blocked_bidi && can_enc(pos, end, m, FRM_SBB, true))
        enc_streams_blocked_frame(pos, end, m, true);

    if (c->sid_blocked_uni && can_enc(pos, end, m, FRM_SBU, true))
        enc_streams_blocked_frame(pos, end, m, false);

    if (c->tx_max_sid_bidi && can_enc(pos, end, m, FRM_MSB, true))
        enc_max_streams_frame(pos, end, m, true);

    if (c->tx_max_sid_uni && can_enc(pos, end, m, FRM_MSU, true))
        enc_max_streams_frame(pos, end, m, false);

    while (!sl_empty(&c->need_ctrl)) {
        // XXX this assumes we can encode all the ctrl frames
        struct q_stream * const s = sl_first(&c->need_ctrl);
        sl_remove_head(&c->need_ctrl, node_ctrl);
        s->in_ctrl = false;
        // encode stream control frames
        if (s->blocked && can_enc(pos, end, m, FRM_SDB, true))
            enc_stream_data_blocked_frame(pos, end, m, s);
        if (s->tx_max_stream_data && can_enc(pos, end, m, FRM_MSD, true))
            enc_max_stream_data_frame(pos, end, m, s);
    }
}


bool enc_pkt(struct q_stream * const s,
             const bool rtx,
             const bool enc_data,
             const bool tx_ack_eliciting,
             struct w_iov * const v,
             struct pkt_meta * const m)
{

    if (likely(enc_data))
        // prepend the header by adjusting the buffer offset
        adj_iov_to_start(v, m);

    struct q_conn * const c = s->c;
    uint8_t * len_pos = 0;

    const epoch_t epoch = strm_epoch(s);
    struct pn_space * const pn = m->pn = pn_for_epoch(c, epoch);

    if (unlikely(c->tx_rtry))
        m->hdr.nr = 0;
    else if (unlikely(pn->lg_sent == UINT64_MAX))
        // next pkt nr
        m->hdr.nr = pn->lg_sent = 0;
    else
        m->hdr.nr = ++pn->lg_sent;

    switch (epoch) {
    case ep_init:
        m->hdr.type = unlikely(c->tx_rtry) ? LH_RTRY : LH_INIT;
        m->hdr.flags =
            LH | m->hdr.type | (unlikely(c->tx_rtry) ? c->odcid.len - 3 : 0);
        break;
    case ep_0rtt:
        if (c->is_clnt) {
            m->hdr.type = LH_0RTT;
            m->hdr.flags = LH | m->hdr.type;
        } else
            m->hdr.type = m->hdr.flags = SH;
        break;
    case ep_hshk:
        m->hdr.type = LH_HSHK;
        m->hdr.flags = LH | m->hdr.type;
        break;
    case ep_data:
        m->hdr.type = m->hdr.flags = SH;
        m->hdr.flags |= pn->data.out_kyph ? SH_KYPH : 0;
        if (c->spin_enabled && c->spin)
            m->hdr.flags |= SH_SPIN;
        break;
    }

    ensure(m->hdr.nr < (1ULL << 62) - 1, "packet number overflow");

    const uint8_t pnl = needed_pkt_nr_len(pn->lg_acked, m->hdr.nr);
    m->hdr.flags |= (pnl - 1);

    uint8_t * pos = v->buf;
    const uint8_t * const end =
        v->buf + (enc_data ? m->stream_data_start : v->len);
    enc1(&pos, end, m->hdr.flags);

    if (unlikely(is_lh(m->hdr.flags))) {
        m->hdr.vers = c->vers;
        enc4(&pos, end, m->hdr.vers);
        enc_lh_cids(&pos, end, m, c->dcid, c->scid);

        if (unlikely(m->hdr.type == LH_RTRY))
            encb(&pos, end, c->odcid.id, c->odcid.len);

        if (m->hdr.type == LH_INIT)
            encv(&pos, end, c->is_clnt ? c->tok_len : 0);

        if (((c->is_clnt && m->hdr.type == LH_INIT) ||
             m->hdr.type == LH_RTRY) &&
            c->tok_len)
            encb(&pos, end, c->tok, c->tok_len);

        if (m->hdr.type != LH_RTRY) {
            // leave space for length field (2 bytes is enough)
            len_pos = pos;
            pos += 2;
        }

    } else {
        cid_cpy(&m->hdr.dcid, c->dcid);
        encb(&pos, end, m->hdr.dcid.id, m->hdr.dcid.len);
    }

    uint8_t * pkt_nr_pos = 0;
    if (likely(m->hdr.type != LH_RTRY)) {
        pkt_nr_pos = pos;
        switch ((pnl - 1) & HEAD_PNRL_MASK) {
        case 0:
            enc1(&pos, end, m->hdr.nr & UINT64_C(0xff));
            break;
        case 1:
            enc2(&pos, end, m->hdr.nr & UINT64_C(0xffff));
            break;
        case 2:
            enc3(&pos, end, m->hdr.nr & UINT64_C(0xffffff));
            break;
        case 3:
            enc4(&pos, end, m->hdr.nr & UINT64_C(0xffffffff));
            break;
        }
    }

    m->hdr.hdr_len = (uint16_t)(pos - v->buf);
    v->addr = unlikely(c->tx_path_chlg) ? c->migr_peer : c->peer;

    log_pkt("TX", v, (struct sockaddr *)&v->addr,
            m->hdr.type == LH_RTRY ? &c->odcid : 0, c->tok, c->tok_len);

    // sanity check
    if (unlikely(m->hdr.hdr_len >=
                 DATA_OFFSET + (is_lh(m->hdr.flags) ? c->tok_len + 16 : 0))) {
        warn(ERR, "pkt header %u >= offset %u", m->hdr.hdr_len,
             DATA_OFFSET + (is_lh(m->hdr.flags) ? c->tok_len + 16 : 0));
        return false;
    }

    if (unlikely(m->hdr.type == LH_RTRY))
        goto tx;

    if (needs_ack(pn) != no_ack)
        enc_ack_frame(&pos, v->buf, end, m, pn);

    if (unlikely(c->state == conn_clsg))
        enc_close_frame(&pos, end, m);
    else if (epoch == ep_data || (!c->is_clnt && epoch == ep_0rtt))
        // TODO calc stream hdr len and subtract
        enc_other_frames(&pos, end, m);

    if (unlikely(rtx)) {
        ensure(has_stream_data(m), "is rtxable");

        // this is a RTX, pad out until beginning of stream header
        enc_padding_frame(&pos, end, m,
                          m->stream_header_pos - (uint16_t)(pos - v->buf));
        pos = v->buf + m->stream_data_start + m->stream_data_len;
        log_stream_or_crypto_frame(true, m, v->buf[m->stream_header_pos], s->id,
                                   false, "");

    } else if (likely(enc_data)) {
        // this is a fresh data/crypto or pure stream FIN packet
        // pad out until stream_data_start and add a stream frame header
        enc_padding_frame(&pos, end, m,
                          m->stream_data_start - (uint16_t)(pos - v->buf));
        enc_stream_or_crypto_frame(&pos, end, m, v, s, s->id >= 0);
    }

    if (unlikely((pos - v->buf) < MAX_PKT_LEN - AEAD_LEN && (enc_data || rtx) &&
                 (epoch == ep_data || (!c->is_clnt && epoch == ep_0rtt))))
        // we can try to stick some more frames in after the stream frame
        enc_other_frames(&pos, v->buf + MAX_PKT_LEN - AEAD_LEN, m);

    if (c->is_clnt && enc_data) {
        if (unlikely(c->try_0rtt == false && m->hdr.type == LH_INIT)) {
            const uint8_t * const max_end = v->buf + MIN_INI_LEN - AEAD_LEN;
            enc_padding_frame(&pos, max_end, m, (uint16_t)(max_end - pos));
        }
        if (unlikely(c->try_0rtt == true && m->hdr.type == LH_0RTT &&
                     s->id >= 0)) {
            // if we pad the first 0-RTT pkt, peek at txq to get the CI length
            const uint8_t * const max_end =
                v->buf + MIN_INI_LEN - AEAD_LEN -
                (sq_first(&c->txq) ? sq_first(&c->txq)->len : 0);
            enc_padding_frame(&pos, max_end, m, (uint16_t)(max_end - pos));
        }
    }

    m->ack_eliciting = is_ack_eliciting(&m->frames);
    if (unlikely(tx_ack_eliciting) && m->ack_eliciting == false &&
        m->hdr.type == SH) {
        enc_ping_frame(&pos, end, m);
        m->ack_eliciting = true;
    }

    ensure((pos - v->buf) > m->hdr.hdr_len, "would have sent %s pkt w/o frames",
           pkt_type_str(m->hdr.flags, &m->hdr.vers));

tx:;
    // make sure we have enough frame bytes for the header protection sample
    const uint16_t pnp_dist = (uint16_t)(pos - pkt_nr_pos);
    if (unlikely(pnp_dist < 4))
        enc_padding_frame(&pos, end, m, 4 - pnp_dist);

    // for LH pkts, now encode the length
    m->hdr.len = (uint16_t)(pos - pkt_nr_pos) + AEAD_LEN;
    if (unlikely(len_pos))
        encvl(&len_pos, len_pos + 2, m->hdr.len, 2);

    v->len = (uint16_t)(pos - v->buf);

    // alloc directly from warpcore for crypto TX - no need for metadata alloc
    struct w_iov * const xv = w_alloc_iov(c->w, 0, 0);
    ensure(xv, "w_alloc_iov failed");
#ifdef DEBUG_BUFFERS
    warn(DBG, "w_alloc_iov idx %u (avail %" PRIu64 ") len %u", w_iov_idx(xv),
         sq_len(&c->w->iov), xv->len);
#endif

    if (unlikely(m->hdr.type == LH_RTRY)) {
        memcpy(xv->buf, v->buf, v->len); // copy data
        xv->len = v->len;
    } else {
        const uint16_t ret =
            enc_aead(v, m, xv, (uint16_t)(pkt_nr_pos - v->buf));
        if (unlikely(ret == 0)) {
            adj_iov_to_start(v, m);
            return false;
        }
    }

    if (!c->is_clnt)
        xv->addr = v->addr;

    // track the flags manually, since warpcore sets them on the xv and it'd
    // require another loop to copy them over
    xv->flags = v->flags |= likely(c->sockopt.enable_ecn) ? IPTOS_ECN_ECT0 : 0;

    sq_insert_tail(&c->txq, xv, next);
    m->udp_len = xv->len;
    c->out_data += m->udp_len;

    if (unlikely(m->hdr.type == LH_INIT && c->is_clnt && m->stream_data_len))
        // adjust v->len to exclude the post-stream padding for CI
        v->len = m->stream_data_start + m->stream_data_len;

    if (likely(enc_data)) {
        adj_iov_to_data(v, m);
        // XXX not clear if changing the len before calling on_pkt_sent is
        // ok
        v->len = m->stream_data_len;
    }

    if (unlikely(rtx))
        // we did an RTX and this is no longer lost
        m->lost = false;

    on_pkt_sent(m);
    bit_or(FRM_MAX, &pn->tx_frames, &m->frames);

    if (c->is_clnt) {
        if (is_lh(m->hdr.flags) == false)
            maybe_flip_keys(c, true);
        if (unlikely(m->hdr.type == LH_HSHK && c->cstreams[ep_init]))
            abandon_pn(&c->pns[ep_init]);
    }

    return true;
}


#define dec1_chk(val, pos, end)                                                \
    do {                                                                       \
        if (unlikely(dec1((val), (pos), (end)) == false))                      \
            return false;                                                      \
    } while (0)


#define dec2_chk(val, pos, end)                                                \
    do {                                                                       \
        if (unlikely(dec2((val), (pos), (end)) == false))                      \
            return false;                                                      \
    } while (0)


#define dec3_chk(val, pos, end)                                                \
    do {                                                                       \
        if (unlikely(dec3((val), (pos), (end)) == false))                      \
            return false;                                                      \
    } while (0)


#define dec4_chk(val, pos, end)                                                \
    do {                                                                       \
        if (unlikely(dec4((val), (pos), (end)) == false))                      \
            return false;                                                      \
    } while (0)


#define decv_chk(val, pos, end)                                                \
    do {                                                                       \
        if (unlikely(decv((val), (pos), (end)) == false))                      \
            return false;                                                      \
    } while (0)


#define decb_chk(val, pos, end, len)                                           \
    do {                                                                       \
        if (unlikely(decb((val), (pos), (end), (len)) == false))               \
            return false;                                                      \
    } while (0)


bool dec_pkt_hdr_beginning(struct w_iov * const xv,
                           struct w_iov * const v,
                           struct pkt_meta * const m,
                           const bool is_clnt,
                           struct cid * const odcid,
                           uint8_t * const tok,
                           uint16_t * const tok_len,
                           const uint8_t dcid_len)

{
    const uint8_t * pos = xv->buf;
    const uint8_t * const end = xv->buf + xv->len;

    m->udp_len = xv->len;

    dec1_chk(&m->hdr.flags, &pos, end);
    m->hdr.type = pkt_type(m->hdr.flags);

    if (unlikely(is_lh(m->hdr.flags))) {
        dec4_chk(&m->hdr.vers, &pos, end);
        dec1_chk(&m->hdr.dcid.len, &pos, end);

        m->hdr.scid.len = m->hdr.dcid.len;
        m->hdr.dcid.len >>= 4;
        m->hdr.scid.len &= 0x0f;

        if (m->hdr.dcid.len) {
            m->hdr.dcid.len += 3;
            decb_chk(m->hdr.dcid.id, &pos, end, m->hdr.dcid.len);
        }

        if (m->hdr.scid.len) {
            m->hdr.scid.len += 3;
            decb_chk(m->hdr.scid.id, &pos, end, m->hdr.scid.len);
        }

        // if this is a CI, the dcid len must be >= 8 bytes
        if (is_clnt == false &&
            unlikely(m->hdr.type == LH_INIT && m->hdr.dcid.len < 8)) {
            warn(DBG, "dcid len %u too short", m->hdr.dcid.len);
            return false;
        }

        if (m->hdr.vers == 0) {
            // version negotiation packet - copy raw
            memcpy(v->buf, xv->buf, xv->len);
            v->len = xv->len;
            goto done;
        }

        if (m->hdr.type == LH_RTRY) {
            // decode odcid
            odcid->len = (m->hdr.flags & 0x0f) + 3;
            decb_chk(odcid->id, &pos, end, odcid->len);
        }

        if (m->hdr.type == LH_INIT) {
            // decode token
            uint64_t tmp = 0;
            decv_chk(&tmp, &pos, end);
            *tok_len = (uint16_t)tmp;
            if (is_clnt && *tok_len) {
                // server initial pkts must have no tokens
                warn(ERR, "tok (len %u) present in serv initial", *tok_len);
                return false;
            }
        } else if (m->hdr.type == LH_RTRY)
            *tok_len = (uint16_t)(end - pos);

        if (*tok_len) {
            if (unlikely(*tok_len >= MAX_TOK_LEN ||
                         *tok_len + m->hdr.hdr_len > xv->len)) {
                // corrupt token len
                warn(DBG, "tok_len %u invalid (max %u)", *tok_len, MAX_TOK_LEN);
                return false;
            }
            decb_chk(tok, &pos, end, *tok_len);
        }

        if (m->hdr.type != LH_RTRY) {
            uint64_t tmp = 0;
            decv_chk(&tmp, &pos, end);
            m->hdr.len = (uint16_t)tmp;
            // sanity check len
            if (unlikely(m->hdr.len + m->hdr.hdr_len > xv->len)) {
                warn(DBG, "len %u invalid", m->hdr.len);
                return false;
            }
        }

    } else {
        // this logic depends on picking a SCID w/known length during handshake
        m->hdr.dcid.len = dcid_len;
        decb_chk(m->hdr.dcid.id, &pos, end, m->hdr.dcid.len);
    }

done:
    m->hdr.hdr_len = (uint16_t)(pos - xv->buf);
    return true;
}


bool xor_hp(struct w_iov * const xv,
            const struct pkt_meta * const m,
            const struct cipher_ctx * const ctx,
            const uint16_t pkt_nr_pos,
            const bool is_enc)
{
    const uint16_t off = pkt_nr_pos + MAX_PKT_NR_LEN;
    const uint16_t len =
        is_lh(m->hdr.flags) ? pkt_nr_pos + m->hdr.len : xv->len;
    if (unlikely(off + AEAD_LEN > len))
        return false;

    ptls_cipher_init(ctx->header_protection, &xv->buf[off]);
    uint8_t mask[MAX_PKT_NR_LEN + 1] = {0};
    ptls_cipher_encrypt(ctx->header_protection, mask, mask, sizeof(mask));

    const uint8_t orig_flags = xv->buf[0];
    xv->buf[0] ^= mask[0] & (unlikely(is_lh(m->hdr.flags)) ? 0x0f : 0x1f);
    const uint8_t pnl = pkt_nr_len(is_enc ? orig_flags : xv->buf[0]);
    for (uint8_t i = 0; i < pnl; i++)
        xv->buf[pkt_nr_pos + i] ^= mask[1 + i];

#ifdef DEBUG_EXTRA
    warn(DBG, "%s HP over [0, %u..%u] w/sample off %u",
         is_enc ? "apply" : "undo", pkt_nr_pos, pkt_nr_pos + pnl - 1, off);
#endif

    return true;
}


static bool undo_hp(struct w_iov * const xv,
                    struct pkt_meta * const m,
                    const struct cipher_ctx * const ctx)
{
    // undo HP and update meta; m->hdr.hdr_len holds the offset of the pnr field
    if (unlikely(xor_hp(xv, m, ctx, m->hdr.hdr_len, false) == false))
        return false;

    m->hdr.flags = xv->buf[0];
    m->hdr.type = pkt_type(xv->buf[0]);
    const uint8_t pnl = pkt_nr_len(xv->buf[0]);
    struct pn_space * const pn = pn_for_pkt_type(m->pn->c, m->hdr.type);
    const uint8_t * pnp = xv->buf + m->hdr.hdr_len;

    switch (xv->buf[0] & HEAD_PNRL_MASK) {
    case 0:;
        uint8_t tmp1;
        dec1_chk(&tmp1, &pnp, pnp + pnl);
        m->hdr.nr = tmp1;
        break;
    case 1:;
        uint16_t tmp2;
        dec2_chk(&tmp2, &pnp, pnp + pnl);
        m->hdr.nr = tmp2;
        break;
    case 2:;
        uint32_t tmp34;
        dec3_chk(&tmp34, &pnp, pnp + pnl);
        m->hdr.nr = tmp34;
        break;
    case 3:
        dec4_chk(&tmp34, &pnp, pnp + pnl);
        m->hdr.nr = tmp34;
        break;
    }
    m->hdr.hdr_len += pnl;

    const uint64_t expected_pn = diet_max(&pn->recv) + 1;
    const uint64_t pn_win = UINT64_C(1) << (pnl * 8);
    const uint64_t pn_hwin = pn_win / 2;
    const uint64_t pn_mask = pn_win - 1;

    m->hdr.nr |= (expected_pn & ~pn_mask);
    if (m->hdr.nr + pn_hwin <= expected_pn)
        m->hdr.nr += pn_win;
    else if (m->hdr.nr > expected_pn + pn_hwin && m->hdr.nr > pn_win)
        m->hdr.nr -= pn_win;

    return true;
}


static const struct cipher_ctx * __attribute__((nonnull))
which_cipher_ctx_in(struct q_conn * const c,
                    struct pkt_meta * const m,
                    const bool kyph)
{
    switch (m->hdr.type) {
    case LH_INIT:
    case LH_RTRY:
        m->pn = &c->pns[pn_init];
        return &m->pn->early.in;
    case LH_0RTT:
        m->pn = &c->pns[pn_data];
        return &m->pn->data.in_0rtt;
    case LH_HSHK:
        m->pn = &c->pns[pn_hshk];
        return &m->pn->early.in;
    default:
        m->pn = &c->pns[pn_data];
        return &m->pn->data.in_1rtt[kyph ? is_set(SH_KYPH, m->hdr.flags) : 0];
    }
}


struct q_conn * is_srt(const struct w_iov * const xv, struct pkt_meta * const m)
{
    if ((m->hdr.flags & LH) != HEAD_FIXD || xv->len < 23 + SRT_LEN)
        return 0;

    uint8_t * const srt = &xv->buf[xv->len - SRT_LEN];
    struct q_conn * const c = get_conn_by_srt(srt);

    if (c && c->state != conn_drng) {
        m->is_reset = true;
        warn(DBG, "stateless reset for %s conn %s", conn_type(c),
             cid2str(c->scid));
        conn_to_state(c, conn_drng);
        enter_closing(c);
        return c;
    }
    return 0;
}


bool dec_pkt_hdr_remainder(struct w_iov * const xv,
                           struct w_iov * const v,
                           struct pkt_meta * const m,
                           struct q_conn * const c,
                           struct w_iov_sq * const x,
                           bool * const decoal)
{
    *decoal = false;
    const struct cipher_ctx * ctx = which_cipher_ctx_in(c, m, false);
    if (unlikely(ctx->header_protection == 0))
        return false;

    // we can now undo the packet protection
    if (unlikely(undo_hp(xv, m, ctx) == false))
        return is_srt(xv, m);

    // we can now try and decrypt the packet
    struct pn_space * const pn = &c->pns[pn_data];
    struct pn_data * const pnd = &pn->data;
    if (likely(is_lh(m->hdr.flags) == false) &&
        unlikely(is_set(SH_KYPH, m->hdr.flags) != pnd->in_kyph)) {
        if (pnd->out_kyph == pnd->in_kyph)
            // this is a peer-initiated key phase flip
            flip_keys(c, false);
        else
            // the peer switched to a key phase that we flipped
            pnd->in_kyph = pnd->out_kyph;
    }

    ctx = which_cipher_ctx_in(c, m, true);
    if (unlikely(ctx->aead == 0))
        return is_srt(xv, m);

    const uint16_t pkt_len = is_lh(m->hdr.flags) ? m->hdr.hdr_len + m->hdr.len -
                                                       pkt_nr_len(m->hdr.flags)
                                                 : xv->len;
    const uint16_t ret = dec_aead(xv, v, m, pkt_len, ctx);
    if (unlikely(ret == 0))
        return is_srt(xv, m);

    const uint8_t rsvd_bits =
        m->hdr.flags & (is_lh(m->hdr.flags) ? LH_RSVD_MASK : SH_RSVD_MASK);
    if (unlikely(rsvd_bits)) {
        err_close(c, ERR_PROTOCOL_VIOLATION, 0,
                  "reserved %s bits are 0x%02x (= non-zero)",
                  is_lh(m->hdr.flags) ? "LH" : "SH", rsvd_bits);
        return false;
    }

    if (unlikely(is_lh(m->hdr.flags))) {
        // check for coalesced packet
        if (unlikely(pkt_len < xv->len)) {
            *decoal = true;
            // allocate new w_iov for coalesced packet and copy it over
            struct w_iov * const dup = w_iov_dup(xv, 0, pkt_len);
            // adjust length of first packet
            xv->len = pkt_len;
            // rx() has already removed xv from x, so just insert dup at head
            sq_insert_head(x, dup, next);
            warn(DBG, "split out coalesced %u-byte %s pkt", dup->len,
                 pkt_type_str(*dup->buf, &dup->buf[1]));
        }

    } else {
        // check if a key phase flip has been verified
        const bool v_kyph = is_set(SH_KYPH, m->hdr.flags);
        if (unlikely(v_kyph != pnd->in_kyph))
            pnd->in_kyph = v_kyph;

        if (c->spin_enabled && m->hdr.nr > diet_max(&pn->recv_all))
            // short header, spin the bit
            c->spin = (is_set(SH_SPIN, m->hdr.flags) == !c->is_clnt);
    }

    v->len = xv->len - AEAD_LEN;

    if (!c->is_clnt &&
        unlikely(m->hdr.type == LH_HSHK && c->cstreams[ep_init])) {
        abandon_pn(&c->pns[pn_init]);

        // server can assume path is validated
        warn(DBG, "clnt path validated");
        c->path_val_win = UINT64_MAX;
    }

    // packet protection verified OK
    if (diet_find(&pn_for_pkt_type(c, m->hdr.type)->recv_all, m->hdr.nr))
        return is_srt(xv, m);

    // check if we need to send an immediate ACK
    if (unlikely(diet_empty(&m->pn->recv_all) == false &&
                     m->hdr.nr < diet_max(&m->pn->recv_all) ||
                 (xv->flags & IPTOS_ECN_MASK) == IPTOS_ECN_CE))
        // XXX: this also sends an imm_ack if the reor is "fixed" within a burst
        m->pn->imm_ack = true;

    return true;
}


const char * pkt_type_str(const uint8_t flags, const void * const vers)
{
    if (is_lh(flags)) {
        if (((const uint8_t * const)vers)[0] == 0 &&
            ((const uint8_t * const)vers)[1] == 0 &&
            ((const uint8_t * const)vers)[2] == 0 &&
            ((const uint8_t * const)vers)[3] == 0)
            return "Version Negotiation";
        switch (pkt_type(flags)) {
        case LH_INIT:
            return "Initial";
        case LH_RTRY:
            return "Retry";
        case LH_HSHK:
            return "Handshake";
        case LH_0RTT:
            return "0-RTT Protected";
        }
    } else if (pkt_type(flags) == SH)
        return "Short";
    return RED "Unknown" NRM;
}


bool is_lh(const uint8_t flags)
{
    return is_set(HEAD_FORM, flags);
}


uint8_t pkt_type(const uint8_t flags)
{
    return is_lh(flags) ? flags & LH_TYPE_MASK : SH;
}


uint8_t pkt_nr_len(const uint8_t flags)
{
    return (flags & HEAD_PNRL_MASK) + 1;
}


epoch_t epoch_for_pkt_type(const uint8_t type)
{
    switch (type) {
    case LH_INIT:
    case LH_RTRY:
        return ep_init;
    case LH_0RTT:
        return ep_0rtt;
    case LH_HSHK:
        return ep_hshk;
    default:
        return ep_data;
    }
}


struct pn_space * pn_for_pkt_type(struct q_conn * const c, const uint8_t t)
{
    return pn_for_epoch(c, epoch_for_pkt_type(t));
}


bool has_pkt_nr(const uint8_t flags, const uint32_t vers)
{
    return is_lh(flags) == false || (vers && pkt_type(flags) != LH_RTRY);
}
