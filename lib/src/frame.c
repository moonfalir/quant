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
#include <math.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>

// IWYU pragma: no_include <picotls/../picotls.h>

#include <ev.h>
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


// TODO: check error conditions and codes more thoroughly


#define track_frame(m, ft) bit_set(FRM_MAX, (ft), &(m)->frames)

#define err_close_return(c, code, ...)                                         \
    do {                                                                       \
        err_close((c), (code), __VA_ARGS__);                                   \
        return false;                                                          \
    } while (0)


#define dec1_chk(val, pos, end, c, type)                                       \
    do {                                                                       \
        if (unlikely(dec1((val), (pos), (end)) == false))                      \
            err_close_return((c), ERR_FRAME_ENC, (type), "dec1 %s in %s:%u",   \
                             #val, __FILE__, __LINE__);                        \
    } while (0)


#define dec2_chk(val, pos, end, c, type)                                       \
    do {                                                                       \
        if (unlikely(dec2((val), (pos), (end)) == false))                      \
            err_close_return((c), ERR_FRAME_ENC, (type), "dec4 %s in %s:%u",   \
                             #val, __FILE__, __LINE__);                        \
    } while (0)


#define dec8_chk(val, pos, end, c, type)                                       \
    do {                                                                       \
        if (unlikely(dec8((val), (pos), (end)) == false))                      \
            err_close_return((c), ERR_FRAME_ENC, (type), "dec4 %s in %s:%u",   \
                             #val, __FILE__, __LINE__);                        \
    } while (0)


#define decv_chk(val, pos, end, c, type)                                       \
    do {                                                                       \
        if (unlikely(decv((val), (pos), (end)) == false))                      \
            err_close_return((c), ERR_FRAME_ENC, (type), "decv %s in %s:%u",   \
                             #val, __FILE__, __LINE__);                        \
    } while (0)

#define decb_chk(val, pos, end, len, c, type)                                  \
    do {                                                                       \
        if (unlikely(decb((val), (pos), (end), (len)) == false))               \
            err_close_return((c), ERR_FRAME_ENC, (type), "decb %s in %s:%u",   \
                             #val, __FILE__, __LINE__);                        \
    } while (0)


#ifndef NDEBUG
void log_stream_or_crypto_frame(const bool rtx,
                                const struct pkt_meta * const m,
                                const uint8_t fl,
                                const int64_t sid,
                                const bool in,
                                const char * kind)
{
    if (util_dlevel < INF)
        return;

    const struct q_conn * const c = m->pn->c;
    const struct q_stream * const s = m->stream;
    if (kind == 0)
        kind = BLD RED "invalid" NRM;

    if (sid >= 0)
        warn(INF,
             "%sSTREAM" NRM " 0x%02x=%s%s%s%s%s id=" FMT_SID "/%" PRIu64
             " off=%" PRIu64 "/%" PRIu64 " len=%u coff=%" PRIu64 "/%" PRIu64
             " %s%s%s%s",
             in ? FRAM_IN : FRAM_OUT, fl, is_set(F_STREAM_FIN, fl) ? "FIN" : "",
             is_set(F_STREAM_FIN, fl) &&
                     (is_set(F_STREAM_LEN, fl) || is_set(F_STREAM_OFF, fl))
                 ? "|"
                 : "",
             is_set(F_STREAM_LEN, fl) ? "LEN" : "",
             is_set(F_STREAM_LEN, fl) && is_set(F_STREAM_OFF, fl) ? "|" : "",
             is_set(F_STREAM_OFF, fl) ? "OFF" : "", sid, max_sid(sid, c),
             m->stream_off,
             in ? (s ? s->in_data_max : 0) : (s ? s->out_data_max : 0),
             m->stream_data_len, in ? c->in_data_str : c->out_data_str,
             in ? c->tp_in.max_data : c->tp_out.max_data,
             rtx ? REV BLD GRN "[RTX]" NRM " " : "", in ? "[" : "", kind,
             in ? "]" : "");
    else
        warn(INF, "%sCRYPTO" NRM " off=%" PRIu64 " len=%u %s%s%s%s",
             in ? FRAM_IN : FRAM_OUT, m->stream_off, m->stream_data_len,
             rtx ? REV BLD GRN "[RTX]" NRM " " : "", in ? "[" : "", kind,
             in ? "]" : "");
}
#endif


static void __attribute__((nonnull)) trim_frame(struct pkt_meta * const p)
{
    const uint64_t diff = p->stream->in_data_off - p->stream_off;
    p->stream_off += diff;
    p->stream_data_start += diff;
    p->stream_data_len -= diff;
}


static struct q_stream * __attribute__((nonnull))
get_and_validate_strm(struct q_conn * const c,
                      const int64_t sid,
                      const uint8_t type,
                      const bool ok_when_writer)
{
    if (is_uni(sid) && unlikely(is_srv_ini(sid) ==
                                (ok_when_writer ? c->is_clnt : !c->is_clnt)))
        err_close(c, ERR_STREAM_STATE, type,
                  "got frame 0x%02x for uni sid %" PRId64 " but am %s", type,
                  sid, conn_type(c));
    else {
        struct q_stream * s = get_stream(c, sid);
        if (unlikely(s == 0)) {
            if (unlikely(diet_find(&c->closed_streams, (uint64_t)sid)))
                warn(NTE,
                     "ignoring 0x%02x frame for closed strm " FMT_SID
                     " on %s conn %s",
                     type, sid, conn_type(c), cid2str(c->scid));
            else if (type == FRM_MSD || type == FRM_STP)
                // we are supposed to open closed streams on RX of these frames
                s = new_stream(c, sid);
            else
                err_close(c, ERR_STREAM_STATE, type, "unknown strm %" PRId64,
                          sid);
        }
        return s;
    }
    return 0;
}


static bool __attribute__((nonnull))
dec_stream_or_crypto_frame(const uint8_t type,
                           const uint8_t ** pos,
                           const uint8_t * const end,
                           struct pkt_meta * const m,
                           struct w_iov * const v)
{
    struct q_conn * const c = m->pn->c;
    m->stream_header_pos = (uint16_t)(*pos - v->buf) - 1;

    int64_t sid = 0;
    if (unlikely(type == FRM_CRY)) {
        const epoch_t e = epoch_for_pkt_type(m->hdr.type);
        if (unlikely(c->cstreams[e] == 0))
            err_close_return(c, ERR_STREAM_STATE, type,
                             "epoch %u pkt processing abandoned", e);
        sid = crpt_strm_id(e);
        m->stream = c->cstreams[e];
    } else {
        m->is_fin = is_set(F_STREAM_FIN, type);
        decv_chk((uint64_t *)&sid, pos, end, c, type);
        m->stream = get_stream(c, sid);
    }

    if (is_set(F_STREAM_OFF, type) || unlikely(type == FRM_CRY))
        decv_chk(&m->stream_off, pos, end, c, type);
    else
        m->stream_off = 0;

    uint64_t l = 0;
    if (is_set(F_STREAM_LEN, type) || unlikely(type == FRM_CRY)) {
        decv_chk(&l, pos, end, c, type);
        if (unlikely(*pos + l > end))
            err_close_return(c, ERR_FRAME_ENC, type, "illegal strm len");
    } else
        // stream data extends to end of packet
        l = (uint16_t)(end - *pos);

    const int64_t max = max_sid(sid, c);
    if (unlikely(sid > max)) {
        log_stream_or_crypto_frame(false, m, type, sid, true, 0);
        err_close_return(c, ERR_STREAM_ID, type,
                         "sid %" PRId64 " > max %" PRId64, sid, max);
    }

    m->stream_data_start = (uint16_t)(*pos - v->buf);
    m->stream_data_len = (uint16_t)l;

    // deliver data into stream
    bool ignore = false;
    const char * kind = 0;

    if (unlikely(m->stream_data_len == 0 && !is_set(F_STREAM_FIN, type))) {
        // warn(WRN, "zero-len strm/crypt frame on sid " FMT_SID ", ignoring",
        //      sid);
        ignore = true;
        kind = "ign";
        goto done;
    }

    if (unlikely(m->stream == 0)) {
        if (unlikely(diet_find(&c->closed_streams, (uint64_t)sid))) {
            // warn(NTE,
            //      "ignoring STREAM frame for closed strm " FMT_SID
            //      " on %s conn %s",
            //      sid, conn_type(c), cid2str(c->scid));
            ignore = true;
            kind = "ign";
            goto done;
        }

        if (unlikely(is_srv_ini(sid) != c->is_clnt)) {
            log_stream_or_crypto_frame(false, m, type, sid, true, 0);
            err_close_return(c, ERR_STREAM_STATE, type,
                             "got sid %" PRId64 " but am %s", sid,
                             conn_type(c));
        }

        m->stream = new_stream(c, sid);
    }

    // best case: new in-order data
    if (m->stream->in_data_off >= m->stream_off &&
        m->stream->in_data_off <=
            m->stream_off + m->stream_data_len - (m->stream_data_len ? 1 : 0)) {
        kind = "seq";

        if (unlikely(m->stream->state == strm_hcrm ||
                     m->stream->state == strm_clsd)) {
            warn(NTE,
                 "ignoring STREAM frame for %s strm " FMT_SID " on %s conn %s",
                 strm_state_str[m->stream->state], sid, conn_type(c),
                 cid2str(c->scid));
            ignore = true;
            goto done;
        }

        if (unlikely(m->stream->in_data_off > m->stream_off))
            // already-received data at the beginning of the frame, trim
            trim_frame(m);

        track_bytes_in(m->stream, m->stream_data_len);
        m->stream->in_data_off += m->stream_data_len;
        sq_insert_tail(&m->stream->in, v, next);

        // check if a hole has been filled that lets us dequeue ooo data
        struct pkt_meta * p = splay_min(ooo_by_off, &m->stream->in_ooo);
        while (p) {
            struct pkt_meta * const nxt =
                splay_next(ooo_by_off, &m->stream->in_ooo, p);

            if (unlikely(p->stream_off + p->stream_data_len <
                         m->stream->in_data_off)) {
                // right edge of p < left edge of stream
                warn(WRN, "drop stale frame [%" PRIu64 "..%" PRIu64 "]",
                     p->stream_off, p->stream_off + p->stream_data_len);
                ensure(splay_remove(ooo_by_off, &m->stream->in_ooo, p),
                       "removed");
                p = nxt;
                continue;
            }

            // right edge of p >= left edge of stream
            if (p->stream_off > m->stream->in_data_off)
                // also left edge of p > left edge of stream: still a gap
                break;

            // left edge of p <= left edge of stream: overlap, trim & enqueue
            if (unlikely(p->stream->in_data_off > p->stream_off))
                trim_frame(p);
            sq_insert_tail(&m->stream->in, w_iov(c->w, pm_idx(p)), next);
            m->stream->in_data_off += p->stream_data_len;
            ensure(splay_remove(ooo_by_off, &m->stream->in_ooo, p), "removed");

            // mark ooo crypto data for freeing by rx_crypto()
            if (p->stream->id < 0)
                p->stream = 0;
            p = nxt;
        }

        // check if we have delivered a FIN, and act on it if we did
        struct w_iov * const last = sq_last(&m->stream->in, w_iov, next);
        if (last) {
            const struct pkt_meta * const m_last = &meta(last);
            if (unlikely(v != last))
                adj_iov_to_start(last, m_last);
            if (m_last->is_fin) {
                m->pn->imm_ack = true;
                strm_to_state(m->stream, m->stream->state <= strm_hcrm
                                             ? strm_hcrm
                                             : strm_clsd);
                maybe_api_return(q_readall_stream, c, m->stream);
                if (m->stream->state == strm_clsd)
                    maybe_api_return(q_close_stream, c, m->stream);
            }
            if (unlikely(v != last))
                adj_iov_to_data(last, m_last);
        }

        if (type != FRM_CRY) {
            do_stream_fc(m->stream, 0);
            do_conn_fc(c, 0);
            c->have_new_data = true;
            maybe_api_return(q_read, c, 0);
        }
        goto done;
    }

    // data is a complete duplicate
    if (m->stream_off + m->stream_data_len <= m->stream->in_data_off) {
        kind = RED "dup" NRM;
        ignore = true;
        goto done;
    }

    // data is out of order - check if it overlaps with already stored ooo data
    kind = YEL "ooo" NRM;
    if (unlikely(m->stream->state == strm_hcrm ||
                 m->stream->state == strm_clsd)) {
        warn(NTE, "ignoring STREAM frame for %s strm " FMT_SID " on %s conn %s",
             strm_state_str[m->stream->state], sid, conn_type(c),
             cid2str(c->scid));
        ignore = true;
        kind = "ign";
        goto done;
    }

    struct pkt_meta * p = splay_min(ooo_by_off, &m->stream->in_ooo);
    while (p && p->stream_off + p->stream_data_len - 1 < m->stream_off)
        p = splay_next(ooo_by_off, &m->stream->in_ooo, p);

    // right edge of p >= left edge of v
    if (p && p->stream_off <= m->stream_off + m->stream_data_len - 1) {
        // left edge of p <= right edge of v
        warn(ERR,
             "[%" PRIu64 "..%" PRIu64
             "] have existing overlapping ooo data [%" PRIu64 "..%" PRIu64 "]",
             m->stream_off, m->stream_off + m->stream_data_len, p->stream_off,
             p->stream_off + p->stream_data_len - 1);
        ignore = true;
        kind = "ign";
        goto done;
    }

    // this ooo data doesn't overlap with anything
    track_bytes_in(m->stream, m->stream_data_len);
    ensure(splay_insert(ooo_by_off, &m->stream->in_ooo, m) == 0, "inserted");

done:
    log_stream_or_crypto_frame(false, m, type, sid, true, kind);

    if (m->stream && type != FRM_CRY &&
        m->stream_off + m->stream_data_len > m->stream->in_data_max)
        err_close_return(c, ERR_FLOW_CONTROL, type,
                         "stream %" PRIu64 " off %" PRIu64
                         " >= in_data_max %" PRIu64,
                         m->stream->id, m->stream_off + m->stream_data_len - 1,
                         m->stream->in_data_max);

    if (ignore)
        // this indicates to callers that the w_iov was not placed in a stream
        m->stream = 0;

    *pos = &v->buf[m->stream_data_start + m->stream_data_len];
    return true;
}


#ifndef NDEBUG
static uint64_t __attribute__((const))
shorten_ack_nr(const uint64_t ack, const uint64_t diff)
{
    if (unlikely(diff == 0))
        return ack;

    uint64_t div = (uint64_t)(powl(ceill(log10l(diff)), 10));
    div = MAX(10, div);
    while ((ack - diff) % div + diff >= div)
        div *= 10;
    return ack % div;
}
#endif


static bool __attribute__((nonnull))
dec_ack_frame(const uint8_t type,
              const uint8_t ** pos,
              const uint8_t * const end,
              const struct pkt_meta * const m)
{
    struct pn_space * const pn = m->pn;
    struct q_conn * const c = pn->c;

    uint64_t lg_ack = 0;
    decv_chk(&lg_ack, pos, end, c, type);

    uint64_t ack_delay_raw = 0;
    decv_chk(&ack_delay_raw, pos, end, c, type);

    // TODO: figure out a better way to handle huge ACK delays
    if (unlikely(ack_delay_raw > UINT32_MAX))
        err_close_return(c, ERR_FRAME_ENC, type, "ACK delay raw %" PRIu64,
                         ack_delay_raw);

    // handshake pkts always use the default ACK delay exponent
    const uint64_t ade = m->hdr.type == LH_INIT || m->hdr.type == LH_HSHK
                             ? DEF_ACK_DEL_EXP
                             : c->tp_in.ack_del_exp;
    const uint64_t ack_delay = ack_delay_raw * (1 << ade);

    uint64_t num_blocks = 0;
    decv_chk(&num_blocks, pos, end, c, type);

    const struct ival * const cum_ack_ival = diet_min_ival(&pn->acked);
    const uint64_t cum_ack = cum_ack_ival ? cum_ack_ival->hi : UINT64_MAX;

    uint64_t lg_ack_in_block = lg_ack;
    ev_tstamp lg_acked_tx_t = 0;
    bool got_new_ack = false;
    for (uint64_t n = num_blocks + 1; n > 0; n--) {
        uint64_t gap = 0;
        uint64_t ack_block_len = 0;
        decv_chk(&ack_block_len, pos, end, c, type);

        if (unlikely(ack_block_len > (UINT16_MAX << 4)))
            err_close_return(c, ERR_INTERNAL, type, "ACK block len %" PRIu64,
                             ack_block_len);

        if (unlikely(ack_block_len > lg_ack_in_block))
            err_close_return(c, ERR_FRAME_ENC, type, "ACK block len %" PRIu64,
                             " > lg_ack_in_block %" PRIu64, ack_block_len,
                             lg_ack_in_block);

#ifndef NDEBUG
        if (ack_block_len == 0) {
            if (n == num_blocks + 1)
                warn(INF,
                     FRAM_IN "ACK" NRM " 0x%02x=%s lg=" FMT_PNR_OUT
                             " delay=%" PRIu64 " (%" PRIu64
                             " usec) cnt=%" PRIu64 " block=%" PRIu64
                             " [" FMT_PNR_OUT "]",
                     type, type == FRM_ACE ? "ECN" : "", lg_ack, ack_delay_raw,
                     ack_delay, num_blocks, ack_block_len, lg_ack);
            else
                warn(INF,
                     FRAM_IN "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                             " [" FMT_PNR_OUT "]",
                     gap, ack_block_len, lg_ack_in_block);
        } else {
            if (n == num_blocks + 1)
                warn(INF,
                     FRAM_IN "ACK" NRM " 0x%02x=%s lg=" FMT_PNR_OUT
                             " delay=%" PRIu64 " (%" PRIu64
                             " usec) cnt=%" PRIu64 " block=%" PRIu64
                             " [" FMT_PNR_OUT ".." FMT_PNR_OUT "]",
                     type, type == FRM_ACE ? "ECN" : "", lg_ack, ack_delay_raw,
                     ack_delay, num_blocks, ack_block_len,
                     lg_ack_in_block - ack_block_len,
                     shorten_ack_nr(lg_ack_in_block, ack_block_len));
            else
                warn(INF,
                     FRAM_IN "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                             " [" FMT_PNR_OUT ".." FMT_PNR_OUT "]",
                     gap, ack_block_len, lg_ack_in_block - ack_block_len,
                     shorten_ack_nr(lg_ack_in_block, ack_block_len));
        }
#endif

        uint64_t ack = lg_ack_in_block;
        while (ack_block_len >= lg_ack_in_block - ack) {

            if (likely(cum_ack != UINT64_MAX) && ack <= cum_ack)
                // we can skip the remainder of this block entirely
                goto next_block;

            if (diet_find(&pn->acked, ack) || diet_find(&pn->lost, ack))
                goto skip;

            struct pkt_meta * m_acked;
            struct w_iov * const acked = find_sent_pkt(pn, ack, &m_acked);
            if (unlikely(acked == 0)) {
#ifndef FUZZING
                // this is just way too noisy when fuzzing
                err_close_return(c, ERR_PROTOCOL_VIOLATION, type,
                                 "got ACK for %s pkt " FMT_PNR_OUT
                                 " never sent",
                                 pn_type_str(pn->type), ack);
#endif
                goto skip;
            }

            got_new_ack = true;
            if (unlikely(ack == lg_ack)) {
                // call this only for the largest ACK in the frame
                on_ack_received_1(m_acked, ack_delay);
                lg_acked_tx_t = m_acked->tx_t;
            }

            on_pkt_acked(acked, m_acked);

            // if the ACK'ed pkt was sent with ECT, verify peer and path support
            if (likely(c->sockopt.enable_ecn &&
                       is_set(IPTOS_ECN_ECT0, acked->flags)) &&
                unlikely(type != FRM_ACE)) {
                warn(NTE, "ECN verification failed for %s conn %s",
                     conn_type(c), cid2str(c->scid));
                c->sockopt.enable_ecn = false;
                w_set_sockopt(c->sock, &c->sockopt);
            }

        skip:
            if (likely(ack > 0))
                ack--;
            else
                break;
        }

    next_block:
        if (n > 1) {
            decv_chk(&gap, pos, end, c, type);
            if (unlikely((lg_ack_in_block - ack_block_len) < gap + 2)) {
                warn(DBG,
                     "lg_ack_in_block=%" PRIu64 ", ack_block_len=%" PRIu64
                     ", gap=%" PRIu64,
                     lg_ack_in_block, ack_block_len, -gap);
                err_close_return(c, ERR_PROTOCOL_VIOLATION, type,
                                 "illegal ACK frame");
            }
            lg_ack_in_block = (lg_ack_in_block - ack_block_len) - gap - 2;
        }
    }

    if (type == FRM_ACE) {
        // decode ECN
        uint64_t ect0_cnt = 0;
        uint64_t ect1_cnt = 0;
        uint64_t ce_cnt = 0;
        decv_chk(&ect0_cnt, pos, end, c, type);
        decv_chk(&ect1_cnt, pos, end, c, type);
        decv_chk(&ce_cnt, pos, end, c, type);
        warn(INF,
             FRAM_IN "ECN" NRM " ect0=%s%" PRIu64 NRM " ect1=%s%" PRIu64 NRM
                     " ce=%s%" PRIu64 NRM,
             ect0_cnt ? GRN : NRM, ect0_cnt, ect1_cnt ? GRN : NRM, ect1_cnt,
             ce_cnt ? GRN : NRM, ce_cnt);
        // TODO: add sanity check whether markings make sense

        // ProcessECN
        if (ce_cnt > pn->ce_cnt) {
            pn->ce_cnt = ce_cnt;
            congestion_event(c, lg_acked_tx_t);
        }
    }

    if (got_new_ack)
        on_ack_received_2(pn);

    bit_zero(FRM_MAX, &pn->tx_frames);
    return true;
}


static bool __attribute__((nonnull))
dec_close_frame(const uint8_t type,
                const uint8_t ** pos,
                const uint8_t * const end,
                const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;

    uint16_t err_code;
    dec2_chk(&err_code, pos, end, c, type);

    uint64_t frame_type = 0;
    if (type == FRM_CLQ)
        decv_chk(&frame_type, pos, end, c, type);

    uint64_t reas_len = 0;
    decv_chk(&reas_len, pos, end, c, type);
    if (unlikely(reas_len > (uint64_t)(end - *pos)))
        err_close_return(c, ERR_FRAME_ENC, type, "illegal reason len %u",
                         reas_len);

    char reas_phr[2048]; // XXX
    if (unlikely(reas_len > sizeof(reas_phr)))
        err_close_return(c, ERR_INTERNAL, type, "reason_phr too long %u",
                         reas_len);
    if (reas_len)
        decb_chk((uint8_t *)reas_phr, pos, end, (uint16_t)reas_len, c, type);

    if (type == FRM_CLQ)
        warn(INF,
             FRAM_IN "CONNECTION_CLOSE" NRM " 0x%02x=quic err=%s0x%04x " NRM
                     "frame=0x%" PRIx64 " rlen=%" PRIu64 " reason=%s%.*s" NRM,
             type, err_code ? RED : NRM, err_code, frame_type, reas_len,
             err_code ? RED : NRM, (int)reas_len, reas_phr);
    else
        warn(INF,
             FRAM_IN "CONNECTION_CLOSE" NRM " 0x%02x=app err=%s0x%04x " NRM
                     "rlen=%" PRIu64 " reason=%s%.*s" NRM,
             type, err_code ? RED : NRM, err_code, reas_len,
             err_code ? RED : NRM, (int)reas_len, reas_phr);

    if (c->state == conn_drng || (c->is_clnt && c->state == conn_clsg))
        ev_feed_event(loop, &c->closing_alarm, 0);
    else {
        if (c->state == conn_clsg)
            conn_to_state(c, conn_drng);
        enter_closing(c);
    }

    return true;
}


static bool __attribute__((nonnull))
dec_max_stream_data_frame(const uint8_t ** pos,
                          const uint8_t * const end,
                          const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    int64_t sid = 0;
    decv_chk((uint64_t *)&sid, pos, end, c, FRM_MSD);

    uint64_t max = 0;
    decv_chk(&max, pos, end, c, FRM_MSD);

    warn(INF, FRAM_IN "MAX_STREAM_DATA" NRM " id=" FMT_SID " max=%" PRIu64, sid,
         max);

    struct q_stream * const s = get_and_validate_strm(c, sid, FRM_MSD, true);
    if (unlikely(s == 0))
        return false;

    if (max > s->out_data_max) {
        s->out_data_max = max;
        if (s->blocked) {
            s->blocked = false;
            c->needs_tx = true;
        }
        need_ctrl_update(s);
    } else if (max < s->out_data_max)
        warn(NTE, "MAX_STREAM_DATA %" PRIu64 " < current value %" PRIu64, max,
             s->out_data_max);

    return true;
}


static bool __attribute__((nonnull))
dec_max_streams_frame(const uint8_t type,
                      const uint8_t ** pos,
                      const uint8_t * const end,
                      const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;

    uint64_t max = 0;
    decv_chk(&max, pos, end, c, type);

    warn(INF, FRAM_IN "MAX_STREAMS" NRM " 0x%02x=%s max=%" PRIu64, type,
         type == FRM_MSU ? "uni" : "bi", max);

    uint64_t * const max_streams = type == FRM_MSU
                                       ? &c->tp_out.max_streams_uni
                                       : &c->tp_out.max_streams_bidi;

    if (max > *max_streams) {
        *max_streams = max;
        maybe_api_return(q_rsv_stream, c, 0);
    } else if (max < *max_streams)
        warn(NTE, "RX'ed max_%s_streams %" PRIu64 " < current value %" PRIu64,
             type == FRM_MSU ? "uni" : "bidi", max, *max_streams);

    return true;
}


static bool __attribute__((nonnull))
dec_max_data_frame(const uint8_t ** pos,
                   const uint8_t * const end,
                   const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    uint64_t max = 0;
    decv_chk(&max, pos, end, c, FRM_MCD);

    warn(INF, FRAM_IN "MAX_DATA" NRM " max=%" PRIu64, max);

    if (max > c->tp_out.max_data) {
        c->tp_out.max_data = max;
        c->blocked = false;
    } else if (max < c->tp_out.max_data)
        warn(NTE, "MAX_DATA %" PRIu64 " < current value %" PRIu64, max,
             c->tp_out.max_data);

    return true;
}


static bool __attribute__((nonnull))
dec_stream_data_blocked_frame(const uint8_t ** pos,
                              const uint8_t * const end,
                              const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    int64_t sid = 0;
    decv_chk((uint64_t *)&sid, pos, end, c, FRM_SDB);

    uint64_t off = 0;
    decv_chk(&off, pos, end, c, FRM_SDB);

    warn(INF, FRAM_IN "STREAM_DATA_BLOCKED" NRM " id=" FMT_SID " lim=%" PRIu64,
         sid, off);

    struct q_stream * const s = get_and_validate_strm(c, sid, FRM_SDB, false);
    if (unlikely(s == 0))
        return false;

    do_stream_fc(s, 0);
    // because do_stream_fc() only sets this when increasing the FC window
    s->tx_max_stream_data = true;
    need_ctrl_update(s);

    return true;
}


static bool __attribute__((nonnull))
dec_data_blocked_frame(const uint8_t ** pos,
                       const uint8_t * const end,
                       const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    uint64_t off = 0;
    decv_chk(&off, pos, end, c, FRM_CDB);

    warn(INF, FRAM_IN "DATA_BLOCKED" NRM " lim=%" PRIu64, off);

    do_conn_fc(c, 0);
    // because do_conn_fc() only sets this when increasing the FC window
    c->tx_max_data = true;

    return false;
}


static bool __attribute__((nonnull))
dec_streams_blocked_frame(const uint8_t type,
                          const uint8_t ** pos,
                          const uint8_t * const end,
                          const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;

    uint64_t max = 0;
    decv_chk(&max, pos, end, c, FRM_SBB);

    warn(INF, FRAM_IN "STREAMS_BLOCKED" NRM " 0x%02x=%s max=%" PRIu64, type,
         type == FRM_SBB ? "bi" : "uni", max);

    do_stream_id_fc(c, max, type == FRM_SBB, false);

    return true;
}


static bool __attribute__((nonnull))
dec_stop_sending_frame(const uint8_t ** pos,
                       const uint8_t * const end,
                       const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    int64_t sid = 0;
    decv_chk((uint64_t *)&sid, pos, end, c, FRM_STP);

    uint16_t err_code;
    dec2_chk(&err_code, pos, end, c, FRM_STP);

    warn(INF, FRAM_IN "STOP_SENDING" NRM " id=" FMT_SID " err=%s0x%04x" NRM,
         sid, err_code ? RED : NRM, err_code);

    struct q_stream * const s = get_and_validate_strm(c, sid, FRM_STP, true);
    if (unlikely(s == 0))
        return false;

    return true;
}


static bool __attribute__((nonnull))
dec_path_challenge_frame(const uint8_t ** pos,
                         const uint8_t * const end,
                         const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    dec8_chk(&c->path_chlg_in, pos, end, c, FRM_PCL);

    warn(INF, FRAM_IN "PATH_CHALLENGE" NRM " data=%" PRIx64, c->path_chlg_in);

    c->path_resp_out = c->path_chlg_in;
    c->needs_tx = c->tx_path_resp = true;

    return true;
}


static bool __attribute__((nonnull))
dec_path_response_frame(const uint8_t ** pos,
                        const uint8_t * const end,
                        const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    dec8_chk(&c->path_resp_in, pos, end, c, FRM_PRP);

    warn(INF, FRAM_IN "PATH_RESPONSE" NRM " data=%" PRIx64, c->path_resp_in);

    if (unlikely(c->tx_path_chlg == false)) {
        warn(NTE, "unexpected PATH_RESPONSE %" PRIx64 ", ignoring",
             c->path_resp_in);
        return true;
    }

    if (unlikely(c->path_resp_in != c->path_chlg_out)) {
        warn(NTE, "PATH_RESPONSE %" PRIx64 " != %" PRIx64 ", ignoring",
             c->path_resp_in, c->path_chlg_out);
        return true;
    }

#ifndef NDEBUG
    char ip[NI_MAXHOST];
    char port[NI_MAXSERV];
    char migr_ip[NI_MAXHOST];
    char migr_port[NI_MAXSERV];
    ensure(getnameinfo((struct sockaddr *)&c->peer, sizeof(c->peer), ip,
                       sizeof(ip), port, sizeof(port),
                       NI_NUMERICHOST | NI_NUMERICSERV) == 0,
           "getnameinfo");
    ensure(getnameinfo((struct sockaddr *)&c->migr_peer, sizeof(c->migr_peer),
                       migr_ip, sizeof(migr_ip), migr_port, sizeof(migr_port),
                       NI_NUMERICHOST | NI_NUMERICSERV) == 0,
           "getnameinfo");

    warn(NTE, "migration from %s:%s to %s:%s complete", ip, port, migr_ip,
         migr_port);
#endif
    c->tx_path_chlg = false;
    c->peer = c->migr_peer;

    return true;
}


static bool __attribute__((nonnull))
dec_new_cid_frame(const uint8_t ** pos,
                  const uint8_t * const end,
                  const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    struct cid dcid = {.seq = 0, .has_srt = true};
    decv_chk(&dcid.seq, pos, end, c, FRM_CID);
    dec1_chk(&dcid.len, pos, end, c, FRM_CID);

    if (unlikely(dcid.len < CID_LEN_MIN || dcid.len > CID_LEN_MAX))
        err_close_return(c, ERR_PROTOCOL_VIOLATION, FRM_CID,
                         "illegal cid len %u", dcid.len);

    decb_chk(dcid.id, pos, end, dcid.len, c, FRM_CID);
    decb_chk(dcid.srt, pos, end, sizeof(dcid.srt), c, FRM_CID);

    const bool dup = splay_find(cids_by_seq, &c->dcids_by_seq, &dcid);
    if (dup == false)
        add_dcid(c, &dcid);

    warn(INF,
         FRAM_IN "NEW_CONNECTION_ID" NRM " seq=%" PRIu64
                 " len=%u dcid=%s srt=%s%s",
         dcid.seq, dcid.len, cid2str(&dcid),
         hex2str(dcid.srt, sizeof(dcid.srt)),
         dup ? " [" RED "dup" NRM "]" : "");

    return true;
}


static bool __attribute__((nonnull))
dec_reset_stream_frame(const uint8_t ** pos,
                       const uint8_t * const end,
                       const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    int64_t sid = 0;
    decv_chk((uint64_t *)&sid, pos, end, c, FRM_RST);

    uint16_t err;
    dec2_chk(&err, pos, end, c, FRM_RST);

    uint64_t off = 0;
    decv_chk(&off, pos, end, c, FRM_RST);

    warn(INF,
         FRAM_IN "RESET_STREAM" NRM " id=" FMT_SID " err=%s0x%04x" NRM
                 " off=%" PRIu64,
         sid, err ? RED : NRM, err, off);

    struct q_stream * const s = get_and_validate_strm(c, sid, FRM_RST, false);
    if (unlikely(s == 0))
        return false;

    strm_to_state(s, strm_clsd);

    return true;
}


static bool __attribute__((nonnull))
dec_retire_cid_frame(const uint8_t ** pos,
                     const uint8_t * const end,
                     const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    struct cid which = {.seq = 0};
    decv_chk(&which.seq, pos, end, c, FRM_RTR);

    warn(INF, FRAM_IN "RETIRE_CONNECTION_ID" NRM " seq=%" PRIu64, which.seq);

    struct cid * const scid = splay_find(cids_by_seq, &c->scids_by_seq, &which);
    if (unlikely(scid == 0))
        err_close_return(c, ERR_PROTOCOL_VIOLATION, FRM_RTR,
                         "no cid seq %" PRIu64, which.seq);
    else if (c->scid->seq == scid->seq) {
        struct cid * const next_scid =
            splay_next(cids_by_seq, &c->scids_by_seq, scid);
        if (unlikely(next_scid == 0))
            err_close_return(c, ERR_INTERNAL, FRM_RTR, "no next scid");
        c->scid = next_scid;
    }

    free_scid(c, scid);

    // rx of RETIRE_CONNECTION_ID means we should send more
    c->tx_ncid = true;

    return true;
}


static bool __attribute__((nonnull))
dec_new_token_frame(const uint8_t ** pos,
                    const uint8_t * const end,
                    const struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    uint64_t tok_len = 0;
    decv_chk(&tok_len, pos, end, c, FRM_TOK);

    if (unlikely(tok_len > (uint64_t)(end - *pos)))
        err_close_return(c, ERR_FRAME_ENC, FRM_TOK, "illegal tok len");

    uint8_t tok[MAX_TOK_LEN];
    if (unlikely(tok_len > sizeof(tok)))
        err_close_return(c, ERR_FRAME_ENC, FRM_TOK, "max tok_len is %u, got %u",
                         sizeof(tok), tok_len);
    decb_chk(tok, pos, end, (uint16_t)tok_len, c, FRM_TOK);

    warn(INF, FRAM_IN "NEW_TOKEN" NRM " len=%" PRIu64 " tok=%s", tok_len,
         hex2str(tok, tok_len));

    // TODO: actually do something with the token

    return true;
}


#ifndef NDEBUG
static void log_pad(const uint16_t len)
{
    warn(INF, FRAM_IN "PADDING" NRM " len=%u", len);
}
#else
#define log_pad(...)                                                           \
    do {                                                                       \
    } while (0)
#endif


bool dec_frames(struct q_conn * const c,
                struct w_iov ** vv,
                struct pkt_meta ** mm)
{
    struct w_iov * v = *vv;
    struct pkt_meta * m = *mm;
    const uint8_t * pos = v->buf + m->hdr.hdr_len;
    const uint8_t * end = v->buf + v->len;
    const uint8_t * pad_start = 0;

#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
    // when called from the fuzzer, v->addr.ss_family is zero
    if (v->addr.ss_family)
        write_to_corpus(corpus_frm_dir, pos, (size_t)(end - pos));
#endif

    while (likely(pos < end)) {
        uint8_t type;
        dec1_chk(&type, &pos, end, c, 0);

        // special-case for optimized parsing of padding ranges
        if (type == FRM_PAD) {
            if (unlikely(pad_start == 0)) {
                pad_start = pos;
                track_frame(m, FRM_PAD);
            }
            continue;
        } else {
            if (pad_start) {
                log_pad((uint16_t)(pos - pad_start + 1));
                pad_start = 0;
            }
        }

        // check that frame type is allowed in this pkt type
        static const struct frames lh_ok =
            bitset_t_initializer(1 << FRM_CRY | 1 << FRM_ACK | 1 << FRM_ACE |
                                 1 << FRM_PAD | 1 << FRM_CLQ | 1 << FRM_CLA);
        if (unlikely((m->hdr.type == LH_INIT || m->hdr.type == LH_HSHK) &&
                     bit_isset(FRM_MAX, type, &lh_ok) == false))
            err_close_return(c, ERR_PROTOCOL_VIOLATION, type,
                             "0x%02x frame not allowed in 0x%02x pkt", type,
                             m->hdr.type);

        bool ok;
        switch (type) {
        case FRM_CRY:
        case FRM_STR:
        case FRM_STR_09:
        case FRM_STR_0a:
        case FRM_STR_0b:
        case FRM_STR_0c:
        case FRM_STR_0d:
        case FRM_STR_0e:
        case FRM_STR_0f:;
            static const struct frames cry_or_str =
                bitset_t_initializer(1 << FRM_CRY | 1 << FRM_STR);
            if (unlikely(bit_overlap(FRM_MAX, &m->frames, &cry_or_str)) &&
                m->stream) {
                // already had at least one stream or crypto frame in this
                // packet with non-duplicate data, so generate (another) copy
#ifdef DEBUG_EXTRA
                warn(DBG, "addtl stream or crypto frame, copy");
#endif
                const uint16_t off = (uint16_t)(pos - v->buf - 1);
                struct pkt_meta * mdup;
                struct w_iov * const vdup = w_iov_dup(v, &mdup, off);
                pm_cpy(mdup, m, false);
                // adjust w_iov start and len to stream frame data
                v->buf += m->stream_data_start;
                v->len = m->stream_data_len;
                // continue parsing in the copied w_iov
                v = *vv = vdup;
                m = *mm = mdup;
                pos = v->buf + 1;
                end = v->buf + v->len;
            }
            ok = dec_stream_or_crypto_frame(type, &pos, end, m, v);
            type = type == FRM_CRY ? FRM_CRY : FRM_STR;
            break;

        case FRM_ACE:
        case FRM_ACK:
            ok = dec_ack_frame(type, &pos, end, m);
            type = FRM_ACK; // only enc FRM_ACK in bitstr_t
            break;

        case FRM_RST:
            ok = dec_reset_stream_frame(&pos, end, m);
            break;

        case FRM_CLQ:
        case FRM_CLA:
            ok = dec_close_frame(type, &pos, end, m);
            break;

        case FRM_PNG:
            warn(INF, FRAM_IN "PING" NRM);
            ok = true;
            break;

        case FRM_MSD:
            ok = dec_max_stream_data_frame(&pos, end, m);
            break;

        case FRM_MSB:
        case FRM_MSU:
            ok = dec_max_streams_frame(type, &pos, end, m);
            break;

        case FRM_MCD:
            ok = dec_max_data_frame(&pos, end, m);
            break;

        case FRM_SDB:
            ok = dec_stream_data_blocked_frame(&pos, end, m);
            break;

        case FRM_CDB:
            ok = dec_data_blocked_frame(&pos, end, m);
            break;

        case FRM_SBB:
        case FRM_SBU:
            ok = dec_streams_blocked_frame(type, &pos, end, m);
            break;

        case FRM_STP:
            ok = dec_stop_sending_frame(&pos, end, m);
            break;

        case FRM_PCL:
            ok = dec_path_challenge_frame(&pos, end, m);
            break;

        case FRM_PRP:
            ok = dec_path_response_frame(&pos, end, m);
            break;

        case FRM_CID:
            ok = dec_new_cid_frame(&pos, end, m);
            break;

        case FRM_TOK:
            ok = dec_new_token_frame(&pos, end, m);
            break;

        case FRM_RTR:
            ok = dec_retire_cid_frame(&pos, end, m);
            break;

        default:
            err_close_return(c, ERR_FRAME_ENC, type,
                             "unknown frame type 0x%02x", type);
        }

        if (unlikely(ok == false))
            // there was an error parsing a frame
            return false;

        // record this frame type in the meta data
        track_frame(m, type);
    }

    if (pad_start)
        log_pad((uint16_t)(pos - pad_start + 1));

    if (m->stream_data_start) {
        // adjust w_iov start and len to stream frame data
        v->buf += m->stream_data_start;
        v->len = m->stream_data_len;
    }

    // track outstanding frame types in the pn space
    struct pn_space * const pn = pn_for_pkt_type(c, m->hdr.type);
    bit_or(FRM_MAX, &pn->rx_frames, &m->frames);

    return true;
}


uint16_t max_frame_len(const uint8_t type)
{
    // return max len needed to encode the given frame type
    uint16_t len = sizeof(uint8_t); // type

    switch (type) {
    case FRM_PAD:
    case FRM_PNG:
        break;

        // these are always first, so assume there is enough space
        // case FRM_ACE:
        // case FRM_ACK:

    case FRM_RST:
        len += sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint64_t);
        break;

        // these two are never combined with stream frames, so no need to
        // check case FRM_CLQ: case FRM_CLA:

    case FRM_STP:
        len += sizeof(uint64_t) + sizeof(uint16_t);
        break;

        // these two don't need to be length-checked
        // case FRM_STR:
        // case FRM_CRY:

    case FRM_TOK:
        // only true on TX; update when make_rtry_tok() changes
        len += sizeof(uint64_t) + PTLS_MAX_DIGEST_SIZE + CID_LEN_MAX;
        break;

    case FRM_MCD:
    case FRM_MSB:
    case FRM_MSU:
    case FRM_CDB:
    case FRM_SBB:
    case FRM_SBU:
    case FRM_RTR:
    case FRM_PCL:
    case FRM_PRP:
        len += sizeof(uint64_t);
        break;

    case FRM_MSD:
    case FRM_SDB:
        len += sizeof(uint64_t) + sizeof(uint64_t);
        break;

    case FRM_CID:
        len += sizeof(uint64_t) + sizeof(uint8_t) + CID_LEN_MAX + SRT_LEN;
        break;

    default:
        die("unhandled frame type 0x%02x", type);
    }

    return len;
}


void enc_padding_frame(uint8_t ** pos,
                       const uint8_t * const end,
                       struct pkt_meta * const m,
                       const uint16_t len)
{
    if (unlikely(len == 0))
        return;
    ensure(*pos + len <= end, "buffer overflow");
    memset(*pos, FRM_PAD, len);
    *pos += len;
    warn(INF, FRAM_OUT "PADDING" NRM " len=%u", len);
    track_frame(m, FRM_PAD);
}


void enc_ack_frame(uint8_t ** pos,
                   const uint8_t * const start,
                   const uint8_t * const end,
                   struct pkt_meta * const m,
                   struct pn_space * const pn)
{
    const uint8_t type =
        (pn->ect0_cnt || pn->ect1_cnt || pn->ce_cnt) ? FRM_ACE : FRM_ACK;
    enc1(pos, end, type);

    struct ival * b = diet_max_ival(&pn->recv);
    ensure(b, "nothing to ACK");
    m->lg_acked = b->hi;
    encv(pos, end, m->lg_acked);

    // handshake pkts always use the default ACK delay exponent
    struct q_conn * const c = pn->c;
    const uint64_t ade = m->hdr.type == LH_INIT || m->hdr.type == LH_HSHK
                             ? DEF_ACK_DEL_EXP
                             : c->tp_out.ack_del_exp;
    const uint64_t ack_delay =
        (uint64_t)((ev_now(loop) - diet_timestamp(b)) * USECS_PER_SEC) /
        (1 << ade);
    encv(pos, end, ack_delay);

    m->ack_block_cnt = diet_cnt(&pn->recv) - 1;
    encv(pos, end, m->ack_block_cnt);
    m->ack_block_pos = (uint16_t)(*pos - start);

    uint64_t prev_lo = 0;
    diet_foreach_rev (b, diet, &pn->recv) {
        uint64_t gap = 0;
        if (prev_lo) {
            gap = prev_lo - b->hi - 2;
            encv(pos, end, gap);
        }
        const uint64_t ack_block = b->hi - b->lo;
#ifndef NDEBUG
        if (ack_block) {
            if (prev_lo)
                warn(INF,
                     FRAM_OUT "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                              " [" FMT_PNR_IN ".." FMT_PNR_IN "]",
                     gap, ack_block, b->lo, shorten_ack_nr(b->hi, ack_block));
            else
                warn(INF,
                     FRAM_OUT "ACK" NRM " 0x%02x=%s lg=" FMT_PNR_IN
                              " delay=%" PRIu64 " (%" PRIu64
                              " usec) cnt=%" PRIu64 " block=%" PRIu64
                              " [" FMT_PNR_IN ".." FMT_PNR_IN "]",
                     type, type == FRM_ACE ? "ECN" : "", m->lg_acked, ack_delay,
                     ack_delay * (1 << ade), m->ack_block_cnt, ack_block, b->lo,
                     shorten_ack_nr(b->hi, ack_block));

        } else {
            if (prev_lo)
                warn(INF,
                     FRAM_OUT "ACK" NRM " gap=%" PRIu64 " block=%" PRIu64
                              " [" FMT_PNR_IN "]",
                     gap, ack_block, b->hi);
            else
                warn(INF,
                     FRAM_OUT "ACK" NRM " 0x%02x=%s lg=" FMT_PNR_IN
                              " delay=%" PRIu64 " (%" PRIu64
                              " usec) cnt=%" PRIu64 " block=%" PRIu64
                              " [" FMT_PNR_IN "]",
                     type, type == FRM_ACE ? "ECN" : "", m->lg_acked, ack_delay,
                     ack_delay * (1 << ade), m->ack_block_cnt, ack_block,
                     m->lg_acked);
        }
#endif
        encv(pos, end, ack_block);
        prev_lo = b->lo;
    }

    if (type == FRM_ACE) {
        // encode ECN
        encv(pos, end, pn->ect0_cnt);
        encv(pos, end, pn->ect1_cnt);
        encv(pos, end, pn->ce_cnt);
        warn(INF,
             FRAM_OUT "ECN" NRM " ect0=%s%" PRIu64 NRM " ect1=%s%" PRIu64 NRM
                      " ce=%s%" PRIu64 NRM,
             pn->ect0_cnt ? BLU : NRM, pn->ect0_cnt, pn->ect1_cnt ? BLU : NRM,
             pn->ect1_cnt, pn->ce_cnt ? BLU : NRM, pn->ce_cnt);
    }

    ev_timer_stop(loop, &c->ack_alarm);
    bit_zero(FRM_MAX, &pn->rx_frames);
    pn->pkts_rxed_since_last_ack_tx = 0;
    pn->imm_ack = false;
    track_frame(m, FRM_ACK);
}


void enc_stream_or_crypto_frame(uint8_t ** pos,
                                const uint8_t * const end,
                                struct pkt_meta * const m,
                                struct w_iov * const v,
                                struct q_stream * const s,
                                const bool enc_strm)
{
    const uint64_t dlen = v->len - m->stream_data_start;
    uint8_t type = FRM_CRY;

    if (likely(enc_strm)) {
        ensure(is_lh(m->hdr.flags) == false || m->hdr.type == LH_0RTT,
               "sid %" PRId64 " in %s pkt", s->id,
               pkt_type_str(m->hdr.flags, &m->hdr.vers));

        ensure(dlen || s->state > strm_open,
               "no stream data or need to send FIN");

        type = FRM_STR | (dlen ? F_STREAM_LEN : 0) |
               (s->out_data ? F_STREAM_OFF : 0);

        // if stream is closed locally and this is last packet, include FIN
        if (unlikely(m->is_fin))
            type |= F_STREAM_FIN;
    }

    *pos = v->buf + m->stream_data_start;
    if (dlen || unlikely(!enc_strm)) {
        *pos -= varint_size(dlen);
        uint8_t * const p = *pos;
        encv(pos, end, dlen);
        *pos = p;
    }
    if (s->out_data || unlikely(!enc_strm)) {
        *pos -= varint_size(s->out_data);
        uint8_t * const p = *pos;
        encv(pos, end, s->out_data);
        *pos = p;
    }
    if (likely(enc_strm)) {
        *pos -= varint_size((uint64_t)s->id);
        uint8_t * const p = *pos;
        encv(pos, end, (uint64_t)s->id);
        *pos = p;
    }
    m->stream_header_pos = (uint16_t)(--(*pos) - v->buf);
    enc1(pos, end, type);

    m->stream = s; // remember stream this buf belongs to
    m->stream_data_len = (uint16_t)dlen;
    m->stream_off = s->out_data;
    *pos = v->buf + m->stream_data_start + m->stream_data_len;

    log_stream_or_crypto_frame(false, m, type, s->id, false, "");
    track_bytes_out(s, dlen);
    ensure(!enc_strm || s->out_data < s->out_data_max, "exceeded fc window");
    track_frame(m, type == FRM_CRY ? FRM_CRY : FRM_STR);
}


void enc_close_frame(uint8_t ** pos,
                     const uint8_t * const end,
                     struct pkt_meta * const m)
{
    const struct q_conn * const c = m->pn->c;
    const uint8_t type = c->err_frm == 0 ? FRM_CLA : FRM_CLQ;

    enc1(pos, end, type);
    enc2(pos, end, c->err_code);
    if (type == FRM_CLQ)
        enc1(pos, end, c->err_frm);
    encv(pos, end, c->err_reason_len);
    if (c->err_reason_len)
        encb(pos, end, (const uint8_t *)c->err_reason, c->err_reason_len);

#ifndef NDEBUG
    if (type == FRM_CLQ)
        warn(INF,
             FRAM_OUT "CONNECTION_CLOSE" NRM " 0x%02x=quic err=%s0x%04x" NRM
                      " frame=0x%02x rlen=%u reason=%s%.*s" NRM,
             type, c->err_code ? RED : NRM, c->err_code, c->err_frm,
             c->err_reason_len, c->err_code ? RED : NRM, (int)c->err_reason_len,
             c->err_reason);
    else
        warn(INF,
             FRAM_OUT "CONNECTION_CLOSE" NRM " 0x%02x=app err=%s0x%04x" NRM
                      " rlen=%u reason=%s%.*s" NRM,
             type, c->err_code ? RED : NRM, c->err_code, c->err_reason_len,
             c->err_code ? RED : NRM, (int)c->err_reason_len, c->err_reason);
#endif

    track_frame(m, type);
}


void enc_max_stream_data_frame(uint8_t ** pos,
                               const uint8_t * const end,
                               struct pkt_meta * const m,
                               struct q_stream * const s)
{
    enc1(pos, end, FRM_MSD);
    encv(pos, end, (uint64_t)s->id);
    encv(pos, end, s->in_data_max);

    warn(INF, FRAM_OUT "MAX_STREAM_DATA" NRM " id=" FMT_SID " max=%" PRIu64,
         s->id, s->in_data_max);

    m->max_stream_data_sid = s->id;
    m->max_stream_data = s->in_data_max;
    s->tx_max_stream_data = false;
    track_frame(m, FRM_MSD);
}


void enc_max_data_frame(uint8_t ** pos,
                        const uint8_t * const end,
                        struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    enc1(pos, end, FRM_MCD);
    encv(pos, end, c->tp_in.max_data);

    warn(INF, FRAM_OUT "MAX_DATA" NRM " max=%" PRIu64, c->tp_in.max_data);

    m->max_data = c->tp_in.max_data;
    c->tx_max_data = false;
    track_frame(m, FRM_MCD);
}


void enc_max_streams_frame(uint8_t ** pos,
                           const uint8_t * const end,
                           struct pkt_meta * const m,
                           const bool bidi)
{
    struct q_conn * const c = m->pn->c;
    const uint8_t type = bidi ? FRM_MSB : FRM_MSU;
    enc1(pos, end, type);
    const uint64_t max =
        bidi ? c->tp_in.max_streams_bidi : c->tp_in.max_streams_uni;
    encv(pos, end, max);

    warn(INF, FRAM_OUT "MAX_STREAMS" NRM " 0x%02x=%s max=%" PRIu64, type,
         bidi ? "bi" : "uni", max);

    if (bidi)
        c->tx_max_sid_bidi = false;
    else
        c->tx_max_sid_uni = false;
    track_frame(m, type);
}


void enc_stream_data_blocked_frame(uint8_t ** pos,
                                   const uint8_t * const end,
                                   struct pkt_meta * const m,
                                   struct q_stream * const s)
{
    enc1(pos, end, FRM_SDB);
    encv(pos, end, (uint64_t)s->id);
    m->stream_data_blocked = s->out_data_max;
    encv(pos, end, m->stream_data_blocked);

    warn(INF, FRAM_OUT "STREAM_DATA_BLOCKED" NRM " id=" FMT_SID " lim=%" PRIu64,
         s->id, m->stream_data_blocked);

    track_frame(m, FRM_SDB);
}


void enc_data_blocked_frame(uint8_t ** pos,
                            const uint8_t * const end,
                            struct pkt_meta * const m)
{
    enc1(pos, end, FRM_CDB);

    m->data_blocked = m->pn->c->tp_out.max_data + m->stream_data_len;
    encv(pos, end, m->data_blocked);

    warn(INF, FRAM_OUT "DATA_BLOCKED" NRM " lim=%" PRIu64, m->data_blocked);

    track_frame(m, FRM_CDB);
}


void enc_streams_blocked_frame(uint8_t ** pos,
                               const uint8_t * const end,
                               struct pkt_meta * const m,
                               const bool bidi)
{
    struct q_conn * const c = m->pn->c;
    const uint8_t type = bidi ? FRM_SBB : FRM_SBU;
    enc1(pos, end, type);
    const uint64_t lim =
        bidi ? c->tp_out.max_streams_bidi : c->tp_out.max_streams_uni;
    encv(pos, end, lim);

    warn(INF, FRAM_OUT "STREAMS_BLOCKED" NRM " 0x%02x=%s lim=%" PRIu64, type,
         type == FRM_SBB ? "bi" : "uni", lim);

    if (bidi)
        c->sid_blocked_bidi = false;
    else
        c->sid_blocked_uni = false;
    track_frame(m, type);
}


void enc_path_response_frame(uint8_t ** pos,
                             const uint8_t * const end,
                             struct pkt_meta * const m)
{
    const struct q_conn * const c = m->pn->c;
    enc1(pos, end, FRM_PRP);
    enc8(pos, end, c->path_resp_out);

    warn(INF, FRAM_OUT "PATH_RESPONSE" NRM " data=%" PRIx64, c->path_resp_out);

    track_frame(m, FRM_PRP);
}


void enc_path_challenge_frame(uint8_t ** pos,
                              const uint8_t * const end,
                              struct pkt_meta * const m)
{
    const struct q_conn * const c = m->pn->c;
    enc1(pos, end, FRM_PCL);
    enc8(pos, end, c->path_chlg_out);

    warn(INF, FRAM_OUT "PATH_CHALLENGE" NRM " data=%" PRIx64, c->path_chlg_out);

    track_frame(m, FRM_PCL);
}


void enc_new_cid_frame(uint8_t ** pos,
                       const uint8_t * const end,
                       struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;

    const struct cid * const max_scid =
        splay_max(cids_by_seq, &c->scids_by_seq);
    const struct cid * const min_scid =
        splay_min(cids_by_seq, &c->scids_by_seq);
    c->max_cid_seq_out = MAX(min_scid->seq, c->max_cid_seq_out + 1);
    struct cid ncid = {.seq = c->max_cid_seq_out,
                       .len = c->is_clnt ? SCID_LEN_CLNT : SCID_LEN_SERV};

    struct cid * enc_cid = &ncid;
    if (max_scid && ncid.seq <= max_scid->seq) {
        enc_cid = splay_find(cids_by_seq, &c->scids_by_seq, &ncid);
        ensure(enc_cid, "max_scid->seq %" PRIu64 " ncid.seq %" PRIu64,
               max_scid->seq, ncid.seq);
    } else {
        rand_bytes(ncid.id, sizeof(ncid.id) + sizeof(ncid.srt));
        add_scid(c, &ncid);
    }

    m->min_cid_seq = m->min_cid_seq == 0 ? enc_cid->seq : m->min_cid_seq;

    enc1(pos, end, FRM_CID);
    encv(pos, end, enc_cid->seq);
    enc1(pos, end, enc_cid->len);
    encb(pos, end, enc_cid->id, enc_cid->len);
    encb(pos, end, enc_cid->srt, sizeof(enc_cid->srt));

    warn(INF,
         FRAM_OUT "NEW_CONNECTION_ID" NRM " seq=%" PRIu64
                  " len=%u cid=%s srt=%s %s",
         enc_cid->seq, enc_cid->len, cid2str(enc_cid),
         hex2str(enc_cid->srt, sizeof(enc_cid->srt)),
         enc_cid == &ncid ? "" : BLD REV GRN "[RTX]" NRM);

    track_frame(m, FRM_CID);
}


void enc_new_token_frame(uint8_t ** pos,
                         const uint8_t * const end,
                         struct pkt_meta * const m)
{
    const struct q_conn * const c = m->pn->c;
    enc1(pos, end, FRM_TOK);
    encv(pos, end, c->tok_len);
    encb(pos, end, c->tok, c->tok_len);

    warn(INF, FRAM_OUT "NEW_TOKEN" NRM " len=%u tok=%s", c->tok_len,
         hex2str(c->tok, c->tok_len));

    track_frame(m, FRM_TOK);
}


void enc_retire_cid_frame(uint8_t ** pos,
                          const uint8_t * const end,
                          struct pkt_meta * const m,
                          struct cid * const dcid)
{
    enc1(pos, end, FRM_RTR);
    encv(pos, end, dcid->seq);

    warn(INF, FRAM_OUT "RETIRE_CONNECTION_ID" NRM " seq=%" PRIu64, dcid->seq);

    m->pn->c->tx_retire_cid = false;
    track_frame(m, FRM_RTR);
}


void enc_ping_frame(uint8_t ** pos,
                    const uint8_t * const end,
                    struct pkt_meta * const m)
{
    enc1(pos, end, FRM_PNG);

    warn(INF, FRAM_OUT "PING" NRM);

    track_frame(m, FRM_PNG);
}


bool is_ack_eliciting(const struct frames * const f)
{
    static const struct frames ack_or_pad =
        bitset_t_initializer(1 << FRM_ACK | 1 << FRM_PAD);
    struct frames not_ack_or_pad = bitset_t_initializer(0);
    bit_nand2(FRM_MAX, &not_ack_or_pad, f, &ack_or_pad);
    return !bit_empty(FRM_MAX, &not_ack_or_pad);
}
