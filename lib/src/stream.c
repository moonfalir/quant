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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#define klib_unused

#include <ev.h>
#include <khash.h>
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#include "conn.h"
#include "diet.h"
#include "pkt.h"
#include "quic.h"
#include "stream.h"


#undef STRM_STATE
#define STRM_STATE(k, v) [v] = #k


const char * const strm_state_str[] = {STRM_STATES};


int64_t crpt_strm_id(const epoch_t epoch)
{
    switch (epoch) { // lgtm [cpp/missing-return]
    case ep_init:
        return -4;
    case ep_hshk:
        return -2;
    case ep_data:
        return -1;
    case ep_0rtt:
        die("unhandled epoch %u", epoch);
    }
}


epoch_t strm_epoch(const struct q_stream * const s)
{
    if (unlikely(s->id < 0))
        switch (s->id) {
        case -4:
            return ep_init;
        case -2:
            return ep_hshk;
        case -1:
            return ep_data;
        default:
            die("illegal sid %" PRId64, s->id);
        }

    if (unlikely(s->c->is_clnt == true && s->c->state == conn_opng))
        return ep_0rtt;

    return ep_data;
}


void need_ctrl_update(struct q_stream * const s)
{
    if (unlikely(needs_ctrl(s) != s->in_ctrl)) {
        if (s->in_ctrl == false)
            sl_insert_head(&s->c->need_ctrl, s, node_ctrl);
        else
            sl_remove(&s->c->need_ctrl, s, q_stream, node_ctrl);
        s->in_ctrl = !s->in_ctrl;
    }
}


struct q_stream * get_stream(struct q_conn * const c, const int64_t id)
{
    const khiter_t k = kh_get(streams_by_id, c->streams_by_id, (khint64_t)id);
    if (unlikely(k == kh_end(c->streams_by_id)))
        return 0;
    return kh_val(c->streams_by_id, k);
}


int64_t max_sid(const int64_t sid, const struct q_conn * const c)
{
    const uint64_t max = is_srv_ini(sid) == c->is_clnt
                             ? (is_uni(sid) ? c->tp_in.max_streams_uni
                                            : c->tp_in.max_streams_bidi)
                             : (is_uni(sid) ? c->tp_out.max_streams_uni
                                            : c->tp_out.max_streams_bidi);
    return unlikely(max == 0) ? 0
                              : (int64_t)((max - 1) << 2) |
                                    ((STRM_FL_SRV | STRM_FL_UNI) & sid);
}


void apply_stream_limits(struct q_stream * const s)
{
    struct q_conn * const c = s->c;
    s->in_data_max = is_srv_ini(s->id) == c->is_clnt
                         ? (is_uni(s->id) ? c->tp_in.max_strm_data_uni
                                          : c->tp_in.max_strm_data_bidi_remote)
                         : (is_uni(s->id) ? c->tp_in.max_strm_data_uni
                                          : c->tp_in.max_strm_data_bidi_local);
    s->out_data_max =
        is_srv_ini(s->id) == c->is_clnt
            ? (is_uni(s->id) ? c->tp_out.max_strm_data_uni
                             : c->tp_out.max_strm_data_bidi_remote)
            : (is_uni(s->id) ? c->tp_out.max_strm_data_uni
                             : c->tp_out.max_strm_data_bidi_local);

    if (s->id >= 0)
        do_stream_fc(s, 0);
}


struct q_stream * new_stream(struct q_conn * const c, const int64_t id)
{
    struct q_stream * const s = calloc(1, sizeof(*s));
    ensure(s, "could not calloc q_stream");
    sq_init(&s->out);
    sq_init(&s->in);
    s->c = c;
    s->id = id;
    strm_to_state(s, strm_open);

    const uint64_t cnt = (uint64_t)((id >> 2) + 1);
    if (is_uni(id))
        c->cnt_uni = MAX(cnt, c->cnt_uni);
    else
        c->cnt_bidi = MAX(cnt, c->cnt_bidi);

    if (unlikely(id < 0)) {
        c->cstreams[strm_epoch(s)] = s;
        return s;
    }

    int ret;
    const khiter_t k =
        kh_put(streams_by_id, c->streams_by_id, (khint64_t)id, &ret);
    ensure(ret >= 1, "inserted");
    kh_val(c->streams_by_id, k) = s;

    apply_stream_limits(s);
    const bool is_local = (is_srv_ini(id) != c->is_clnt);
    do_stream_id_fc(c, cnt, !is_uni(id), is_local);

    if (is_local) {
        // this is a local stream
        if (is_uni(id))
            c->next_sid_uni += 4;
        else
            c->next_sid_bidi += 4;
    }

    return s;
}


void free_stream(struct q_stream * const s)
{
    struct q_conn * const c = s->c;
    if (likely(s->id >= 0)) {
#ifndef FUZZING
        warn(DBG, "freeing strm " FMT_SID " on %s conn %s", s->id, conn_type(c),
             cid2str(c->scid));
#endif
        diet_insert(&c->closed_streams, (uint64_t)s->id, (ev_tstamp)NAN);
        const khiter_t k =
            kh_get(streams_by_id, c->streams_by_id, (khint64_t)s->id);
        ensure(k != kh_end(c->streams_by_id), "found");
        kh_del(streams_by_id, c->streams_by_id, k);
    } else
        s->c->cstreams[strm_epoch(s)] = 0;

    while (!splay_empty(&s->in_ooo)) {
        struct pkt_meta * const p = splay_min(ooo_by_off, &s->in_ooo);
        ensure(splay_remove(ooo_by_off, &s->in_ooo, p), "removed");
        free_iov(w_iov(c->w, pm_idx(p)), p);
    }

    q_free(&s->out);
    q_free(&s->in);
    free(s);
}


void track_bytes_in(struct q_stream * const s, const uint64_t n)
{
    if (likely(s->id >= 0))
        // crypto "streams" don't count
        s->c->in_data_str += n;
    s->in_data += n;
}


void track_bytes_out(struct q_stream * const s, const uint64_t n)
{
    if (likely(s->id >= 0))
        // crypto "streams" don't count
        s->c->out_data_str += n;
    s->out_data += n;
}


void reset_stream(struct q_stream * const s, const bool forget)
{
    // warn(DBG, "reset strm %u " FMT_SID " on %s conn %s", forget, s->id,
    //      conn_type(s->c), cid2str(s->c->scid));

    // reset stream offsets
    s->in_data_off = s->in_data = s->out_data = 0;

    if (forget) {
        s->out_una = 0;
        q_free(&s->out);
        q_free(&s->in);
        return;
    }

    struct w_iov * v = s->out_una;
    sq_foreach_from (v, &s->out, next) {
        struct pkt_meta * const m = &meta(v);
        if (m->pn)
            // remove trailing padding
            v->len = m->stream_data_len;

        // don't reset stream-data-related fields
        // TODO: redo this with offsetof magic
        const bool fin = m->is_fin;
        const uint16_t shp = m->stream_header_pos;
        const uint16_t sds = m->stream_data_start;
        const uint16_t sdl = m->stream_data_len;
        memset(m, 0, sizeof(*m));
        m->is_fin = fin;
        m->stream_header_pos = shp;
        m->stream_data_start = sds;
        m->stream_data_len = sdl;
    }
}


void do_stream_fc(struct q_stream * const s, const uint16_t len)
{
    s->blocked = (s->out_data + len + MAX_PKT_LEN > s->out_data_max);

    if (s->in_data * 2 > s->in_data_max) {
        s->tx_max_stream_data = true;
        s->in_data_max *= 2;
    }

    need_ctrl_update(s);
}


void do_stream_id_fc(struct q_conn * const c,
                     const uint64_t cnt,
                     const bool bidi,
                     const bool local)
{
    if (local) {
        // this is a local stream
        if (bidi)
            c->sid_blocked_bidi = (cnt == c->tp_out.max_streams_bidi);
        else
            c->sid_blocked_uni =
                (c->tp_out.max_streams_uni && cnt == c->tp_out.max_streams_uni);
        return;
    }

    // this is a remote stream
    if (bidi) {
        if (cnt == c->tp_in.max_streams_bidi) {
            c->tx_max_sid_bidi = true;
            c->tp_in.max_streams_bidi *= 2;
        }
    } else {
        if (cnt == c->tp_in.max_streams_uni) {
            c->tx_max_sid_uni = true;
            c->tp_in.max_streams_uni *= 2;
        }
    }
}


void concat_out(struct q_stream * const s, struct w_iov_sq * const q)
{
    if (s->out_una == 0)
        s->out_una = sq_first(q);

    sq_concat(&s->out, q);
}


bool q_is_uni_stream(const struct q_stream * const s)
{
    return is_uni(s->id);
}


bool out_fully_acked(const struct q_stream * const s)
{
    return s->out_una == 0;
}


bool needs_ctrl(const struct q_stream * const s)
{
    return s->tx_max_stream_data || s->blocked;
}
