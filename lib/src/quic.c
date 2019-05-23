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

#include <arpa/inet.h>
#include <math.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>


#define klib_unused

// IWYU pragma: no_include <picotls/../picotls.h>

#include <ev.h>
#include <khash.h>
#include <picotls.h> // IWYU pragma: keep
#include <quant/quant.h>
#include <warpcore/warpcore.h>

#ifdef HAVE_ASAN
#include <sanitizer/asan_interface.h>
#else
#define ASAN_POISON_MEMORY_REGION(x, y)
#define ASAN_UNPOISON_MEMORY_REGION(x, y)
#endif

#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "conn.h"
#include "pkt.h"
#include "pn.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"
#include "tls.h"


struct ev_loop;

SPLAY_GENERATE(ooo_by_off, pkt_meta, off_node, ooo_by_off_cmp)

// TODO: many of these globals should move to a per-engine struct


/// QUIC version supported by this implementation in order of preference.
const uint32_t ok_vers[] = {
#ifndef NDEBUG
    0xbabababa, // reserved version to trigger negotiation, TODO: randomize
#endif
    0x45474700 + DRAFT_VERSION, // quant private version -xx
    0xff000000 + DRAFT_VERSION, // draft-ietf-quic-transport-xx
};

/// Length of the @p ok_vers array.
const uint8_t ok_vers_len = sizeof(ok_vers) / sizeof(ok_vers[0]);


struct pkt_meta * pkt_meta = 0;
struct ev_loop * loop = 0;

func_ptr api_func = 0;
void *api_conn = 0, *api_strm = 0;

struct q_conn_sl accept_queue = sl_head_initializer(accept_queue);

static ev_timer api_alarm;
static uint64_t num_bufs;

#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
int corpus_pkt_dir, corpus_frm_dir;
#endif


/// Run the event loop for the API function @p func with connection @p conn
/// and (optionally, if non-zero) stream @p strm.
///
/// @param      func  The API function to run the event loop for.
/// @param      conn  The connection to run the event loop for.
/// @param      strm  The stream to run the event loop for.
///
static void __attribute__((nonnull(1)))
do_loop_run(const func_ptr func,
            struct q_conn * const conn,
            struct q_stream * const strm)
{
    EV_VERIFY(loop);
    ensure(api_func == 0, "other API call active");
    api_func = func;
    api_conn = conn;
    api_strm = strm;
    ev_run(loop, 0);
    api_func = 0;
    api_conn = api_strm = 0;
}

#define loop_run(func, conn, strm) do_loop_run((func_ptr)(func), (conn), (strm))


void alloc_off(struct w_engine * const w,
               struct w_iov_sq * const q,
               const uint32_t len,
               const uint16_t off)
{
    w_alloc_len(w, q, len, MAX_PKT_LEN - AEAD_LEN - off, off);
    struct w_iov * v = 0;
    sq_foreach (v, q, next) {
        struct pkt_meta * const m = &meta(v);
        ASAN_UNPOISON_MEMORY_REGION(m, sizeof(*m));
        m->stream_data_start = off;

#ifdef DEBUG_BUFFERS
        warn(DBG, "idx %u (avail %" PRIu64 ") len %u", w_iov_idx(v),
             sq_len(&w->iov), v->len);
#endif
    }
}


void free_iov(struct w_iov * const v, struct pkt_meta * const m)
{
#ifdef DEBUG_BUFFERS
    warn(DBG, "idx %u (avail %" PRIu64 ") %cX'ed %s pkt nr=%" PRIu64,
         w_iov_idx(v), sq_len(&v->w->iov) + 1, m->txed ? 'T' : 'R',
         pkt_type_str(m->hdr.flags, &m->hdr.vers),
         has_pkt_nr(m->hdr.flags, m->hdr.vers) ? m->hdr.nr : 0);
#endif

    if (m->txed) {
        if (m->acked == false && m->lost == false && m->pn->sent_pkts)
            on_pkt_lost(m);

        struct pkt_meta * m_rtx = sl_first(&m->rtx);
        if (unlikely(m_rtx)) {
            // this pkt has prior or later RTXs
            if (m->has_rtx) {
                // this pkt has an RTX
#ifdef DEBUG_BUFFERS
                warn(DBG, "pkt nr=%" PRIu64 " has RTX %" PRIu64,
                     has_pkt_nr(m->hdr.flags, m->hdr.vers) ? m->hdr.nr : 0,
                     has_pkt_nr(m_rtx->hdr.flags, m_rtx->hdr.vers)
                         ? m_rtx->hdr.nr
                         : 0);
#endif
                sl_remove(&m_rtx->rtx, m, pkt_meta, rtx_next);

            } else {
                // this is the last ("real") RTX of a packet
                while (m_rtx) {
#ifdef DEBUG_BUFFERS
                    warn(DBG, "pkt nr=%" PRIu64 " was also TX'ed as %" PRIu64,
                         has_pkt_nr(m->hdr.flags, m->hdr.vers) ? m->hdr.nr : 0,
                         has_pkt_nr(m_rtx->hdr.flags, m_rtx->hdr.vers)
                             ? m_rtx->hdr.nr
                             : 0);
#endif
                    ensure(m_rtx->has_rtx, "was RTX'ed");
                    sl_remove_head(&m->rtx, rtx_next);
                    sl_remove_head(&m_rtx->rtx, rtx_next);
                    m_rtx = sl_next(m_rtx, rtx_next);
                }
            }
        }
    }

    memset(m, 0, sizeof(*m));
    ASAN_POISON_MEMORY_REGION(m, sizeof(*m));
    w_free_iov(v);
}


struct w_iov * alloc_iov(struct w_engine * const w,
                         const uint16_t len,
                         const uint16_t off,
                         struct pkt_meta ** const m)
{
    struct w_iov * const v = w_alloc_iov(w, len, off);
    ensure(v, "w_alloc_iov failed");
    *m = &meta(v);
    ASAN_UNPOISON_MEMORY_REGION(*m, sizeof(**m));
    (*m)->stream_data_start = off;

#ifdef DEBUG_BUFFERS
    warn(DBG, "alloc_iov idx %u (avail %" PRIu64 ") len %u off %u",
         w_iov_idx(v), sq_len(&w->iov), v->len, off);
#endif

    return v;
}


struct w_iov * w_iov_dup(const struct w_iov * const v,
                         struct pkt_meta ** const mdup,
                         const uint16_t off)
{
    struct w_iov * const vdup = w_alloc_iov(v->w, v->len - off, 0);
    ensure(vdup, "w_alloc_iov failed");

#ifdef DEBUG_BUFFERS
    warn(DBG, "w_alloc_iov idx %u (avail %" PRIu64 ") len %u", w_iov_idx(vdup),
         sq_len(&v->w->iov), vdup->len);
#endif

    if (mdup) {
        *mdup = &meta(vdup);
        ASAN_UNPOISON_MEMORY_REGION(*mdup, sizeof(**mdup));
    }
    memcpy(vdup->buf, v->buf + off, v->len - off);
    memcpy(&vdup->addr, &v->addr, sizeof(v->addr));
    vdup->flags = v->flags;
    return vdup;
}


void q_alloc(struct w_engine * const w,
             struct w_iov_sq * const q,
             const size_t len)
{
    ensure(len <= UINT32_MAX, "len %zu too long", len);
    alloc_off(w, q, (uint32_t)len, DATA_OFFSET);
}


void q_free(struct w_iov_sq * const q)
{
    while (!sq_empty(q)) {
        struct w_iov * const v = sq_first(q);
        sq_remove_head(q, next);
        free_iov(v, &meta(v));
    }
}


static void __attribute__((nonnull)) mark_fin(struct w_iov_sq * const q)
{
    struct w_iov * const last = sq_last(q, w_iov, next);
    ensure(last, "got last buffer");
    meta(last).is_fin = true;
}


struct q_conn * q_connect(struct w_engine * const w,
                          const struct sockaddr * const peer,
                          const char * const peer_name,
                          struct w_iov_sq * const early_data,
                          struct q_stream ** const early_data_stream,
                          const bool fin,
                          const struct q_conn_conf * const conf)
{
    // make new connection
    const uint vers = ok_vers[0];
    struct q_conn * const c = new_conn(w, vers, 0, 0, peer, peer_name, 0, conf);

    // init TLS
    init_tls(c, conf ? conf->alpn : 0);
    init_tp(c);

    // if we have no early data, we're not trying 0-RTT
    c->try_0rtt &= early_data && early_data_stream;

#ifndef NDEBUG
    char ip[NI_MAXHOST];
    char port[NI_MAXSERV];
    ensure(getnameinfo(peer, sizeof(*peer), ip, sizeof(ip), port, sizeof(port),
                       NI_NUMERICHOST | NI_NUMERICSERV) == 0,
           "getnameinfo");

    warn(WRN,
         "new %u-RTT %s conn %s to %s:%s, %" PRIu64 " byte%s queued for TX",
         c->try_0rtt ? 0 : 1, conn_type(c), cid2str(c->scid), ip, port,
         early_data ? w_iov_sq_len(early_data) : 0,
         plural(early_data ? w_iov_sq_len(early_data) : 0));
#endif

    ev_timer_again(loop, &c->idle_alarm);
    w_connect(c->sock, peer);

    // start TLS handshake
    tls_io(c->cstreams[ep_init], 0);

    if (early_data && !sq_empty(early_data)) {
        ensure(early_data_stream, "early data without stream pointer");
        // queue up early data
        if (fin)
            mark_fin(early_data);
        *early_data_stream = new_stream(c, c->next_sid_bidi);
        concat_out(*early_data_stream, early_data);
    } else if (early_data_stream)
        *early_data_stream = 0;

    ev_feed_event(loop, &c->tx_w, 0);

    warn(DBG, "waiting for connect to complete on %s conn %s to %s:%s",
         conn_type(c), cid2str(c->scid), ip, port);
    conn_to_state(c, conn_opng);
    loop_run(q_connect, c, 0);

    if (fin && early_data_stream && *early_data_stream)
        strm_to_state(*early_data_stream,
                      (*early_data_stream)->state == strm_hcrm ? strm_clsd
                                                               : strm_hclo);

    if (c->state != conn_estb) {
        warn(WRN, "%s conn %s not connected", conn_type(c), cid2str(c->scid));
        return 0;
    }

#ifndef NDEBUG
    struct pn_data * const pnd = &c->pns[pn_data].data;
    warn(WRN, "%s conn %s connected%s, cipher %s", conn_type(c),
         cid2str(c->scid), c->did_0rtt ? " after 0-RTT" : "",
         pnd->out_1rtt[pnd->out_kyph].aead->algo->name);
#endif

    return c;
}


bool q_write(struct q_stream * const s,
             struct w_iov_sq * const q,
             const bool fin)
{
    struct q_conn * const c = s->c;
    if (unlikely(c->state == conn_qlse || c->state == conn_drng ||
                 c->state == conn_clsd)) {
        warn(ERR, "%s conn %s is in state %s, can't write", conn_type(c),
             cid2str(c->scid), conn_state_str[c->state]);
        return false;
    }

    if (unlikely(sq_empty(q)))
        return false;

    const uint64_t qlen = w_iov_sq_len(q);
    const uint64_t qcnt = w_iov_sq_cnt(q);
    warn(WRN,
         "writing %" PRIu64 " byte%s in %" PRIu64
         " buf%s on %s conn %s strm " FMT_SID " %s",
         qlen, plural(qlen), qcnt, plural(qcnt), conn_type(c), cid2str(c->scid),
         s->id, fin ? "and closing" : "");

    if (s->state >= strm_hclo) {
        warn(ERR, "%s conn %s strm " FMT_SID " is in state %s, can't write",
             conn_type(c), cid2str(c->scid), s->id, strm_state_str[s->state]);
        return false;
    }

    // add to stream
    if (fin)
        mark_fin(q);
    const uint64_t prev_out_data = s->out_data;
    concat_out(s, q);

#ifndef NDEBUG
    struct timespec before;
    clock_gettime(CLOCK_MONOTONIC, &before);
#endif

    // kick TX watcher
    ev_feed_event(loop, &c->tx_w, 0);
    loop_run(q_write, s->c, s);

#ifndef NDEBUG
    struct timespec after;
    struct timespec diff;
    clock_gettime(CLOCK_MONOTONIC, &after);
    timespec_sub(&after, &before, &diff);
    const double elapsed = timespec_to_double(diff);
#endif

    // how much data did we write?
    const uint64_t data_written =
        s->out_una && meta(s->out_una).udp_len
            ? meta(s->out_una).stream_off - prev_out_data
            : qlen;

    // move data back
    sq_concat(q, &s->out);

    if (fin)
        strm_to_state(s, s->state == strm_hcrm ? strm_clsd : strm_hclo);

    warn(WRN,
         "wrote %" PRIu64 " byte%s in %.3f sec (%s) on %s conn %s strm " FMT_SID
         " %s",
         data_written, plural(data_written), elapsed,
         bps(data_written, elapsed), conn_type(c), cid2str(c->scid), s->id,
         fin ? "and closed" : "");

    // TODO these can be removed eventually
    ensure(w_iov_sq_len(q) == qlen,
           "payload corrupted, %" PRIu64 " != %" PRIu64 "", w_iov_sq_len(q),
           qlen);
    ensure(w_iov_sq_cnt(q) == qcnt,
           "payload corrupted, %" PRIu64 " != %" PRIu64 "", w_iov_sq_cnt(q),
           qcnt);

    return data_written == qlen;
}


struct q_stream *
q_read(struct q_conn * const c, struct w_iov_sq * const q, const bool block)
{
    if (c->state == conn_clsd)
        return 0;

    warn(WRN, "%sblocking read on %s conn %s", block ? "" : "non-",
         conn_type(c), cid2str(c->scid));

#ifndef NDEBUG
    struct timespec before;
    clock_gettime(CLOCK_MONOTONIC, &before);
#endif

again:;
    struct q_stream * s = 0;
    if (c->state == conn_estb) {
        kh_foreach_value(c->streams_by_id, s, {
            if (!sq_empty(&s->in) && s->state != strm_clsd)
                // we found a stream with queued data
                break;
        });

        if (s == 0 && block) {
            // no data queued on any stream, wait for new data
            warn(WRN, "waiting for data on any stream on %s conn %s",
                 conn_type(c), cid2str(c->scid));
            loop_run(q_read, c, 0);
            goto again;
        }
    }

#ifndef NDEBUG
    struct timespec after;
    struct timespec diff;
    clock_gettime(CLOCK_MONOTONIC, &after);
    timespec_sub(&after, &before, &diff);
    const double elapsed = timespec_to_double(diff);
#endif

    if (s) {
        // return data
        sq_concat(q, &s->in);

        warn(WRN,
             "read %" PRIu64
             " byte%s in %.3f sec (%s) on %s conn %s strm " FMT_SID,
             w_iov_sq_len(q), plural(w_iov_sq_len(q)), elapsed,
             bps(w_iov_sq_len(q), elapsed), conn_type(c), cid2str(c->scid),
             s->id);
    }

    return s;
}


void q_readall_stream(struct q_stream * const s, struct w_iov_sq * const q)
{
    struct q_conn * const c = s->c;

#ifndef NDEBUG
    struct timespec before;
    clock_gettime(CLOCK_MONOTONIC, &before);
#endif

    while (c->state == conn_estb && s->state != strm_hcrm &&
           s->state != strm_clsd) {
        warn(WRN, "reading all on %s conn %s strm " FMT_SID, conn_type(c),
             cid2str(c->scid), s->id);
        loop_run(q_readall_stream, c, s);
    }

#ifndef NDEBUG
    struct timespec after;
    struct timespec diff;
    clock_gettime(CLOCK_MONOTONIC, &after);
    timespec_sub(&after, &before, &diff);
    const double elapsed = timespec_to_double(diff);
#endif

    if (!sq_empty(&s->in)) {
        struct w_iov * const last = sq_last(&s->in, w_iov, next);
        const struct pkt_meta * const m_last = &meta(last);
        warn(WRN,
             "read %" PRIu64
             " byte%s in %.3f sec (%s) on %s conn %s strm " FMT_SID " %s",
             w_iov_sq_len(&s->in), plural(w_iov_sq_len(&s->in)), elapsed,
             bps(w_iov_sq_len(&s->in), elapsed), conn_type(c), cid2str(c->scid),
             s->id, m_last->is_fin ? "" : "(FIN missing)");

        if (m_last->is_fin)
            // return data
            sq_concat(q, &s->in);
    }
}


struct q_conn * q_bind(struct w_engine * const w, const uint16_t port)
{
    // bind socket and create new embryonic server connection
    struct q_conn * const c = new_conn(w, 0, 0, 0, 0, 0, htons(port), 0);
    if (likely(c))
        warn(INF, "bound %s socket to port %u", conn_type(c), port);
    return c;
}


static void __attribute__((nonnull))
cancel_api_call(struct ev_loop * const l __attribute__((unused)),
                ev_timer * const w __attribute__((unused)),
                int e __attribute__((unused)))
{
    warn(DBG, "canceling API call");
    ev_timer_stop(loop, &api_alarm);
    maybe_api_return(q_accept, 0, 0);
    maybe_api_return(q_ready, 0, 0);
}


struct q_conn * q_accept(const struct q_conn_conf * const conf)
{
    if (sl_first(&accept_queue))
        goto accept;

    warn(WRN, "waiting for conn on any serv sock (timeout %f sec)",
         conf ? (double)conf->idle_timeout / MSECS_PER_SEC : 0);

    if (conf && conf->idle_timeout) {
        if (ev_is_active(&api_alarm))
            ev_timer_stop(loop, &api_alarm);
        ev_timer_init(&api_alarm, cancel_api_call,
                      (double)conf->idle_timeout / MSECS_PER_SEC, 0);
        ev_timer_start(loop, &api_alarm);
    }

    loop_run(q_accept, 0, 0);

    if (sl_empty(&accept_queue)) {
        warn(ERR, "no conn ready for accept");
        return 0;
    }

accept:;
    struct q_conn * const c = sl_first(&accept_queue);
    sl_remove_head(&accept_queue, node_aq);
    ev_timer_again(loop, &c->idle_alarm);
    c->needs_accept = false;

#ifndef NDEBUG
    char ip[NI_MAXHOST];
    char port[NI_MAXSERV];
    ensure(getnameinfo((struct sockaddr *)&c->peer, sizeof(c->peer), ip,
                       sizeof(ip), port, sizeof(port),
                       NI_NUMERICHOST | NI_NUMERICSERV) == 0,
           "getnameinfo");

    struct pn_data * const pnd = &c->pns[pn_data].data;
    warn(WRN, "%s conn %s accepted from clnt %s:%s%s, cipher %s", conn_type(c),
         cid2str(c->scid), ip, port, c->did_0rtt ? " after 0-RTT" : "",
         pnd->out_1rtt[pnd->out_kyph].aead->algo->name);
#endif

    update_conf(c, conf);
    return c;
}


struct q_stream * q_rsv_stream(struct q_conn * const c, const bool bidi)
{
    if (unlikely(c->state == conn_drng || c->state == conn_clsd))
        return 0;

    const uint64_t * const max_streams =
        bidi ? &c->tp_out.max_streams_bidi : &c->tp_out.max_streams_uni;

    if (unlikely(*max_streams == 0))
        warn(WRN, "peer hasn't allowed %s streams", bidi ? "bi" : "uni");

    int64_t * const next_sid = bidi ? &c->next_sid_bidi : &c->next_sid_uni;
    const uint64_t next = (uint64_t)(*next_sid >> 2);
    if (unlikely(next >= *max_streams)) {
        // we hit the max stream limit, wait for MAX_STREAMS frame
        warn(WRN, "need %s MAX_STREAMS increase (%" PRIu64 " >= %" PRIu64 ")",
             bidi ? "bi" : "uni", next, *max_streams);
        if (bidi)
            c->sid_blocked_bidi = true;
        else
            c->sid_blocked_uni = true;
        loop_run(q_rsv_stream, c, 0);
    }

    // stream blocking is handled by new_stream
    return new_stream(c, *next_sid);
}


#if !defined(FUZZING) && defined(__linux__)
static void __attribute__((noreturn))
signal_cb(struct ev_loop * l,
          ev_signal * w,
          int revents __attribute__((unused)))
{
    ev_break(l, EVBREAK_ALL);
    w_cleanup(w->data);
    exit(0);
}
#endif


#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
static int __attribute__((nonnull))
mk_or_open_dir(const char * const path, mode_t mode)
{
    int fd = mkdir(path, mode);
    ensure(fd == 0 || fd == -1 && errno == EEXIST, "mkdir %s", path);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    ensure(fd != -1, "open %s", path);
    return fd;
}
#endif


struct w_engine * q_init(const char * const ifname,
                         const struct q_conf * const conf)
{
    // check versions
    // ensure(WARPCORE_VERSION_MAJOR == 0 && WARPCORE_VERSION_MINOR == 12,
    //        "%s version %s not compatible with %s version %s", quant_name,
    //        quant_version, warpcore_name, warpcore_version);

    // init connection structures
    conns_by_ipnp = kh_init(conns_by_ipnp);
    conns_by_id = kh_init(conns_by_id);
    conns_by_srt = kh_init(conns_by_srt);

    // initialize warpcore on the given interface
    num_bufs = conf && conf->num_bufs ? conf->num_bufs : 10000;
    struct w_engine * const w = w_init(ifname, 0, num_bufs);
    const uint64_t num_bufs_ok = sq_len(&w->iov);
    if (num_bufs_ok < num_bufs)
        warn(WRN, "only allocated %" PRIu64 "/%" PRIu64 " warpcore buffers",
             num_bufs_ok, num_bufs);
    pkt_meta = calloc(num_bufs, sizeof(*pkt_meta));
    ensure(pkt_meta, "could not calloc");
    ASAN_POISON_MEMORY_REGION(pkt_meta, num_bufs * sizeof(*pkt_meta));

    // initialize the event loop (prefer kqueue and epoll)
    loop = ev_default_loop(ev_recommended_backends() | EVBACKEND_KQUEUE |
                           EVBACKEND_EPOLL);

#ifndef NDEBUG
    static const char * ev_backend_str[] = {
        [EVBACKEND_SELECT] = "select",   [EVBACKEND_POLL] = "poll",
        [EVBACKEND_EPOLL] = "epoll",     [EVBACKEND_KQUEUE] = "kqueue",
        [EVBACKEND_DEVPOLL] = "devpoll", [EVBACKEND_PORT] = "port"};
#endif

    warn(INF, "%s/%s %s/%s with libev/%s %u.%u ready", quant_name,
         w->backend_name, quant_version, QUANT_COMMIT_HASH_ABBREV_STR,
         ev_backend_str[ev_backend(loop)], ev_version_major(),
         ev_version_minor());
    warn(INF, "submit bug reports at https://github.com/NTAP/quant/issues");

    // initialize TLS context
    init_tls_ctx(conf);

#if !defined(FUZZING) && defined(__linux__)
    // libev seems to need this inside docker to handle Ctrl-C?
    /// but the fuzzer doesn't like it
    static ev_signal signal_w;
    signal_w.data = w;
    ev_signal_init(&signal_w, signal_cb, SIGINT);
    ev_signal_start(loop, &signal_w);
#endif

#if !defined(NDEBUG) && !defined(NO_FUZZER_CORPUS_COLLECTION)
#ifdef FUZZING
    warn(CRT, "%s compiled for fuzzing - will not communicate", quant_name);
#else
    // create the directories for exporting fuzzer corpus data
    warn(NTE, "debug build, storing fuzzer corpus data");
    corpus_pkt_dir = mk_or_open_dir("../corpus_pkt", 0755);
    corpus_frm_dir = mk_or_open_dir("../corpus_frm", 0755);
#endif
#endif

    return w;
}


void q_close_stream(struct q_stream * const s)
{
    if (s->state != strm_clsd && s->c->state != conn_clsd) {
        struct q_conn * const c = s->c;
        warn(WRN, "closing strm " FMT_SID " on %s conn %s", s->id, conn_type(c),
             cid2str(c->scid));

        if (sq_empty(&s->out)) {
            struct w_iov_sq q = w_iov_sq_initializer(q);
            alloc_off(c->w, &q, 1, DATA_OFFSET);
            struct w_iov * const last = sq_last(&q, w_iov, next);
            ensure(last, "got last buffer");
            last->len = 0;
            concat_out(s, &q);
        }
        mark_fin(&s->out);
        s->state = (s->state == strm_hcrm ? strm_clsd : strm_hclo);

        ev_feed_event(loop, &c->tx_w, 0);
        loop_run(q_close_stream, c, s);
    }

    free_stream(s);
}


void q_free_stream(struct q_stream * const s)
{
    free_stream(s);
}


void q_close(struct q_conn * const c,
             const uint16_t code,
             const char * const reason)
{
    if (c->scid)
        warn(WRN, "closing %s conn %s on port %u w/err %s0x%04x%s%s%s" NRM,
             conn_type(c), cid2str(c->scid), ntohs(get_sport(c->sock)),
             code ? RED : NRM, code, reason ? " (" : "", reason ? reason : "",
             reason ? ")" : "");

    c->err_code = code;
    if (reason) {
        strncpy(c->err_reason, reason, MAX_ERR_REASON_LEN);
        c->err_reason_len = (uint8_t)strnlen(reason, MAX_ERR_REASON_LEN);
    }

    if (c->state == conn_idle || c->state == conn_clsd ||
        (!c->is_clnt && c->holds_sock))
        // we don't need to do the closing dance in these cases
        goto done;

    if (c->state != conn_drng) {
        conn_to_state(c, conn_qlse);
        ev_feed_event(loop, &c->tx_w, 0);
    }

    loop_run(q_close, c, 0);

done:
    if (c->scid) {
        conn_info_populate(c);
        warn(INF, "%s conn %s stats:", conn_type(c), cid2str(c->scid));
        warn(INF, "\tpkts_in_valid = %s%" PRIu64 NRM,
             c->i.pkts_in_valid ? NRM : BLD RED, c->i.pkts_in_valid);
        warn(INF, "\tpkts_in_invalid = %s%" PRIu64 NRM,
             c->i.pkts_in_invalid ? BLD RED : NRM, c->i.pkts_in_invalid);
        warn(INF, "\tpkts_out = %" PRIu64, c->i.pkts_out);
        warn(INF, "\tpkts_out_lost = %" PRIu64, c->i.pkts_out_lost);
        warn(INF, "\tpkts_out_rtx = %" PRIu64, c->i.pkts_out_rtx);
        warn(INF, "\trtt = %.3f", c->i.rtt);
        warn(INF, "\trttvar = %.3f", c->i.rttvar);
        warn(INF, "\tcwnd = %" PRIu64, c->i.cwnd);
        warn(INF, "\tssthresh = %" PRIu64, c->i.ssthresh);
        warn(INF, "\tpto_cnt = %" PRIu64, c->i.pto_cnt);
    }
    free_conn(c);
}


void q_cleanup(struct w_engine * const w)
{
    // close all connections
    struct q_conn * c;
    kh_foreach_value(conns_by_id, c, { q_close(c, 0, 0); });
    kh_foreach_value(conns_by_ipnp, c, { q_close(c, 0, 0); });
    kh_foreach_value(conns_by_srt, c, { q_close(c, 0, 0); });

    // stop the event loop
    ev_loop_destroy(loop);

    free_tls_ctx();

    // free 0-RTT reordering cache
    while (!splay_empty(&ooo_0rtt_by_cid)) {
        struct ooo_0rtt * const zo =
            splay_min(ooo_0rtt_by_cid, &ooo_0rtt_by_cid);
        ensure(splay_remove(ooo_0rtt_by_cid, &ooo_0rtt_by_cid, zo), "removed");
        free(zo);
    }

#ifdef HAVE_ASAN
    for (uint64_t i = 0; i < num_bufs; i++) {
        struct pkt_meta * const m = &pkt_meta[i];
        if (__asan_address_is_poisoned(m) == false) {
            warn(DBG,
                 "buffer %" PRIu64 " still in use for %cX'ed %s pkt %" PRIu64,
                 i, m->txed ? 'T' : 'R',
                 pkt_type_str(m->hdr.flags, &m->hdr.vers),
                 has_pkt_nr(m->hdr.flags, m->hdr.vers) ? m->hdr.nr : 0);
        }
    }
#endif

    kh_destroy(conns_by_id, conns_by_id);
    kh_destroy(conns_by_ipnp, conns_by_ipnp);
    kh_destroy(conns_by_srt, conns_by_srt);

    free(pkt_meta);
    w_cleanup(w);

#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
    close(corpus_pkt_dir);
    close(corpus_frm_dir);
#endif
}


char * q_cid(struct q_conn * const c)
{
    return cid2str(c->scid);
}


uint64_t q_sid(const struct q_stream * const s)
{
    return (uint64_t)s->id;
}


bool q_is_stream_closed(const struct q_stream * const s)
{
    return s->state == strm_clsd;
}


bool q_is_conn_closed(const struct q_conn * const c)
{
    return c->state == conn_clsd;
}


#if !defined(NDEBUG) && !defined(FUZZING) &&                                   \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
void write_to_corpus(const int dir, const void * const data, const size_t len)
{
    char file[MAXPATHLEN];
    const uint64_t rand = w_rand();
    strncpy(file, hex2str(&rand, sizeof(rand)), MAXPATHLEN);
    const int fd =
        openat(dir, file, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0644);
    if (fd == -1) {
        warn(ERR, "cannot open corpus file %s", file);
        goto done;
    }
    if (write(fd, data, len) == -1) {
        warn(ERR, "cannot write corpus file %s", file);
        goto done;
    }
done:
    close(fd);
}
#endif


struct q_conn * q_ready(const uint64_t timeout)
{
    if (sl_empty(&c_ready)) {
        if (timeout) {
            if (ev_is_active(&api_alarm))
                ev_timer_stop(loop, &api_alarm);
            ev_timer_init(&api_alarm, cancel_api_call,
                          (double)timeout / MSECS_PER_SEC, 0);
            ev_timer_start(loop, &api_alarm);
        }
        warn(WRN, "waiting for conn to get ready");
        loop_run(q_ready, 0, 0);
    }

    struct q_conn * const c = sl_first(&c_ready);
    if (c) {
        sl_remove_head(&c_ready, node_rx_ext);
        c->have_new_data = c->in_c_ready = false;
        char * op = "rx";
        if (c->needs_accept)
            op = "accept";
        else if (c->state == conn_clsd)
            op = "close";
        warn(WRN, "%s conn %s ready to %s", conn_type(c), cid2str(c->scid), op);
    } else
        warn(WRN, "no conn ready to rx");

    return c;
}


bool q_is_new_serv_conn(const struct q_conn * const c)
{
    return c->needs_accept;
}


void q_rebind_sock(struct q_conn * const c, const bool use_new_dcid)
{
    ensure(c->is_clnt, "can only rebind w_sock on client");

    struct w_sock * const new_sock = w_bind(c->w, 0, &c->sockopt);
    if (new_sock == 0)
        // could not open new w_sock, can't rebind
        return;

#ifndef NDEBUG
    char old_ip[NI_MAXHOST];
    char old_port[NI_MAXSERV];
    const struct sockaddr * src = w_get_addr(c->sock, true);
    ensure(getnameinfo(src, sizeof(*src), old_ip, sizeof(old_ip), old_port,
                       sizeof(old_port), NI_NUMERICHOST | NI_NUMERICSERV) == 0,
           "getnameinfo");
#endif

    // close the current w_sock
    ev_io_stop(loop, &c->rx_w);
    if (c->scid == 0)
        conns_by_ipnp_del(c);
    w_close(c->sock);

    // switch to new w_sock
    c->rx_w.data = c->sock = new_sock;
    ev_io_init(&c->rx_w, rx, w_fd(c->sock), EV_READ);
    ev_set_priority(&c->rx_w, EV_MAXPRI);
    ev_io_start(loop, &c->rx_w);
    w_connect(c->sock, (struct sockaddr *)&c->peer);
    if (c->scid == 0)
        conns_by_ipnp_ins(c);

    if (use_new_dcid)
        // switch to new dcid
        use_next_dcid(c);

#ifndef NDEBUG
    char new_ip[NI_MAXHOST];
    char new_port[NI_MAXSERV];
    src = w_get_addr(c->sock, true);
    ensure(getnameinfo(src, sizeof(*src), new_ip, sizeof(new_ip), new_port,
                       sizeof(new_port), NI_NUMERICHOST | NI_NUMERICSERV) == 0,
           "getnameinfo");

    warn(NTE, "simulated %s for %s conn %s from %s:%s to %s:%s",
         use_new_dcid ? "conn migration" : "NAT rebinding", conn_type(c),
         cid2str(c->scid), old_ip, old_port, new_ip, new_port);
#endif

    ev_feed_event(loop, &c->tx_w, 1);
}


void q_info(struct q_conn * const c, struct q_conn_info * const ci)
{
    conn_info_populate(c);
    memcpy(ci, &c->i, sizeof(*ci));
}


int cids_by_seq_cmp(const struct cid * const a, const struct cid * const b)
{
    return (a->seq > b->seq) - (a->seq < b->seq);
}


void cid_cpy(struct cid * const dst, const struct cid * const src)
{
    memcpy((uint8_t *)dst + offsetof(struct cid, seq),
           (const uint8_t *)src + offsetof(struct cid, seq),
           sizeof(struct cid) - offsetof(struct cid, seq) -
               sizeof(src->_unused));
}


void pm_cpy(struct pkt_meta * const dst,
            const struct pkt_meta * const src,
            const bool also_frame_info)
{
    const size_t off = also_frame_info ? offsetof(struct pkt_meta, stream)
                                       : offsetof(struct pkt_meta, tx_t);
    memcpy((uint8_t *)dst + off, (const uint8_t *)src + off,
           sizeof(*dst) - off);
}


int ooo_by_off_cmp(const struct pkt_meta * const a,
                   const struct pkt_meta * const b)
{
    return (a->stream_off > b->stream_off) - (a->stream_off < b->stream_off);
}


void adj_iov_to_start(struct w_iov * const v, const struct pkt_meta * const m)
{
    v->buf -= m->stream_data_start;
    v->len += m->stream_data_start;
}


void adj_iov_to_data(struct w_iov * const v, const struct pkt_meta * const m)
{
    v->buf += m->stream_data_start;
    v->len -= m->stream_data_start;
}
