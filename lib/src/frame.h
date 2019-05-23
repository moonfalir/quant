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

#include <stdbool.h>
#include <stdint.h>

#include "bitset.h"

struct pn_space;
struct q_conn;
struct q_stream;
struct w_iov;
struct cid;


#define FRM_PAD 0x00 ///< PADDING
#define FRM_PNG 0x01 ///< PING
#define FRM_ACK 0x02 ///< ACK (only type encoded in the frames bitstr_t)
#define FRM_ACE 0x03 ///< ACK w/ECN
#define FRM_RST 0x04 ///< RESET_STREAM
#define FRM_STP 0x05 ///< STOP_SENDING
#define FRM_CRY 0x06 ///< CRYPTO
#define FRM_TOK 0x07 ///< NEW_TOKEN
#define FRM_STR 0x08 ///< STREAM (only type encoded in the frames bitstr_t)
#define FRM_STR_09 0x09
#define FRM_STR_0a 0x0a
#define FRM_STR_0b 0x0b
#define FRM_STR_0c 0x0c
#define FRM_STR_0d 0x0d
#define FRM_STR_0e 0x0e
#define FRM_STR_0f 0x0f
#define FRM_STR_MAX FRM_STR_0f
#define FRM_MCD 0x10 ///< MAX_DATA (connection)
#define FRM_MSD 0x11 ///< MAX_STREAM_DATA
#define FRM_MSB 0x12 ///< MAX_STREAMS (bidirectional)
#define FRM_MSU 0x13 ///< MAX_STREAMS (unidirectional)
#define FRM_CDB 0x14 ///< (connection) DATA_BLOCKED
#define FRM_SDB 0x15 ///< STREAM_DATA_BLOCKED
#define FRM_SBB 0x16 ///< STREAMS_BLOCKED (bidirectional)
#define FRM_SBU 0x17 ///< STREAMS_BLOCKED (unidirectional)
#define FRM_CID 0x18 ///< NEW_CONNECTION_ID
#define FRM_RTR 0x19 ///< RETIRE_CONNECTION_ID
#define FRM_PCL 0x1a ///< PATH_CHALLENGE
#define FRM_PRP 0x1b ///< PATH_RESPONSE
#define FRM_CLQ 0x1c ///< CONNECTION_CLOSE (QUIC layer)
#define FRM_CLA 0x1d ///< CONNECTION_CLOSE (application)

#define FRM_MAX (FRM_CLA + 1)

bitset_define(frames, FRM_MAX);

#define F_STREAM_FIN 0x01
#define F_STREAM_LEN 0x02
#define F_STREAM_OFF 0x04

#ifndef NDEBUG
#define FRAM_IN BLD BLU
#define FRAM_OUT BLD GRN
#endif

#define has_frame(frames, type) bit_isset(FRM_MAX, (type), &(frames))

struct pkt_meta;

#ifdef NDEBUG
#define log_stream_or_crypto_frame(...)                                        \
    do {                                                                       \
    } while (0)
#else
extern void __attribute__((nonnull(2)))
log_stream_or_crypto_frame(const bool is_rtx,
                           const struct pkt_meta * const m,
                           const uint8_t fl,
                           const int64_t sid,
                           const bool in,
                           const char * const kind);
#endif

extern bool __attribute__((nonnull))
dec_frames(struct q_conn * const c, struct w_iov ** vv, struct pkt_meta ** mm);

extern uint16_t __attribute__((const)) max_frame_len(const uint8_t type);

extern void __attribute__((nonnull))
enc_padding_frame(uint8_t ** pos,
                  const uint8_t * const end,
                  struct pkt_meta * const m,
                  const uint16_t len);

extern void __attribute__((nonnull)) enc_ack_frame(uint8_t ** pos,
                                                   const uint8_t * const start,
                                                   const uint8_t * const end,
                                                   struct pkt_meta * const m,
                                                   struct pn_space * const pn);

extern void __attribute__((nonnull))
enc_stream_or_crypto_frame(uint8_t ** pos,
                           const uint8_t * const end,
                           struct pkt_meta * const m,
                           struct w_iov * const v,
                           struct q_stream * const s,
                           const bool enc_strm);

extern void __attribute__((nonnull)) enc_close_frame(uint8_t ** pos,
                                                     const uint8_t * const end,
                                                     struct pkt_meta * const m);

extern void __attribute__((nonnull))
enc_path_response_frame(uint8_t ** pos,
                        const uint8_t * const end,
                        struct pkt_meta * const m);

extern void __attribute__((nonnull))
enc_max_stream_data_frame(uint8_t ** pos,
                          const uint8_t * const end,
                          struct pkt_meta * const m,
                          struct q_stream * const s);

extern void __attribute__((nonnull))
enc_max_data_frame(uint8_t ** pos,
                   const uint8_t * const end,
                   struct pkt_meta * const m);

extern void __attribute__((nonnull))
enc_max_streams_frame(uint8_t ** pos,
                      const uint8_t * const end,
                      struct pkt_meta * const m,
                      const bool bidi);

extern void __attribute__((nonnull))
enc_stream_data_blocked_frame(uint8_t ** pos,
                              const uint8_t * const end,
                              struct pkt_meta * const m,
                              struct q_stream * const s);

extern void __attribute__((nonnull))
enc_data_blocked_frame(uint8_t ** pos,
                       const uint8_t * const end,
                       struct pkt_meta * const m);

extern void __attribute__((nonnull))
enc_streams_blocked_frame(uint8_t ** pos,
                          const uint8_t * const end,
                          struct pkt_meta * const m,
                          const bool bidi);

extern void __attribute__((nonnull))
enc_path_challenge_frame(uint8_t ** pos,
                         const uint8_t * const end,
                         struct pkt_meta * const m);

extern void __attribute__((nonnull))
enc_new_cid_frame(uint8_t ** pos,
                  const uint8_t * const end,
                  struct pkt_meta * const m);

extern void __attribute__((nonnull))
enc_new_token_frame(uint8_t ** pos,
                    const uint8_t * const end,
                    struct pkt_meta * const m);

extern void __attribute__((nonnull))
enc_retire_cid_frame(uint8_t ** pos,
                     const uint8_t * const end,
                     struct pkt_meta * const m,
                     struct cid * const dcid);

extern void __attribute__((nonnull)) enc_ping_frame(uint8_t ** pos,
                                                    const uint8_t * const end,
                                                    struct pkt_meta * const m);

extern bool __attribute__((nonnull))
is_ack_eliciting(const struct frames * const f);
