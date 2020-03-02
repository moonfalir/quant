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

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef NO_TLS_LOG
#include <stdarg.h>
#endif

#ifndef NO_SERVER
#include <sys/param.h>
#endif

#ifdef WITH_OPENSSL
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <picotls/openssl.h>

#define cipher_suite ptls_openssl_cipher_suites
#define aes128gcmsha256 ptls_openssl_aes128gcmsha256
#define secp256r1 ptls_openssl_secp256r1
#ifndef MINIMAL_CIPHERS
#define x25519 ptls_openssl_x25519
#endif
#else
#include <picotls/minicrypto.h>

#ifndef MINIMAL_CIPHERS
#define cipher_suite ptls_minicrypto_cipher_suites
#define x25519 ptls_minicrypto_x25519
#else
static const ptls_cipher_suite_t * cipher_suite[] = {
    &ptls_minicrypto_aes128gcmsha256, 0};
#endif

#define aes128gcmsha256 ptls_minicrypto_aes128gcmsha256
#define secp256r1 ptls_minicrypto_secp256r1
#endif

#include <quant/quant.h>


#if defined(PARTICLE) || defined(RIOT_VERSION)
#if defined(PARTICLE)
#define MAXPATHLEN 8
#endif

#include <uECC.h>

void ptls_minicrypto_random_bytes(void * buf, size_t len)
{
    while (len >= sizeof(uint32_t)) {
        *((uint32_t *)buf) = w_rand32();
        buf += sizeof(uint32_t);
        len -= sizeof(uint32_t);
    }
    while (len > 0) {
        *((uint8_t *)buf) = w_rand32();
        buf += sizeof(uint8_t);
        len -= sizeof(uint8_t);
    }
}


static int uecc_rng(uint8_t * dest, unsigned size)
{
    ptls_minicrypto_random_bytes(dest, size);
    return 1;
}
#endif


#include "bitset.h"
#include "conn.h"
#include "frame.h"
#include "marshall.h"
#include "pkt.h"
#include "pn.h"
#include "quic.h"
#include "stream.h"
#include "tls.h"


struct tls_ticket {
#if !defined(PARTICLE) && !defined(RIOT_VERSION)
    splay_entry(tls_ticket) node;
#endif
    char * sni;
    char * alpn;
    uint8_t * ticket;
    size_t ticket_len;
    struct transport_params tp;
    uint32_t vers;
    uint8_t _unused[12];
};


struct tickets_by_peer {
#if !defined(PARTICLE) && !defined(RIOT_VERSION)
    splay_head(, tls_ticket);
#else
    struct tls_ticket last_ticket;
#endif
};

static struct tickets_by_peer tickets;


#if !defined(PARTICLE) && !defined(RIOT_VERSION)
static int __attribute__((nonnull))
tls_ticket_cmp(const struct tls_ticket * const a,
               const struct tls_ticket * const b)
{
    int diff = strcmp(a->sni, b->sni);
    if (diff)
        return diff;

    diff = strcmp(a->alpn, b->alpn);
    return diff;
}


SPLAY_PROTOTYPE(tickets_by_peer, tls_ticket, node, tls_ticket_cmp)
SPLAY_GENERATE(tickets_by_peer, tls_ticket, node, tls_ticket_cmp)
#endif


// first entry is client default, if not otherwise specified
// last entry should be h3-, since we ignore that in on_ch
static const ptls_iovec_t alpn[] = {{(uint8_t *)"hq-" DRAFT_VERSION_STRING, 5},
                                    {(uint8_t *)"h3-" DRAFT_VERSION_STRING, 5}};
static const size_t alpn_cnt = sizeof(alpn) / sizeof(alpn[0]);


#define QUIC_TP 0xffa5

#define TP_OCID 0x00    ///< original_connection_id
#define TP_IDTO 0x01    ///< idle_timeout
#define TP_SRT 0x02     ///< stateless_reset_token
#define TP_MPS 0x03     ///< max_packet_size
#define TP_IMD 0x04     ///< initial_max_data
#define TP_IMSD_BL 0x05 ///< initial_max_stream_data_bidi_local
#define TP_IMSD_BR 0x06 ///< initial_max_stream_data_bidi_remote
#define TP_IMSD_U 0x07  ///< initial_max_stream_data_uni
#define TP_IMSB 0x08    ///< initial_max_streams_bidi
#define TP_IMSU 0x09    ///< initial_max_streams_uni
#define TP_ADE 0x0a     ///< ack_delay_exponent
#define TP_MAD 0x0b     ///< max_ack_delay
#define TP_DMIG 0x0c    ///< disable_active_migration
#define TP_PRFA 0x0d    ///< preferred_address
#define TP_ACIL 0x0e    ///< active_connection_id_limit
#define TP_MAX (TP_ACIL + 1)

#define TP_QR 3127


// quicly shim
#define AEAD_BASE_LABEL PTLS_HKDF_EXPAND_LABEL_PREFIX "quic "
#define st_quicly_cipher_context_t cipher_ctx


// from quicly
void dispose_cipher(struct st_quicly_cipher_context_t * ctx)
{
    if (ctx->aead) {
        ptls_aead_free(ctx->aead);
        ctx->aead = 0;
    }
    if (ctx->header_protection) {
        ptls_cipher_free(ctx->header_protection);
        ctx->header_protection = 0;
    }
}


// from quicly (with mods for key update)
static int setup_cipher(ptls_cipher_context_t ** hp_ctx,
                        ptls_aead_context_t ** aead_ctx,
                        ptls_aead_algorithm_t * aead,
                        ptls_hash_algorithm_t * hash,
                        int is_enc,
                        const void * secret)
{
    uint8_t hpkey[PTLS_MAX_SECRET_SIZE] = {0};
    int ret;

    // *hp_ctx = NULL;
    // *aead_ctx = NULL;

    if (hp_ctx) {
        if ((ret = ptls_hkdf_expand_label(
                 hash, hpkey, aead->ctr_cipher->key_size,
                 ptls_iovec_init(secret, hash->digest_size), "quic hp",
                 ptls_iovec_init(NULL, 0), NULL)) != 0)
            goto Exit;
        if ((*hp_ctx = ptls_cipher_new(aead->ctr_cipher, is_enc, hpkey)) ==
            NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
    }
    if ((*aead_ctx = ptls_aead_new(aead, hash, is_enc, secret,
                                   AEAD_BASE_LABEL)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

#ifdef DEBUG_PROT
    warn(NTE, "aead-secret: %s, hp-key: %s",
         hex2str(secret, hash->digest_size,
                 (char[hex_str_len(PTLS_MAX_DIGEST_SIZE)]){""},
                 hex_str_len(PTLS_MAX_DIGEST_SIZE)),
         hex2str(hpkey, aead->ctr_cipher->key_size,
                 (char[hex_str_len(PTLS_MAX_DIGEST_SIZE)]){""},
                 hex_str_len(PTLS_MAX_DIGEST_SIZE)));
#endif

    ret = 0;
Exit:
    if (ret != 0) {
        if (*aead_ctx != NULL) {
            ptls_aead_free(*aead_ctx);
            *aead_ctx = NULL;
        }
        if (hp_ctx && *hp_ctx != NULL) {
            ptls_cipher_free(*hp_ctx);
            *hp_ctx = NULL;
        }
    }
    ptls_clear_memory(hpkey, sizeof(hpkey));
    return ret;
}


// from quicly (with mods for key update)
static int setup_initial_key(struct st_quicly_cipher_context_t * ctx,
                             ptls_cipher_suite_t * cs,
                             const void * master_secret,
                             const char * label,
                             int is_enc,
                             void * new_secret)
{
    uint8_t _aead_secret[PTLS_MAX_DIGEST_SIZE];
    uint8_t * const aead_secret = new_secret ? new_secret : _aead_secret;

    int ret;

    if ((ret = ptls_hkdf_expand_label(
             cs->hash, aead_secret, cs->hash->digest_size,
             ptls_iovec_init(master_secret, cs->hash->digest_size), label,
             ptls_iovec_init(NULL, 0), NULL)) != 0)
        goto Exit;
    if ((ret =
             setup_cipher(new_secret ? 0 : &ctx->header_protection, &ctx->aead,
                          cs->aead, cs->hash, is_enc, aead_secret)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(_aead_secret, sizeof(_aead_secret));
    return ret;
}


// from quicly (with mods to the setup_initial_key call)
static int setup_initial_encryption(struct st_quicly_cipher_context_t * ingress,
                                    struct st_quicly_cipher_context_t * egress,
                                    ptls_cipher_suite_t ** cipher_suites,
                                    ptls_iovec_t cid,
                                    int is_client)
{
    static const uint8_t salt[] = {0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb,
                                   0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4,
                                   0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02};
    static const char * labels[2] = {"client in", "server in"};
    ptls_cipher_suite_t ** cs;
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    /* find aes128gcm cipher */
    for (cs = cipher_suites;; ++cs) {
        assert(cs != NULL);
        if ((*cs)->id == PTLS_CIPHER_SUITE_AES_128_GCM_SHA256)
            break;
    }

    /* extract master secret */
    if ((ret = ptls_hkdf_extract((*cs)->hash, secret,
                                 ptls_iovec_init(salt, sizeof(salt)), cid)) !=
        0)
        goto Exit;

    /* create aead contexts */
    if ((ret = setup_initial_key(ingress, *cs, secret, labels[is_client], 0,
                                 0)) != 0)
        goto Exit;
    if ((ret = setup_initial_key(egress, *cs, secret, labels[!is_client], 1,
                                 0)) != 0)
        goto Exit;

Exit:
    ptls_clear_memory(secret, sizeof(secret));
    return ret;
}


static int __attribute__((nonnull))
on_ch(ptls_on_client_hello_t * const self __attribute__((unused)),
      ptls_t * const tls,
      ptls_on_client_hello_parameters_t * const params)
{
    if (params->server_name.len) {
        // TODO verify the SNI instead of accepting whatever the client sent
        warn(INF, "\tSNI = %.*s", (int)params->server_name.len,
             params->server_name.base);
        ensure(ptls_set_server_name(tls, (const char *)params->server_name.base,
                                    params->server_name.len) == 0,
               "ptls_set_server_name");
    } else
        warn(INF, "\tSNI = ");

    if (params->negotiated_protocols.count == 0) {
        warn(WRN, "\tALPN = ");
        return 0;
    }

    size_t j;
    for (j = 0; j < alpn_cnt - 1; j++)
        for (size_t i = 0; i < params->negotiated_protocols.count; i++)
            if (params->negotiated_protocols.list[i].len == alpn[j].len &&
                memcmp(params->negotiated_protocols.list[i].base, alpn[j].base,
                       alpn[j].len) == 0)
                goto done;

    if (j == alpn_cnt - 1) {
        warn(WRN, RED "\tALPN = %.*s (and maybe others, none supported)" NRM,
             (int)params->negotiated_protocols.list[0].len,
             params->negotiated_protocols.list[0].base);
        return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
    }

done:
    // mark this ALPN as negotiated
    ptls_set_negotiated_protocol(tls, (char *)alpn[j].base, alpn[j].len);
    warn(INF, "\tALPN = %.*s", (int)alpn[j].len, alpn[j].base);

    return 0;
}


static int filter_tp(ptls_t * tls __attribute__((unused)),
                     struct st_ptls_handshake_properties_t * properties
                     __attribute__((unused)),
                     uint16_t type)
{
    return type == QUIC_TP;
}


static bool __attribute__((nonnull))
dec_tp(uint_t * const val, const uint8_t ** pos, const uint8_t * const end)
{
    uint64_t len;
    if (decv(&len, pos, end) == false)
        return false;
    if (len) {
        uint64_t v = 0;
        decv(&v, pos, end);
        *val = (uint_t)v;
    }
    return true;
}


static int chk_tp(ptls_t * tls __attribute__((unused)),
                  ptls_handshake_properties_t * properties,
                  ptls_raw_extension_t * slots)
{
    // get connection based on properties pointer
    struct q_conn * const c =
        (void *)((char *)properties - offsetof(struct tls, tls_hshk_prop) -
                 offsetof(struct q_conn, tls));

    if (unlikely(slots[0].type != QUIC_TP)) {
        err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY, "slots[0].type = 0x%04x",
                  slots[0].type);
        return 1;
    }
    if (unlikely(slots[1].type != UINT16_MAX)) {
        err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY, "slots[1].type = 0x%04x",
                  slots[1].type);
        return 1;
    }

    // set up parsing
    const uint8_t * pos = (const uint8_t *)slots[0].data.base;
    const uint8_t * const end = pos + slots[0].data.len;

    // keep track of which transport parameters we've seen before
    bitset_define(tp_list, TP_MAX);
    struct tp_list tp_list = bitset_t_initializer(0);

    c->tp_peer.act_cid_lim = UINT_T_MAX;
    c->tp_peer.max_pkt = MAX_PKT_LEN;
    while (pos < end) {
        uint64_t tp;
        if (decv(&tp, &pos, end) == false)
            return 1;

        // skip unknown TPs
        if (tp >= TP_MAX) {
            uint64_t unknown_len;
            if (decv(&unknown_len, &pos, end) == false)
                return 1;
            warn(WRN,
                 "\t" BLD "%s tp" NRM " (0x%" PRIx64 " w/len %" PRIu64 ") = %s",
                 (tp & 0xff00) == 0xff00
                     ? YEL "private"
                     : (tp == TP_QR ? RED "quantum-ready" : RED "unknown"),
                 tp, unknown_len,
                 hex2str(pos, unknown_len, (char[16]){""}, 16));
            pos += unknown_len;
            continue;
        }

        // check if this transport parameter is a duplicate
        if (bit_isset(TP_MAX, tp, &tp_list)) {
            err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                      "duplicate tp 0x%04x", tp);
            return 1;
        }
        bit_set(TP_MAX, tp, &tp_list);

        switch (tp) {
        case TP_IMSD_U:
            if (dec_tp(&c->tp_peer.max_strm_data_uni, &pos, end) == false)
                return 1;
            warn(INF, "\tinitial_max_stream_data_uni = %" PRIu " [bytes]",
                 c->tp_peer.max_strm_data_uni);
            break;

        case TP_IMSD_BL:
            if (dec_tp(&c->tp_peer.max_strm_data_bidi_remote, &pos, end) ==
                false)
                return 1;
            warn(INF,
                 "\tinitial_max_stream_data_bidi_local = %" PRIu " [bytes]",
                 c->tp_peer.max_strm_data_bidi_remote);
            break;

        case TP_IMSD_BR:
            // this is RX'ed as _remote, but applies to streams we open, so:
            if (dec_tp(&c->tp_peer.max_strm_data_bidi_local, &pos, end) ==
                false)
                return 1;
            warn(INF,
                 "\tinitial_max_stream_data_bidi_remote = %" PRIu " [bytes]",
                 c->tp_peer.max_strm_data_bidi_local);
            break;

        case TP_IMD:
            if (dec_tp(&c->tp_peer.max_data, &pos, end) == false)
                return 1;
            warn(INF, "\tinitial_max_data = %" PRIu " [bytes]",
                 c->tp_peer.max_data);
            break;

        case TP_IMSB:
            if (dec_tp(&c->tp_peer.max_strms_bidi, &pos, end) == false)
                return 1;
            warn(INF, "\tinitial_max_streams_bidi = %" PRIu,
                 c->tp_peer.max_strms_bidi);
            break;

        case TP_IMSU:
            if (dec_tp(&c->tp_peer.max_strms_uni, &pos, end) == false)
                return 1;
            warn(INF, "\tinitial_max_streams_uni = %" PRIu,
                 c->tp_peer.max_strms_uni);
            break;

        case TP_IDTO:
            if (dec_tp(&c->tp_peer.max_idle_to, &pos, end) == false)
                return 1;
            warn(INF, "\tmax_idle_timeout = %" PRIu " [ms]",
                 c->tp_peer.max_idle_to);
            break;

        case TP_MPS:
            if (dec_tp(&c->tp_peer.max_pkt, &pos, end) == false)
                return 1;
            warn(INF, "\tmax_packet_size = %" PRIu " [bytes]",
                 c->tp_peer.max_pkt);
            if (c->tp_peer.max_pkt < 1200) {
                err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                          "tp_peer.max_pkt %" PRIu " invalid (< 1200)",
                          c->tp_peer.max_pkt);
                return 1;
            }
            break;

        case TP_ADE:
            if (dec_tp(&c->tp_peer.ack_del_exp, &pos, end) == false)
                return 1;
            warn(INF, "\tack_delay_exponent = %" PRIu, c->tp_peer.ack_del_exp);
            if (c->tp_peer.ack_del_exp > 20) {
                err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                          "ack_delay_exponent %" PRIu " invalid",
                          c->tp_peer.ack_del_exp);
                return 1;
            }
            break;

        case TP_MAD:
            if (dec_tp(&c->tp_peer.max_ack_del, &pos, end) == false)
                return 1;
            warn(INF, "\tmax_ack_delay = %" PRIu " [ms]",
                 c->tp_peer.max_ack_del);
            if (c->tp_peer.max_ack_del > (1 << 14)) {
                err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                          "max_ack_delay %" PRIu " invalid",
                          c->tp_peer.max_ack_del);
                return 1;
            }
            break;

        case TP_OCID:
            if (is_clnt(c) == false) {
                err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                          "rx original_connection_id tp at serv");
                return 1;
            }

            uint64_t len;
            if (decv(&len, &pos, end) == false)
                return 1;
            if (len) {
                decb(c->tp_peer.orig_cid.id, &pos, end, (uint16_t)len);
                c->tp_peer.orig_cid.len = (uint8_t)len;
            }
            warn(INF, "\toriginal_connection_id = %s",
                 cid_str(&c->tp_peer.orig_cid));
            break;

        case TP_DMIG:;
            uint_t dmig;
            if (dec_tp(&dmig, &pos, end) == false)
                return 1;
            warn(INF, "\tdisable_active_migration = true");
            c->tp_peer.disable_active_migration = true;
            break;

        case TP_SRT:
            if (is_clnt(c) == false) {
                err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                          "rx stateless_reset_token tp at serv");
                return 1;
            }
            uint64_t l;
            if (decv(&l, &pos, end) == false)
                return 1;
#ifndef NO_SRT_MATCHING
            struct cid * const dcid = c->dcid;
            uint8_t * srt = dcid->srt;
#else
            uint8_t srt[SRT_LEN];
#endif
            if (l != SRT_LEN) {
                err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                          "illegal srt len %u", l);
                return 1;
            }
            decb(srt, &pos, end, SRT_LEN);
            warn(INF, "\tstateless_reset_token = %s", srt_str(srt));
#ifndef NO_SRT_MATCHING
            dcid->has_srt = true;
            conns_by_srt_ins(c, srt);
#endif
            break;

        case TP_PRFA:
            if (decv(&l, &pos, end) == false)
                return 1;
            const uint8_t * const e = pos + l;

            struct pref_addr * const pa = &c->tp_peer.pref_addr;
            struct w_sockaddr * const pa4 = &pa->addr4;
            struct w_sockaddr * const pa6 = &pa->addr6;

            // use decb, since these need to be in network byte-order
            pa4->addr.af = AF_INET;
            decb((uint8_t *)&pa4->addr.ip4, &pos, e, sizeof(pa4->addr.ip4));
            decb((uint8_t *)&pa4->port, &pos, e, sizeof(pa4->port));

            pa6->addr.af = AF_INET6;
            decb((uint8_t *)&pa6->addr.ip6, &pos, e, sizeof(pa6->addr.ip6));
            decb((uint8_t *)&pa6->port, &pos, e, sizeof(pa6->port));

            dec1(&pa->cid.len, &pos, e);
            decb(pa->cid.id, &pos, e, pa->cid.len);
            pa->cid.seq = 1;

#ifndef NO_SRT_MATCHING
            srt = pa->cid.srt;
            pa->cid.has_srt = true;
#endif
            decb(srt, &pos, e, SRT_LEN);
            add_dcid(c, &pa->cid);

            warn(INF,
                 "\tpreferred_address = IPv4=%s:%u IPv6=[%s]:%u cid=%s srt=%s",
                 w_ntop(&pa4->addr, ip_tmp), bswap16(pa4->port),
                 w_ntop(&pa6->addr, ip_tmp), bswap16(pa6->port),
                 cid_str(&pa->cid), srt_str(srt));
            break;

        case TP_ACIL:
            if (dec_tp(&c->tp_peer.act_cid_lim, &pos, end) == false)
                return 1;
            warn(INF, "\tactive_connection_id_limit = %" PRIu,
                 c->tp_peer.act_cid_lim);
            break;

        default:
            err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                      "unsupported tp 0x%04x", tp);
            return 1;
        }
    }

    // if we did a RETRY, check that we got orig_cid and it matches
    if (is_clnt(c) && c->tok_len) {
        if (c->tp_peer.orig_cid.len == 0) {
            err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                      "no original_connection_id tp received");
            return 1;
        }

        if (cid_cmp(&c->tp_peer.orig_cid, &c->odcid)) {
            err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                      "cid/odcid mismatch");
            return 1;
        }
    }

    if (c->tp_peer.disable_active_migration == false) {
        if (c->tp_peer.act_cid_lim == UINT_T_MAX)
            c->tp_peer.act_cid_lim = 2;
        else if (c->tp_peer.act_cid_lim < 2)
            err_close(c, ERR_TRANSPORT_PARAMETER, FRM_CRY,
                      "active_connection_id_limit %" PRIu " < 2",
                      c->tp_peer.act_cid_lim);
    } else
        c->tp_peer.act_cid_lim = 0;

    // apply these parameter to all current non-crypto streams
    struct q_stream * s;
    kh_foreach_value(&c->strms_by_id, s, apply_stream_limits(s));

    return 0;
}


static void __attribute__((nonnull)) enc_tp(uint8_t ** pos,
                                            const uint8_t * const end,
                                            const uint16_t tp,
                                            const uint_t val)
{
    encv(pos, end, tp);
    encv(pos, end, varint_size(val));
    encv(pos, end, val);
}


static void __attribute__((nonnull(1, 2))) encb_tp(uint8_t ** pos,
                                                   const uint8_t * const end,
                                                   const uint16_t tp,
                                                   const uint8_t * const val,
                                                   const uint16_t len)
{
    encv(pos, end, tp);
    encv(pos, end, len);
    if (val)
        encb(pos, end, val, len);
}


void init_tp(struct q_conn * const c)
{
#if !defined(RIOT_VERSION) && !defined(PARTICLE)
#define TP_LEN 4096
#else
#define TP_LEN 192
#endif

    uint8_t * pos = c->tls.tp_buf;
    const uint8_t * end = c->tls.tp_buf + TP_LEN;

    // add a grease tp
    uint8_t grease[18];
    rand_bytes(&grease, sizeof(grease));
    const uint16_t grease_type = 0xff00 + grease[0];
    const uint16_t grease_len = grease[1] & 0x0f;

    // add the quantum-readiness tp
    memset(ped(c->w)->scratch, 'Q', MIN_INI_LEN);

    uint16_t tp_order[] = {TP_OCID,     TP_IDTO,    TP_SRT,    TP_MPS,  TP_IMD,
                           TP_IMSD_BL,  TP_IMSD_BR, TP_IMSD_U, TP_IMSB, TP_IMSU,
                           TP_ADE,      TP_MAD,     TP_DMIG,   TP_PRFA, TP_ACIL,
                           grease_type, TP_QR};
    const size_t tp_cnt = sizeof(tp_order) / sizeof(tp_order[0]);

    // modern version of Fisher-Yates
    // https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#The_modern_algorithm
    for (size_t j = tp_cnt - 1; j >= 1; j--) {
        const size_t r = w_rand_uniform32((uint32_t)j);
        const uint16_t tmp = tp_order[r];
        tp_order[r] = tp_order[j];
        tp_order[j] = tmp;
    }

    for (size_t j = 0; j <= tp_cnt - 1; j++)
        switch (tp_order[j]) {
        case TP_IMSU:
            if (c->tp_mine.max_strms_uni)
                enc_tp(&pos, end, TP_IMSU, c->tp_mine.max_strms_uni);
            break;
        case TP_IMSD_U:
            if (c->tp_mine.max_strm_data_uni) {
                enc_tp(&pos, end, TP_IMSD_U, c->tp_mine.max_strm_data_uni);
#ifdef DEBUG_EXTRA
                warn(INF, "\tinitial_max_stream_data_uni = %" PRIu " [bytes]",
                     c->tp_mine.max_strm_data_uni);
#endif
            }
            break;
        case TP_SRT:
#ifndef NO_SRT_MATCHING
            if (!is_clnt(c)) {
                encb_tp(&pos, end, TP_SRT, c->scid->srt, sizeof(c->scid->srt));
#ifdef DEBUG_EXTRA
                warn(INF, "\tstateless_reset_token = %s",
                     srt_str(c->scid->srt));
#endif
            }
#endif
            break;
        case TP_OCID:
            if (!is_clnt(c) && c->odcid.len) {
                encb_tp(&pos, end, TP_OCID, c->odcid.id, c->odcid.len);
#ifdef DEBUG_EXTRA
                warn(INF, "\toriginal_connection_id = %s",
                     cid_str(&c->tp_mine.orig_cid));
#endif
            }
            break;
        case TP_IMSB:
            enc_tp(&pos, end, TP_IMSB, c->tp_mine.max_strms_bidi);
#ifdef DEBUG_EXTRA
            warn(INF, "\tinitial_max_streams_bidi = %" PRIu,
                 c->tp_mine.max_strms_bidi);
#endif
            break;
        case TP_IDTO:
            if (c->tp_mine.max_idle_to) {
                enc_tp(&pos, end, TP_IDTO, c->tp_mine.max_idle_to);
#ifdef DEBUG_EXTRA
                warn(INF, "\tmax_idle_timeout = %" PRIu " [ms]",
                     c->tp_mine.max_idle_to);
#endif
            }
            break;
        case TP_IMSD_BR:
            enc_tp(&pos, end, TP_IMSD_BR, c->tp_mine.max_strm_data_bidi_remote);
#ifdef DEBUG_EXTRA
            warn(INF,
                 "\tinitial_max_stream_data_bidi_remote = %" PRIu " [bytes]",
                 c->tp_mine.max_strm_data_bidi_remote);
#endif
            break;
        case TP_IMSD_BL:
            enc_tp(&pos, end, TP_IMSD_BL, c->tp_mine.max_strm_data_bidi_local);
#ifdef DEBUG_EXTRA
            warn(INF,
                 "\tinitial_max_stream_data_bidi_local = %" PRIu " [bytes]",
                 c->tp_mine.max_strm_data_bidi_remote);
#endif
            break;
        case TP_IMD:
            enc_tp(&pos, end, TP_IMD, c->tp_mine.max_data);
#ifdef DEBUG_EXTRA
            warn(INF, "\tinitial_max_data = %" PRIu " [bytes]",
                 c->tp_mine.max_data);
#endif
            break;
        case TP_ADE:
            if (c->tp_mine.ack_del_exp != DEF_ACK_DEL_EXP) {
                enc_tp(&pos, end, TP_ADE, c->tp_mine.ack_del_exp);
#ifdef DEBUG_EXTRA
                warn(INF, "\tack_delay_exponent = %" PRIu,
                     c->tp_mine.ack_del_exp);
#endif
            }
            break;
        case TP_MAD:
            if (c->tp_mine.max_ack_del != DEF_MAX_ACK_DEL) {
                enc_tp(&pos, end, TP_MAD, c->tp_mine.max_ack_del);
#ifdef DEBUG_EXTRA
                warn(INF, "\tmax_ack_delay = %" PRIu " [ms]",
                     c->tp_mine.max_ack_del);
#endif
            }
            break;
        case TP_MPS:
            enc_tp(&pos, end, TP_MPS, c->tp_mine.max_pkt);
#ifdef DEBUG_EXTRA
            warn(INF, "\tmax_packet_size = %" PRIu " [bytes]",
                 c->tp_mine.max_pkt);
#endif
            break;
        case TP_ACIL:
            if (c->tp_mine.disable_active_migration == false) {
                enc_tp(&pos, end, TP_ACIL, c->tp_mine.act_cid_lim);
#ifdef DEBUG_EXTRA
                warn(INF, "\tactive_connection_id_limit = %" PRIu,
                     c->tp_mine.act_cid_lim);
#endif
            }
            break;
        case TP_PRFA:;
            struct pref_addr * const pa = &c->tp_mine.pref_addr;
            if (!is_clnt(c) && pa->cid.seq) {
                struct w_sockaddr * const pa4 = &pa->addr4;
                struct w_sockaddr * const pa6 = &pa->addr6;
#ifndef NO_SRT_MATCHING
                uint8_t * srt = pa->cid.srt;
#else
                uint8_t srt[SRT_LEN];
#endif
                encb_tp(&pos, end, TP_PRFA, 0,
                        4 + 2 + 16 + 2 + 1 + pa->cid.len + SRT_LEN);
                // use encb, since these are already in network byte-order
                encb(&pos, end, (uint8_t *)&pa4->addr.ip4,
                     sizeof(pa4->addr.ip4));
                encb(&pos, end, (uint8_t *)&pa4->port, sizeof(pa4->port));
                encb(&pos, end, pa6->addr.ip6, sizeof(pa6->addr.ip6));
                encb(&pos, end, (uint8_t *)&pa6->port, sizeof(pa6->port));
                enc1(&pos, end, pa->cid.len);
                encb(&pos, end, (uint8_t *)pa->cid.id, pa->cid.len);
                encb(&pos, end, srt, SRT_LEN);
#ifdef DEBUG_EXTRA
                warn(INF,
                     "\tpreferred_address = IPv4=%s:%u IPv6=[%s]:%u cid=%s "
                     "srt=%s",
                     w_ntop(&pa4->addr, ip_tmp), bswap16(pa4->port),
                     w_ntop(&pa6->addr, ip_tmp), bswap16(pa6->port),
                     cid_str(&pa->cid), srt_str(srt));
#endif
            }
            break;
        case TP_DMIG:
            if (c->tp_mine.disable_active_migration) {
                enc_tp(&pos, end, TP_DMIG, c->tp_mine.disable_active_migration);
#ifdef DEBUG_EXTRA
                warn(INF, "\tdisable_active_migration = true");
#endif
            }
            break;
        default:
            if (tp_order[j] == grease_type) {
                encb_tp(&pos, end, grease_type, &grease[2], grease_len);
#ifdef DEBUG_EXTRA
                warn(WRN, "\t" BLD "%s tp" NRM " (0x%04x w/len %u) = %s",
                     (grease_type & 0xff00) == 0xff00 ? YEL "private"
                                                      : RED "unknown",
                     grease_type, grease_len,
                     hex2str(&grease[2], grease_len,
                             (char[hex_str_len(TP_LEN)]){""},
                             hex_str_len(TP_LEN)));
#endif
            } else if (tp_order[j] == TP_QR) {
                if (c->do_qr_test) {
                    encb_tp(&pos, end, TP_QR, ped(c->w)->scratch, MIN_INI_LEN);
#ifdef DEBUG_EXTRA
                    warn(WRN,
                         "\t" BLD RED "quantum-ready tp" NRM
                         " (0x%04x w/len %u)",
                         TP_QR, MIN_INI_LEN);
#endif
                }
            } else
                die("unknown tp 0x%04x", tp_order[j]);
            break;
        }

    c->tls.tp_ext[0] = (ptls_raw_extension_t){
        .type = QUIC_TP,
        {.base = c->tls.tp_buf, .len = (uint16_t)(pos - c->tls.tp_buf)}};
    c->tls.tp_ext[1] = (ptls_raw_extension_t){.type = UINT16_MAX};
}


#ifndef NO_SERVER
static void init_ticket_prot(struct per_engine_data * const ped)
{
    const ptls_cipher_suite_t * const cs = &aes128gcmsha256;
    uint8_t output[PTLS_MAX_SECRET_SIZE] = {0};
    memcpy(output, quant_commit_hash,
           MIN(quant_commit_hash_len, sizeof(output)));
    setup_cipher(&ped->dec_tckt.header_protection, &ped->dec_tckt.aead,
                 cs->aead, cs->hash, 0, output);
    setup_cipher(&ped->enc_tckt.header_protection, &ped->enc_tckt.aead,
                 cs->aead, cs->hash, 1, output);
    ptls_clear_memory(output, sizeof(output));
}


static int encrypt_ticket_cb(ptls_encrypt_ticket_t * self
                             __attribute__((unused)),
                             ptls_t * tls,
                             int is_encrypt,
                             ptls_buffer_t * dst,
                             ptls_iovec_t src)
{
    struct q_conn * const c = *ptls_get_data_ptr(tls);
    uint64_t tid;
    if (ptls_buffer_reserve(dst, src.len + quant_commit_hash_len + sizeof(tid) +
                                     ped(c->w)->enc_tckt.aead->algo->tag_size))
        return -1;

    if (is_encrypt) {
        warn(INF, "creating new 0-RTT session ticket for %s conn %s (%s %s)",
             conn_type(c), cid_str(c->scid), ptls_get_server_name(tls),
             ptls_get_negotiated_protocol(tls));

        // prepend git commit hash
        memcpy(dst->base + dst->off, quant_commit_hash, quant_commit_hash_len);
        dst->off += quant_commit_hash_len;

        // prepend ticket id
        rand_bytes(&tid, sizeof(tid));
        memcpy(dst->base + dst->off, &tid, sizeof(tid));
        dst->off += sizeof(tid);

        // now encrypt ticket
        dst->off +=
            ptls_aead_encrypt(ped(c->w)->enc_tckt.aead, dst->base + dst->off,
                              src.base, src.len, tid, 0, 0);

    } else {
        if (src.len < quant_commit_hash_len + sizeof(tid) +
                          ped(c->w)->dec_tckt.aead->algo->tag_size ||
            memcmp(src.base, quant_commit_hash, quant_commit_hash_len) != 0) {
            warn(WRN,
                 "could not verify 0-RTT session ticket for %s conn %s (%s "
                 "%s)",
                 conn_type(c), cid_str(c->scid), ptls_get_server_name(tls),
                 ptls_get_negotiated_protocol(tls));
            c->did_0rtt = false;
            return -1;
        }
        uint8_t * src_base = src.base + quant_commit_hash_len;
        size_t src_len = src.len - quant_commit_hash_len;

        memcpy(&tid, src_base, sizeof(tid));
        src_base += sizeof(tid);
        src_len -= sizeof(tid);

        const size_t n =
            ptls_aead_decrypt(ped(c->w)->dec_tckt.aead, dst->base + dst->off,
                              src_base, src_len, tid, 0, 0);

        if (n > src_len) {
            warn(WRN,
                 "could not decrypt 0-RTT session ticket for %s conn %s "
                 "(%s %s)",
                 conn_type(c), cid_str(c->scid), ptls_get_server_name(tls),
                 ptls_get_negotiated_protocol(tls));
            c->did_0rtt = false;
            return -1;
        }
        dst->off += n;

        warn(INF, "verified 0-RTT session ticket for %s conn %s (%s %s)",
             conn_type(c), cid_str(c->scid), ptls_get_server_name(tls),
             ptls_get_negotiated_protocol(tls));
        c->did_0rtt = true;
    }

    return 0;
}
#endif


static int save_ticket_cb(ptls_save_ticket_t * self __attribute__((unused)),
                          ptls_t * tls,
                          ptls_iovec_t src)
{
    struct q_conn * const c = *ptls_get_data_ptr(tls);

#if !defined(PARTICLE) && !defined(RIOT_VERSION)
    const char * const ticket_store = ped(c->w)->conf.ticket_store;
    warn(NTE, "saving TLS tickets to %s", ticket_store);
    FILE * const fp = fopen(ticket_store, "wbe");
    ensure(fp, "could not open ticket file %s", ticket_store);

    // write git hash
    ensure(fwrite(&quant_commit_hash_len, sizeof(quant_commit_hash_len), 1, fp),
           "fwrite");
    ensure(fwrite(quant_commit_hash, quant_commit_hash_len, 1, fp), "fwrite");
#endif

    char * s = 0;
    if (ptls_get_server_name(tls))
        s = strdup(ptls_get_server_name(tls));
    else
        s = calloc(1, sizeof(char));
    char * a = 0;
    if (ptls_get_negotiated_protocol(tls))
        a = strdup(ptls_get_negotiated_protocol(tls));
    else
        a = calloc(1, sizeof(char));
#if !defined(PARTICLE) && !defined(RIOT_VERSION)
    const struct tls_ticket which = {.sni = s, .alpn = a};
    struct tls_ticket * t = splay_find(tickets_by_peer, &tickets, &which);
    if (t == 0) {
        // create new ticket
        t = calloc(1, sizeof(*t));
        ensure(t, "calloc");
        t->sni = s;
        t->alpn = a;
        ensure(splay_insert(tickets_by_peer, &tickets, t) == 0, "inserted");
    } else {
        // update current ticket
        free(t->ticket);
        free(s);
        free(a);
    }
#else
    struct tls_ticket * const t = &tickets.last_ticket;
    t->sni = s;
    t->alpn = a;
#endif

    memcpy(&t->tp, &c->tp_peer, sizeof(t->tp));
    t->vers = c->vers;

    t->ticket_len = src.len;
    t->ticket = calloc(1, t->ticket_len);
    ensure(t->ticket, "calloc");
    memcpy(t->ticket, src.base, src.len);

    // write all tickets
    // FIXME this currently dumps the entire cache to file on each connection!
#if !defined(PARTICLE) && !defined(RIOT_VERSION)
    splay_foreach (t, tickets_by_peer, &tickets) {
#endif
        warn(INF, "writing TLS ticket for %s conn %s (%s %s)", conn_type(c),
             cid_str(c->scid), t->sni, t->alpn);

#if !defined(PARTICLE) && !defined(RIOT_VERSION)
        size_t len = strlen(t->sni) + 1;
        ensure(fwrite(&len, sizeof(len), 1, fp), "fwrite");
        ensure(fwrite(t->sni, sizeof(*t->sni), len, fp), "fwrite");

        len = strlen(t->alpn) + 1;
        ensure(fwrite(&len, sizeof(len), 1, fp), "fwrite");
        ensure(fwrite(t->alpn, sizeof(*t->alpn), len, fp), "fwrite");

        ensure(fwrite(&t->tp, sizeof(t->tp), 1, fp), "fwrite");
        ensure(fwrite(&t->vers, sizeof(t->vers), 1, fp), "fwrite");

        ensure(fwrite(&t->ticket_len, sizeof(t->ticket_len), 1, fp), "fwrite");
        ensure(fwrite(t->ticket, sizeof(*t->ticket), t->ticket_len, fp),
               "fwrite");
    }

    fclose(fp);
#endif

    return 0;
}


static ptls_save_ticket_t save_ticket = {.cb = save_ticket_cb};


#ifndef NO_SERVER
static ptls_encrypt_ticket_t encrypt_ticket = {.cb = encrypt_ticket_cb};
#endif


void init_tls(struct q_conn * const c,
              const char * const serv_name,
              const char * const clnt_alpn)
{
    char * const sni =
        is_clnt(c)
            ? strdup(c->tls.t ? ptls_get_server_name(c->tls.t) : serv_name)
            : 0;

    if (c->tls.t)
        // we are re-initializing during version negotiation
        free_tls(c, true);
    else {
        c->tls.tp_buf = calloc(1, TP_LEN);
        ensure(c->tls.tp_buf, "calloc");
    }

    if (is_clnt(c))
        c->tls.t = ptls_client_new(&ped(c->w)->tls_ctx);
#ifndef NO_SERVER
    else
        c->tls.t = ptls_server_new(&ped(c->w)->tls_ctx);
#endif
    ensure(c->tls.t, "ptls_new");
    *ptls_get_data_ptr(c->tls.t) = c;

    ptls_handshake_properties_t * const hshk_prop = &c->tls.tls_hshk_prop;
    hshk_prop->additional_extensions = c->tls.tp_ext;
    hshk_prop->collect_extension = filter_tp;
    hshk_prop->collected_extensions = chk_tp;

    if (is_clnt(c) && sni) {
        ensure(ptls_set_server_name(c->tls.t, sni, 0) == 0,
               "ptls_set_server_name");

        if (clnt_alpn == 0 || *clnt_alpn == 0) {
            c->tls.alpn = alpn[0];
            warn(NTE, "using default ALPN %.*s", (int)c->tls.alpn.len,
                 c->tls.alpn.base);
        } else if (clnt_alpn != (char *)c->tls.alpn.base) {
            free(c->tls.alpn.base);
            c->tls.alpn = ptls_iovec_init(strdup(clnt_alpn), strlen(clnt_alpn));
        }
        hshk_prop->client.negotiated_protocols.list = &c->tls.alpn;
        hshk_prop->client.negotiated_protocols.count = 1;
        hshk_prop->client.max_early_data_size = &c->tls.max_early_data;

        // try to find an existing session ticket
#if !defined(PARTICLE) && !defined(RIOT_VERSION)
        struct tls_ticket which = {// this works, because of strdup() allocation
                                   .sni = sni,
                                   .alpn = (char *)c->tls.alpn.base};
        struct tls_ticket * t = splay_find(tickets_by_peer, &tickets, &which);
        if (t == 0) {
            // if we couldn't find a ticket, try without an alpn
            which.alpn = "";
            t = splay_find(tickets_by_peer, &tickets, &which);
        }
#else
        struct tls_ticket * const t = &tickets.last_ticket;
#endif
        if (t && t->vers != 0) {
            hshk_prop->client.session_ticket =
                ptls_iovec_init(t->ticket, t->ticket_len);
            memcpy(&c->tp_peer, &t->tp, sizeof(t->tp));
            c->vers_initial = c->vers = t->vers;
            c->try_0rtt = true;
        }
    }
    if (sni)
        free(sni);

    init_prot(c);
}


static void __attribute__((nonnull)) free_prot(struct q_conn * const c)
{
    dispose_cipher(&c->pns[pn_init].early.in);
    dispose_cipher(&c->pns[pn_init].early.out);
    dispose_cipher(&c->pns[pn_hshk].early.in);
    dispose_cipher(&c->pns[pn_hshk].early.out);
    dispose_cipher(&c->pns[pn_data].data.in_0rtt);
    dispose_cipher(&c->pns[pn_data].data.out_0rtt);
    dispose_cipher(&c->pns[pn_data].data.in_1rtt[0]);
    dispose_cipher(&c->pns[pn_data].data.out_1rtt[0]);
    dispose_cipher(&c->pns[pn_data].data.in_1rtt[1]);
    dispose_cipher(&c->pns[pn_data].data.out_1rtt[1]);
}


void free_tls(struct q_conn * const c, const bool keep_alpn)
{
    if (c->tls.t)
        ptls_free(c->tls.t);
    ptls_clear_memory(c->tls.secret, sizeof(c->tls.secret));
    free_prot(c);
    if (keep_alpn == false) {
        if (c->tls.alpn.base != alpn[0].base)
            free(c->tls.alpn.base);
        if (c->tls.tp_buf)
            free(c->tls.tp_buf);
    }
}


void init_prot(struct q_conn * const c)
{
    struct cid * const scid = c->scid; // NOLINT
    struct cid * const dcid = c->dcid;
    const ptls_iovec_t cid = {
        .base = (uint8_t *)(is_clnt(c) ? &dcid->id : &scid->id),
        .len = is_clnt(c) ? dcid->len : scid->len};
    ptls_cipher_suite_t * cs = &aes128gcmsha256;
    struct pn_space * const pn = &c->pns[pn_init];
    setup_initial_encryption(&pn->early.in, &pn->early.out, &cs, cid,
                             is_clnt(c));
}


int tls_io(struct q_stream * const s, struct w_iov * const iv)
{
    struct q_conn * const c = s->c;
    const size_t in_len = iv ? iv->len : 0;
    const epoch_t ep_in = strm_epoch(s);
    size_t epoch_off[5] = {0};
    ptls_buffer_t tls_io;
    ptls_buffer_init(&tls_io, ped(s->c->w)->scratch, ped(s->c->w)->scratch_len);

    const int ret =
#ifndef NO_SERVER
        ptls_handle_message
#else
        ptls_client_handle_message
#endif
        (c->tls.t, &tls_io, epoch_off, ep_in, iv ? iv->buf : 0, in_len,
         &c->tls.tls_hshk_prop);

#ifdef DEBUG_PROT
    warn(DBG,
         "epoch %u, in %lu (off %" PRIu
         "), gen %lu (%lu-%lu-%lu-%lu-%lu), ret %d, left %lu",
         ep_in, (unsigned long)(iv ? iv->len : 0), iv ? meta(iv).strm_off : 0,
         (unsigned long)tls_io.off, (unsigned long)epoch_off[0],
         (unsigned long)epoch_off[1], (unsigned long)epoch_off[2],
         (unsigned long)epoch_off[3], (unsigned long)epoch_off[4], ret,
         (unsigned long)(iv ? iv->len - in_len : 0));
#endif
    if (ret == 0) {
        if (c->tls.tp_buf) {
            free(c->tls.tp_buf);
            c->tls.tp_buf = 0;
        }
        if (is_clnt(c)) {
            if (c->state != conn_estb && ptls_is_psk_handshake(c->tls.t))
                c->did_0rtt =
                    c->try_0rtt &&
                    (c->tls.tls_hshk_prop.client.early_data_acceptance ==
                     PTLS_EARLY_DATA_ACCEPTED);
        } else
            c->tx_hshk_done = ptls_handshake_is_complete(c->tls.t) != 0;

    } else if (ret != PTLS_ERROR_IN_PROGRESS &&
               ret != PTLS_ERROR_STATELESS_RETRY) {
        err_close(c, ERR_TLS(PTLS_ERROR_TO_ALERT(ret)), FRM_CRY, "TLS error %u",
                  ret);
        goto done;
    }

    if (tls_io.off == 0)
        goto done;

    // enqueue for TX
    for (epoch_t e = ep_init; e <= ep_data; e++) {
        const size_t out_len = epoch_off[e + 1] - epoch_off[e];
        if (out_len == 0)
            continue;
#ifdef DEBUG_PROT
        warn(DBG, "epoch %u: off %lu len %lu", e, (unsigned long)epoch_off[e],
             (unsigned long)out_len);
#endif
        struct w_iov_sq o = w_iov_sq_initializer(o);
        alloc_off(w_engine(c->sock), &o, 0, q_conn_af(c), (uint32_t)out_len,
                  DATA_OFFSET + c->tok_len);
        const uint8_t * data = tls_io.base + epoch_off[e];
        struct w_iov * ov;
        sq_foreach (ov, &o, next) {
            memcpy(ov->buf, data, ov->len);
            data += ov->len;
        }
        concat_out(c->cstrms[e], &o);
        c->needs_tx = true;
    }

done:
    ptls_buffer_dispose(&tls_io);
    return ret;
}


#if !defined(PARTICLE) && !defined(RIOT_VERSION)
static void __attribute__((nonnull)) free_ticket(struct tls_ticket * const t)
{
    if (t->sni)
        free(t->sni);
    if (t->alpn)
        free(t->alpn);
    if (t->ticket)
        free(t->ticket);
    free(t);
}
#endif


static void read_tickets(const struct q_conf * const conf)
{
    warn(INF, "reading TLS tickets from %s", conf->ticket_store);

#if !defined(PARTICLE) && !defined(RIOT_VERSION)
    FILE * const fp = fopen(conf->ticket_store, "rbe");
    if (fp == 0) {
        warn(WRN, "could not read TLS tickets from %s", conf->ticket_store);
        return;
    }

    // read and verify git hash
    size_t hash_len;
    if (fread(&hash_len, sizeof(quant_commit_hash_len), 1, fp) != 1)
        goto done;
    uint8_t buf[8192];
    if (fread(buf, sizeof(uint8_t), hash_len, fp) != hash_len)
        goto done;
    if (hash_len != quant_commit_hash_len ||
        memcmp(buf, quant_commit_hash, hash_len) != 0) {
        warn(WRN, "TLS tickets were stored by different %s version, removing",
             quant_name);
        ensure(unlink(conf->ticket_store) == 0, "unlink");
        goto done;
    }

    for (;;) {
        // try and read the SNI len
        size_t len;
        if (fread(&len, sizeof(len), 1, fp) != 1)
            // we read all the tickets
            break;
        ensure(len <= 256, "SNI len %lu too long", len);

        struct tls_ticket * const t = calloc(1, sizeof(*t));
        ensure(t, "calloc");
        t->sni = calloc(1, len);
        ensure(t->sni, "calloc");
        if (fread(t->sni, sizeof(*t->sni), len, fp) != len)
            goto abort;

        if (fread(&len, sizeof(len), 1, fp) != 1)
            goto abort;
        ensure(len <= 256, "ALPN len %lu too long", len);
        t->alpn = calloc(1, len);
        ensure(t->alpn, "calloc");
        if (fread(t->alpn, sizeof(*t->alpn), len, fp) != len)
            goto abort;

        if (fread(&t->tp, sizeof(t->tp), 1, fp) != 1)
            goto abort;
        if (fread(&t->vers, sizeof(t->vers), 1, fp) != 1)
            goto abort;

        if (fread(&len, sizeof(len), 1, fp) != 1)
            goto abort;
        ensure(len <= 8192, "ticket_len %lu too long", len);
        t->ticket_len = len;
        t->ticket = calloc(len, sizeof(*t->ticket));
        ensure(t->ticket, "calloc");
        if (fread(t->ticket, sizeof(*t->ticket), len, fp) != len)
            goto abort;

        ensure(splay_insert(tickets_by_peer, &tickets, t) == 0, "inserted");
        warn(INF, "got TLS ticket %s %s", t->sni, t->alpn);
        continue;
    abort:
        free_ticket(t);
        break;
    }

done:
    fclose(fp);
#endif
}


#ifndef NO_TLS_LOG
static void __attribute__((format(printf, 4, 5)))
log_event_cb(ptls_log_event_t * const self __attribute__((unused)),
             ptls_t * const tls,
             const char * const type,
             const char * fmt,
             ...)
{
    struct q_conn * const c = *ptls_get_data_ptr(tls);
    FILE * const tls_log = ped(c->w)->tls_log;

    fprintf(tls_log, "%s %s ", type,
            hex2str(ptls_get_client_random(tls).base, PTLS_HELLO_RANDOM_SIZE,
                    (char[hex_str_len(PTLS_HELLO_RANDOM_SIZE)]){""},
                    hex_str_len(PTLS_HELLO_RANDOM_SIZE)));

    va_list args;
    va_start(args, fmt);
    vfprintf(tls_log, fmt, args);
    va_end(args);

    fprintf(tls_log, "\n");
    fflush(tls_log);
}
#endif


static int update_traffic_key_cb(ptls_update_traffic_key_t * const self
                                 __attribute__((unused)),
                                 ptls_t * const tls,
                                 const int is_enc,
                                 const size_t epoch,
                                 const void * const secret)
{
#ifdef DEBUG_PROT
    warn(CRT, "update_traffic_key %s %lu", is_enc ? "tx" : "rx",
         (unsigned long)epoch);
#endif
    struct q_conn * const c = *ptls_get_data_ptr(tls);
    ptls_cipher_suite_t * const cipher = ptls_get_cipher(c->tls.t);
    struct pn_space * const pn = pn_for_epoch(c, (epoch_t)epoch);

    struct cipher_ctx * ctx = 0;
    switch (epoch) {
    case ep_0rtt:
        ctx = is_enc ? &pn->data.out_0rtt : &pn->data.in_0rtt;
        break;

    case ep_hshk:
        ctx = is_enc ? &pn->early.out : &pn->early.in;
        break;

    case ep_data:
        memcpy(c->tls.secret[is_enc], secret, cipher->hash->digest_size);
        ctx = is_enc ? &pn->data.out_1rtt[pn->data.out_kyph]
                     : &pn->data.in_1rtt[pn->data.in_kyph];
        break;

    default:
        die("epoch %lu unknown", (unsigned long)epoch);
    }

    if (ped(c->w)->tls_ctx.log_event) {
        static const char * const log_labels[2][4] = {
            {0, "CLIENT_EARLY_TRAFFIC_SECRET",
             "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0"},
            {0, 0, "SERVER_HANDSHAKE_TRAFFIC_SECRET",
             "SERVER_TRAFFIC_SECRET_0"}};

        ped(c->w)->tls_ctx.log_event->cb(
            ped(c->w)->tls_ctx.log_event, tls,
            log_labels[ptls_is_server(tls) == is_enc][epoch], "%s",
            hex2str(secret, cipher->hash->digest_size,
                    (char[hex_str_len(PTLS_MAX_DIGEST_SIZE)]){""},
                    hex_str_len(PTLS_MAX_DIGEST_SIZE)));
    }

    return setup_cipher(&ctx->header_protection, &ctx->aead, cipher->aead,
                        cipher->hash, is_enc, secret);
}


void init_tls_ctx(const struct q_conf * const conf,
                  struct per_engine_data * const ped)
{

    ptls_context_t * const tls_ctx = &ped->tls_ctx;
#if defined(PARTICLE) || defined(RIOT_VERSION)
    // the picotls minicrypto backend depends on this
    uECC_set_rng(uecc_rng);
#endif

    if (conf && conf->tls_key) {
#ifdef WITH_OPENSSL
        FILE * const fp = fopen(conf->tls_key, "rbe");
        ensure(fp, "could not open key %s", conf->tls_key);
        EVP_PKEY * const pkey = PEM_read_PrivateKey(fp, 0, 0, 0);
        fclose(fp);
        ensure(pkey, "failed to load private key");
        ptls_openssl_init_sign_certificate(&ped->sign_cert, pkey);
        EVP_PKEY_free(pkey);
#elif !defined(PARTICLE) && !defined(RIOT_VERSION)
        // XXX ptls_minicrypto_load_private_key() only works for ECDSA keys
        const int ret =
            ptls_minicrypto_load_private_key(tls_ctx, conf->tls_key);
        ensure(ret == 0, "could not open key %s", conf->tls_key);
#endif
    }

#ifdef WITH_OPENSSL
    ensure(ptls_openssl_init_verify_certificate(&ped->verify_cert, 0) == 0,
           "ptls_openssl_init_verify_certificate");
#endif

#if !defined(PARTICLE) && !defined(RIOT_VERSION)
    if (conf && conf->tls_cert) {
        const int ret = ptls_load_certificates(tls_ctx, conf->tls_cert);
        ensure(ret == 0, "ptls_load_certificates");
    }
    splay_init(&tickets);
#endif

    if (conf && conf->ticket_store) {
        tls_ctx->save_ticket = &save_ticket;
        read_tickets(conf);
    }
#ifndef NO_SERVER
    tls_ctx->encrypt_ticket = &encrypt_ticket;
    tls_ctx->max_early_data_size = 0xffffffff;
    tls_ctx->ticket_lifetime = 60 * 60 * 24;
    tls_ctx->require_dhe_on_psk = 0;
#endif

#ifndef NO_TLS_LOG
    if (conf && conf->tls_log) {
        ped->tls_log = fopen(conf->tls_log, "abe");
        ensure(ped->tls_log, "could not open TLS log %s", conf->tls_log);
    }

    if (conf && conf->tls_log) {
        static ptls_log_event_t log_event = {log_event_cb};
        tls_ctx->log_event = &log_event;
    }
#endif

    static ptls_key_exchange_algorithm_t * key_exchanges[] = {&secp256r1,
#ifndef MINIMAL_CIPHERS
                                                              &x25519,
#endif
                                                              0};
    static ptls_on_client_hello_t on_client_hello = {on_ch};
    static ptls_update_traffic_key_t update_traffic_key = {
        update_traffic_key_cb};

    tls_ctx->omit_end_of_early_data = true;
    tls_ctx->get_time = &ptls_get_time; // needs to be absolute time
    tls_ctx->cipher_suites = cipher_suite;
    tls_ctx->key_exchanges = key_exchanges;
    tls_ctx->on_client_hello = &on_client_hello;
    tls_ctx->update_traffic_key = &update_traffic_key;
    tls_ctx->random_bytes = rand_bytes;
#ifdef WITH_OPENSSL
    tls_ctx->sign_certificate = &ped->sign_cert.super;
    if (conf && conf->enable_tls_cert_verify)
        tls_ctx->verify_certificate = &ped->verify_cert.super;
#endif

#ifndef NO_SERVER
    init_ticket_prot(ped);
#endif

    static const uint8_t retry_secret[] = {
        0x65, 0x6e, 0x61, 0xe3, 0x36, 0xae, 0x94, 0x17, 0xf7, 0xf0, 0xed,
        0xd8, 0xd7, 0x8d, 0x46, 0x1e, 0x2a, 0xa7, 0x08, 0x4a, 0xba, 0x7a,
        0x14, 0xc1, 0xe9, 0xf7, 0x26, 0xd5, 0x57, 0x09, 0x16, 0x9a};
    const ptls_cipher_suite_t * const cs = &aes128gcmsha256;
    ped->rid_ctx =
        ptls_aead_new(cs->aead, cs->hash, 1, retry_secret, AEAD_BASE_LABEL);
    ensure(ped->rid_ctx, "could not make rit ctx");
}


void free_tls_ctx(struct per_engine_data * const ped)
{
#ifndef NO_SERVER
    dispose_cipher(&ped->dec_tckt);
    dispose_cipher(&ped->enc_tckt);
#endif
    ptls_aead_free(ped->rid_ctx);

#if !defined(PARTICLE) && !defined(RIOT_VERSION)
    // free ticket cache
    struct tls_ticket * t;
    struct tls_ticket * tmp;
    for (t = splay_min(tickets_by_peer, &tickets); t != 0; t = tmp) {
        tmp = splay_next(tickets_by_peer, &tickets, t);
        ensure(splay_remove(tickets_by_peer, &tickets, t), "removed");
        free_ticket(t);
    }
#endif

    for (size_t i = 0; i < ped->tls_ctx.certificates.count; i++)
        free(ped->tls_ctx.certificates.list[i].base);
    free(ped->tls_ctx.certificates.list);

#ifdef WITH_OPENSSL
    ptls_openssl_dispose_sign_certificate(&ped->sign_cert);
    X509_STORE_free(ped->verify_cert.cert_store);
    // FIXME: ptls_openssl_dispose_verify_certificate(&ped->verify_cert) frees!
#endif
}


static inline const struct cipher_ctx * __attribute__((nonnull))
which_cipher_ctx_out(const struct pkt_meta * const m, const bool kyph)
{
    switch (m->hdr.type) {
    case LH_INIT:
    case LH_RTRY:
    case LH_HSHK:
        return &m->pn->early.out;
    case LH_0RTT:
        return &m->pn->data.out_0rtt;
    default:
        return &m->pn->data.out_1rtt[kyph ? is_set(SH_KYPH, m->hdr.flags) : 0];
    }
}


uint16_t dec_aead(const struct w_iov * const xv,
                  const struct w_iov * const v,
                  const struct pkt_meta * const m,
                  const uint16_t len,
                  const struct cipher_ctx * const ctx)
{
    const uint16_t hdr_len = m->hdr.hdr_len;
    if (unlikely(hdr_len == 0 || hdr_len > len))
        return 0;

    const size_t ret =
        ptls_aead_decrypt(ctx->aead, &v->buf[hdr_len], &xv->buf[hdr_len],
                          len - hdr_len, m->hdr.nr, xv->buf, hdr_len);
    if (unlikely(ret == SIZE_MAX))
        return 0;
    memcpy(v->buf, xv->buf, hdr_len);

#ifdef DEBUG_PROT
    warn(DBG, "dec %s AEAD over [%u..%u] in [%u..%u]",
         pkt_type_str(m->hdr.flags, &m->hdr.vers), hdr_len, len - AEAD_LEN - 1,
         len - AEAD_LEN, len - 1);
#endif

    return hdr_len + len;
}


uint16_t enc_aead(const struct w_iov * const v,
                  const struct pkt_meta * const m,
                  struct w_iov * const xv,
                  const uint16_t pkt_nr_pos)
{
    const struct cipher_ctx * ctx = which_cipher_ctx_out(m, true);
    if (unlikely(ctx == 0 || ctx->aead == 0)) {
        warn(NTE, "no %s crypto context",
             pkt_type_str(m->hdr.flags, &m->hdr.vers));
        return 0;
    }

    const uint16_t hdr_len = m->hdr.hdr_len;
    memcpy(xv->buf, v->buf, hdr_len); // copy pkt header

    const uint16_t plen = v->len - hdr_len + AEAD_LEN;
    xv->len = hdr_len + (uint16_t)ptls_aead_encrypt(
                            ctx->aead, &xv->buf[hdr_len], &v->buf[hdr_len],
                            plen - AEAD_LEN, m->hdr.nr, v->buf, hdr_len);

    // apply packet protection
    ctx = which_cipher_ctx_out(m, false);
    if (likely(pkt_nr_pos) &&
        unlikely(xor_hp(xv, m, ctx, pkt_nr_pos, true) == false))
        return 0;

#ifdef DEBUG_PROT
    warn(DBG, "enc %s AEAD over [%u..%u] in [%u..%u]",
         pkt_type_str(m->hdr.flags, &m->hdr.vers), hdr_len,
         hdr_len + plen - AEAD_LEN - 1, hdr_len + plen - AEAD_LEN,
         hdr_len + plen - 1);
#endif
    return xv->len;
}


static ptls_hash_context_t * __attribute__((nonnull))
prep_hash_ctx(const struct q_conn * const c,
              const ptls_cipher_suite_t * const cs)
{
    // create hash context
    ptls_hash_context_t * const hc = cs->hash->create();
    ensure(hc, "could not create hash context");

    // hash our git commit hash and the peer IP address
    hc->update(hc, quant_commit_hash, quant_commit_hash_len);
    hc->update(hc, &c->peer, sizeof(c->peer));

    return hc;
}


void make_rtry_tok(struct q_conn * const c)
{
    const ptls_cipher_suite_t * const cs = &aes128gcmsha256;
    ptls_hash_context_t * const hc = prep_hash_ctx(c, cs);

    // hash current scid
    struct cid * const scid = c->scid;
    hc->update(hc, scid->id, scid->len);
    hc->final(hc, c->tok, PTLS_HASH_FINAL_MODE_FREE);

    // append scid to hashed token
    memcpy(&c->tok[cs->hash->digest_size], scid->id, scid->len);
    // update max_frame_len() when this changes:
    c->tok_len = (uint16_t)cs->hash->digest_size + scid->len;
    // #ifdef DEBUG_PROT
    warn(DBG, "computed Retry tok %s",
         hex2str(c->tok, c->tok_len, (char[hex_str_len(MAX_TOK_LEN)]){""},
                 hex_str_len(c->tok_len)));
    // #endif
}


bool verify_rtry_tok(struct q_conn * const c,
                     const uint8_t * const tok,
                     const uint16_t tok_len)
{
    const ptls_cipher_suite_t * const cs = &aes128gcmsha256;
    ptls_hash_context_t * const hc = prep_hash_ctx(c, cs);

    // hash current cid included in token
    hc->update(hc, tok + cs->hash->digest_size,
               tok_len - cs->hash->digest_size);
    uint8_t buf[PTLS_MAX_DIGEST_SIZE + CID_LEN_MAX];
    hc->final(hc, buf, PTLS_HASH_FINAL_MODE_FREE);

    // #ifdef DEBUG_PROT
    warn(DBG, "computed Retry tok %s",
         hex2str(buf, cs->hash->digest_size,
                 (char[hex_str_len(MAX_TOK_LEN)]){""},
                 hex_str_len(cs->hash->digest_size)));
    // #endif
    if (memcmp(buf, tok, cs->hash->digest_size) == 0) {
        c->odcid.len = (uint8_t)(tok_len - cs->hash->digest_size);
        memcpy(&c->odcid.id, tok + cs->hash->digest_size, c->odcid.len);
        return true;
    }
    // #ifdef DEBUG_PROT
    warn(DBG, "rx'ed Retry tok %s",
         hex2str(tok, cs->hash->digest_size,
                 (char[hex_str_len(MAX_TOK_LEN)]){""},
                 hex_str_len(cs->hash->digest_size)));
    // #endif
    return false;
}


void make_rit(const struct q_conn * const c,
              const uint8_t flags,
              const struct cid * const dcid,
              const struct cid * const scid,
              const uint8_t * const tok,
              const uint16_t tok_len,
              uint8_t * const rit)
{
    uint8_t * pos = ped(c->w)->scratch;
    uint8_t * end = pos + ped(c->w)->scratch_len;

    // encode the pseudo packet
    enc1(&pos, end, c->odcid.len);
    encb(&pos, end, c->odcid.id, c->odcid.len);
    enc1(&pos, end, flags);
    enc4(&pos, end, c->vers);
    enc1(&pos, end, dcid->len);
    encb(&pos, end, dcid->id, dcid->len);
    enc1(&pos, end, scid->len);
    encb(&pos, end, scid->id, scid->len);
    encb(&pos, end, tok, tok_len);

    ptls_aead_encrypt(ped(c->w)->rid_ctx, rit, 0, 0, 0, ped(c->w)->scratch,
                      (size_t)(pos - ped(c->w)->scratch));
}


void flip_keys(struct q_conn * const c, const bool out)
{
    struct pn_data * const pnd = &c->pns[pn_data].data;
    const bool new_kyph = !(out ? pnd->out_kyph : pnd->in_kyph);
#ifdef DEBUG_PROT
    warn(DBG, "flip %s kyph %u -> %u", out ? "out" : "in",
         out ? pnd->out_kyph : pnd->in_kyph, new_kyph);
#endif
    const ptls_cipher_suite_t * const cs = ptls_get_cipher(c->tls.t);
    if (unlikely(cs == 0)) {
        warn(ERR, "cannot obtain cipher suite");
        return;
    }

    uint8_t new_secret[PTLS_MAX_DIGEST_SIZE];
    static const char flip_label[] = "quic ku";
    if (pnd->in_1rtt[new_kyph].aead)
        ptls_aead_free(pnd->in_1rtt[new_kyph].aead);
    if (setup_initial_key(&pnd->in_1rtt[new_kyph], cs, c->tls.secret[0],
                          flip_label, 0, new_secret))
        return;
    memcpy(c->tls.secret[0], new_secret, cs->hash->digest_size);
    if (pnd->out_1rtt[new_kyph].aead)
        ptls_aead_free(pnd->out_1rtt[new_kyph].aead);
    if (setup_initial_key(&pnd->out_1rtt[new_kyph], cs, c->tls.secret[1],
                          flip_label, 1, new_secret) != 0)
        return;
    memcpy(c->tls.secret[1], new_secret, cs->hash->digest_size);

    if (out == false)
        pnd->in_kyph = new_kyph;
    pnd->out_kyph = new_kyph;
}


void maybe_flip_keys(struct q_conn * const c, const bool out)
{
    if (c->key_flips_enabled == false || likely(c->do_key_flip == false))
        return;

    struct pn_data * const pnd = &c->pns[pn_data].data;
    if (pnd->out_kyph != pnd->in_kyph)
        return;

    flip_keys(c, out);
    c->do_key_flip = false;
}
