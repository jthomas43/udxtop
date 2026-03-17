#include "udx_conntrack.h"
#include <assert.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

// this module tracks udx connections
// each connection is made of two flows, going
// in opposite directions.
// a flow can be identified by a 5 tuple of
// src_ip:src_port:dst_ip:dst_port:dst_id

// Algorithm: matching a packet to a stream
// keep two tables for flows - 'established' and 'new'
// the 'established' table is keyed by the 5-tuple src_ip:src_port:dst_ip:dst_port:dst_id
// the 'new' table is keyed by the 4-typle src_ip:srd_port:dst_ip:dst_port
// for each packet
//     lookup a flow in the established table with the 5tuple
//     if found:
//         the stream may be found with the container_of macro. DONE
//     else:
//         lookup a flow in the new table with the 4tuple
//         if found:
//             if the flow's id matches:
//                 we've seen this direction, update seq, ack, etc. DONE.
//             else:
//                 we've found the reverse direction *
//                 label it complete
//                 remove both flows and insert them into the 5tuple table
//                 DONE
//         else:
//             we've never seen this flow (forward or reverse).
//             create a stream, create a forward and reverse flow (leave reverse id=0)
//             label the reverse flow incomplete
//             DONE
// * there's ambiguity here - we don't know for if the stream coming in the other
// direction is the response stream - even if the seq and acks match it could be a previously
// unseen stream with an unseen pair. unlike UDP / TCP we can only make a best guess

udx_flow_t *new[1024];
udx_flow_t *established[1024];

// todo, dynamically grow.. lazy.
udx_stream_t *stream_table[4096];
int nstreams;

#define FNV_32_PRIME ((uint32_t)0x01000193)

// fnv32 hash - licensed public domain
static uint32_t
hash(void *buf, size_t len, uint32_t hval) {

    uint8_t *p = (uint8_t *)buf;
    uint8_t *last = p + len;

    while (p < last) {
        hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
        hval ^= (uint32_t)*p++;
    }

    return hval;
}

size_t
addr_sizeof(struct sockaddr *sa) {
    assert(sa->sa_family == AF_INET || sa->sa_family == AF_INET6);
    return sa->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}

static uint32_t
hash_sockaddr(struct sockaddr *sa, uint32_t h) {
    return hash(sa, addr_sizeof(sa), h);
}

#define ARRAY_SIZEOF(a) (sizeof((a)) / sizeof((a)[0]))
#define container_of(pointer, type, field) ((type *)((char *)(pointer) - offsetof(type, field)))

static bool
addr_equal(struct sockaddr *a, struct sockaddr *b) {
    if (a->sa_family != b->sa_family)
        return false;

    if (a->sa_family == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *)a;
        struct sockaddr_in *sb = (struct sockaddr_in *)b;
        return sa->sin_port == sb->sin_port && memcmp(&sa->sin_addr, &sb->sin_addr, sizeof(sa->sin_addr)) == 0;
    } else {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *sb = (struct sockaddr_in6 *)b;
        return sa->sin6_port == sb->sin6_port && memcmp(&sa->sin6_addr, &sb->sin6_addr, sizeof(sa->sin6_addr)) == 0;
    };
}

// we return a ** instead of the typical * because the
// ** API allows a user to lookup / insert / remove
// lookup: flow = *lookup_4tuple(src, dst)
// insert: *lookup_4tuple(src, dst) = calloc(...)
// remove: pf = lookup_4tuple(src, dst); *pf =  (*pf)->hash_next;
udx_flow_t **
lookup_4tuple(struct sockaddr *src, struct sockaddr *dst) {
    uint32_t h = 0;

    h = hash_sockaddr(src, h);
    h = hash_sockaddr(dst, h);

    int index = h & (ARRAY_SIZEOF(new) - 1);

    udx_flow_t **chain = &new[index];

    while ((*chain) != NULL) {
        if (addr_equal(src, (struct sockaddr *)&(*chain)->src) && addr_equal(dst, (struct sockaddr *)&(*chain)->dst)) {
            break;
        }
        chain = &(*chain)->hash_next;
    }

    return chain;
}
udx_flow_t **
lookup_5tuple(struct sockaddr *src, struct sockaddr *dst, uint32_t id) {
    uint32_t h = 0;

    h = hash_sockaddr(src, h);
    h = hash_sockaddr(dst, h);
    h = hash(&id, sizeof(id), h);

    int index = h & (ARRAY_SIZEOF(established) - 1);
    udx_flow_t **chain = &established[index];

    while (*chain != NULL) {
        if (addr_equal(src, (struct sockaddr *)&(*chain)->src) && addr_equal(dst, (struct sockaddr *)&(*chain)->dst)) {
            break;
        }
        chain = &(*chain)->hash_next;
    }

    return chain;
}

bool debug = false;

udx_flow_t *
upsert_flow(struct sockaddr *src, struct sockaddr *dst, uint32_t id, direction_type_t direction) {

    assert(id != 0);
    assert(direction != DIRECTION_dontcare);
    bool direction_given = direction != DIRECTION_dontcare;
    assert(direction_given == true);

    udx_flow_t **pp = lookup_5tuple(src, dst, id);

    if (*pp) {
        if (direction_given)
            assert((*pp)->direction == direction);
        return *pp;
    }

    pp = lookup_4tuple(src, dst);

    if (*pp) {
        if ((direction_given && (*pp)->direction == direction) || (!direction_given && (*pp)->direction == DIRECTION_incoming)) {
            if ((*pp)->id == 0) {
                (*pp)->id = id;
            }
            return *pp;
        } else {
            if (!direction_given) {
                assert((*pp)->direction == DIRECTION_outgoing);
            } else {
                assert((*pp)->direction == !direction);
            }
            assert((*pp)->id == 0);
            udx_flow_t *f = *pp;

            udx_stream_t *stream = get_stream(f);
            udx_flow_t *f0 = &stream->flow[0];
            udx_flow_t *f1 = &stream->flow[1];

            assert(f == &stream->flow[f->direction]);
            // remove ourselves
            *pp = (*pp)->hash_next;
            pp = lookup_4tuple(dst, src);
            assert(*pp == f0);
            *pp = (*pp)->hash_next;
            // insert into the 5tuple table

            assert(f0->id != 0);
            assert(f1->id != 0);

            *lookup_5tuple((struct sockaddr *)&f0->src, (struct sockaddr *)&f0->dst, f0->id) = f0;
            *lookup_5tuple((struct sockaddr *)&f1->src, (struct sockaddr *)&f1->dst, f1->id) = f1;

            stream->complete = true;

            return f;
        }
    } else {
        // no flow in 4tuple
        udx_stream_t *s = calloc(1, sizeof(*s));
        stream_table[nstreams++] = s;

        if (!direction_given)
            direction = DIRECTION_incoming;

        udx_flow_t *f0 = &s->flow[direction];
        memcpy(&f0->src, src, addr_sizeof(src));
        memcpy(&f0->dst, dst, addr_sizeof(dst));
        f0->direction = direction;
        f0->id = id;

        udx_flow_t *f1 = &s->flow[!direction];
        memcpy(&f1->src, dst, addr_sizeof(dst));
        memcpy(&f1->dst, src, addr_sizeof(src));
        f1->direction = !direction;

        *pp = f0;
        pp = lookup_4tuple(dst, src);
        assert(*pp == NULL);
        *pp = f1;

        return f0;
    }
}

// note: doesn't remove from the stream_list, this is admittedly bad design,
// but it's done in history_rotate
void remove_stream(udx_stream_t *stream) {
    for (udx_flow_t *f = stream->flow; f < stream->flow + 2; f++) {

        udx_flow_t **p = lookup_5tuple((struct sockaddr *)&f->src, (struct sockaddr *)&f->dst, f->id);
        if (*p == NULL)
            p = lookup_4tuple((struct sockaddr *)&f->src, (struct sockaddr *)&f->dst);

        if (*p != NULL) {
            *p = (*p)->hash_next;
        } else {
            assert(false && "stream not found");
        }
    }
    // remove from table - replace with last in table

    udx_stream_t *last = stream_table[nstreams - 1];
    if (stream != last) {
        for (int i = 0; i < nstreams - 1; i++) {
            if (stream_table[i] == stream) {
                stream_table[i] = last;
                break;
            }
        }
    }

    nstreams--;

    free(stream);
}

udx_stream_t *
get_stream(udx_flow_t *flow) {
    if (flow->direction == 0) {
        return container_of(flow, udx_stream_t, flow);
    } else {
        return container_of(flow - 1, udx_stream_t, flow);
    }
}

udx_flow_t *
get_reverse(udx_flow_t *flow) {
    if (flow->direction == 0) {
        return flow + 1;
    } else {
        return flow - 1;
    }
}
