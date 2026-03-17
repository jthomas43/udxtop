#ifndef udx_conntrack_h_INCLUDED
#define udx_conntrack_h_INCLUDED

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#define HISTORY_LENGTH 20
#define RESOLUTION 2
#define DUMP_RESOLUTION 300

typedef enum {
    DIRECTION_dontcare = -1, // for use when listening on e.g. a router interface
    DIRECTION_incoming,
    DIRECTION_outgoing,
} direction_type_t;

typedef struct {
    uint64_t recv[HISTORY_LENGTH];
    uint64_t sent[HISTORY_LENGTH];
    double long total_sent;
    double long total_recv;
    int last_write;
} history_t;

#define HISTORY_DIVISIONS 3
typedef struct {
    double long total_recv;
    double long total_sent;
    double long recv[HISTORY_DIVISIONS];
    double long sent[HISTORY_DIVISIONS];
} line_t;

typedef struct udx_flow_s udx_flow_t;

extern udx_flow_t *established[1024];
extern udx_flow_t *new[1024];
extern udx_flow_t *flow_list;

struct udx_flow_s {
    // key
    struct sockaddr_storage src;
    struct sockaddr_storage dst;
    uint32_t id;
    // end key

    direction_type_t direction;

    udx_flow_t *hash_next;

    uint32_t hash_value;

    uint32_t seq;
    uint32_t ack;
    uint32_t rwnd;

    bool next_seq_valid; // set when we first see a data packet sent
    uint32_t next_seq;
    uint32_t fack;

    struct {
        uint32_t start;
        uint32_t end;
    } sacks[32];
    int nsacks;
};

typedef struct udx_stream_s udx_stream_t;

struct udx_stream_s {
    udx_flow_t flow[2]; // must be first item
    bool complete;      // data seen in both directions

    // only for udxtop
    history_t history;
    line_t line;
};

extern udx_stream_t *stream_table[4096];
extern int nstreams;

// use DIRECTION_dontcare to assign an arbitrary direction to a flow
// in this case, the 1st flow will be stored in stream->flow[0] with direction 'incoming'
// in this case, and 2nd flow will be stored in stream->flow[1] with direction 'outgoing'
udx_flow_t *
upsert_flow(struct sockaddr *src, struct sockaddr *dst, uint32_t id, direction_type_t dir);

udx_stream_t *
get_stream(udx_flow_t *flow);

udx_flow_t *
get_reverse(udx_flow_t *flow);

void remove_stream(udx_stream_t *stream);

size_t
addr_sizeof(struct sockaddr *sa);

#endif // udx_conntrack_h_INCLUDED
