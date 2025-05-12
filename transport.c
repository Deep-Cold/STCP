/*
 * transport.c 
 *
 * CS536 PA2 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <stdint.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"


typedef enum { 
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    TIMED_WAIT,
    CLOSE_WAIT,
    LAST_ACK,
} tcp_state;


#define SEND_BUFFER_SIZE 5120
#define RECV_BUFFER_SIZE 5120
#define RECV_WINDOW_SIZE 5120
#define CONGESTION_WINDOW_SIZE 5120
#define MAX_PAYLOAD_SIZE 500
#define TIMEOUT_USECONDS 500

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */
    tcp_seq seq_num;
    tcp_seq ack_num;
    tcp_state connection_state;
    tcp_seq initial_sequence_num;
    uint16_t cur_window_size;

    char *send_buffer;
    size_t send_buffer_idx;
    char *recv_buffer;
    bool_t *get_buffer;

    struct timeval last_send_time;
    int retransmit_count;

    bool_t is_active;
    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
static void packet_send(mysocket_t sd, context_t *ctx, char *data, int len, uint8_t flags);
static void check_timeout(mysocket_t sd, context_t *ctx);
static void process_in_data(mysocket_t sd, context_t *ctx, char *data, int len);
static void process_out_data(mysocket_t sd, context_t *ctx);
static void handle_fin(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;
    unsigned int event;
    char recv_buffer[MAX_PAYLOAD_SIZE + sizeof(STCPHeader)];
    ssize_t recv_len;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    ctx->done = FALSE;
    ctx->connection_state = is_active ? SYN_SENT : LISTEN;
    ctx->is_active = is_active;
    ctx->cur_window_size = 0;
    ctx->retransmit_count = 0;
    ctx->send_buffer = (char *)malloc(SEND_BUFFER_SIZE);
    ctx->send_buffer_idx = 0;
    ctx->recv_buffer = (char *)malloc(RECV_BUFFER_SIZE);
    ctx->get_buffer = (bool_t *)malloc(RECV_BUFFER_SIZE * sizeof(bool_t));
    memset(ctx->get_buffer, 0, RECV_BUFFER_SIZE * sizeof(bool_t));

    ctx->seq_num = ctx->initial_sequence_num;
    stcp_unblock_application(sd);

    if(is_active) {
        packet_send(sd, ctx, NULL, 0, TH_SYN);
        gettimeofday(&ctx->last_send_time, NULL);
        while(ctx->connection_state == SYN_SENT) {
            event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
            if(event & NETWORK_DATA) {
                recv_len = stcp_network_recv(sd, recv_buffer, sizeof(recv_buffer));
                if(recv_len > 0) {
                    STCPHeader *header = (STCPHeader *)recv_buffer;
                    if(header->th_flags & TH_SYN && header->th_flags & TH_ACK) {
                        ctx->ack_num = header->th_seq + 1;
                        ctx->connection_state = ESTABLISHED;
                        ctx->cur_window_size = MIN(header->th_win, CONGESTION_WINDOW_SIZE);
                        packet_send(sd, ctx, NULL, 0, TH_ACK);
                        gettimeofday(&ctx->last_send_time, NULL);
                        stcp_unblock_application(sd);
                        break;
                    }
                }
            }
            check_timeout(sd, ctx);
        }
    } else {
        while(ctx->connection_state == LISTEN) {
            event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
            if(event & NETWORK_DATA) {
                recv_len = stcp_network_recv(sd, recv_buffer, sizeof(recv_buffer));
                if(recv_len > 0) {
                    STCPHeader *header = (STCPHeader *)recv_buffer;
                    if(header->th_flags & TH_SYN) {
                        ctx->ack_num = header->th_seq + 1;
                        ctx->connection_state = SYN_RECEIVED;
                        packet_send(sd, ctx, NULL, 0, TH_SYN | TH_ACK);
                        gettimeofday(&ctx->last_send_time, NULL);
                        while(ctx->connection_state == SYN_RECEIVED) {
                            event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
                            if(event & NETWORK_DATA) {
                                recv_len = stcp_network_recv(sd, recv_buffer, sizeof(recv_buffer));
                                if(recv_len > 0) {
                                    STCPHeader *header = (STCPHeader *)recv_buffer;
                                    if(header->th_flags & TH_ACK && header->th_ack == ctx->seq_num + 1) {
                                        ctx->connection_state = ESTABLISHED;
                                        ctx->cur_window_size = MIN(header->th_win, CONGESTION_WINDOW_SIZE);
                                        stcp_unblock_application(sd);
                                        break;
                                    }
                                }
                            }
                            check_timeout(sd, ctx);
                        }
                        break;
                    }
                }
            }
        }

    }
    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx->send_buffer);
    free(ctx->recv_buffer);
    free(ctx->get_buffer);
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    ctx->initial_sequence_num = rand() % 200;
    /*ctx->initial_sequence_num =;*/
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    while (!ctx->done)
    {
        unsigned int event;
        char recv_buffer[MAX_PAYLOAD_SIZE + sizeof(STCPHeader)];
        ssize_t recv_len;
        /* see stcp_api.h or stcp_api.c for details of this function */
        event = stcp_wait_for_event(sd, 0, NULL);

        /* check whether it was the network, app, or a close request */
        check_timeout(sd, ctx);
        
        if(event & NETWORK_DATA)
        {
            recv_len = stcp_network_recv(sd, recv_buffer, sizeof(recv_buffer));
            if (recv_len > 0) {
                process_in_data(sd, ctx, recv_buffer, recv_len);
            }
        }

        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            process_out_data(sd, ctx);
        }

        if(event & APP_CLOSE_REQUESTED) {
            if(ctx->connection_state == ESTABLISHED) {
                ctx->connection_state = FIN_WAIT_1;
                packet_send(sd, ctx, NULL, 0, TH_FIN | TH_ACK);
            } else if(ctx->connection_state == CLOSE_WAIT) {
                ctx->connection_state = LAST_ACK;
                packet_send(sd, ctx, NULL, 0, TH_FIN | TH_ACK);
            }
        }
    }
}

static void packet_send(mysocket_t sd, context_t *ctx, char *data, int len, uint8_t flags) {
    char data_send[MAX_PAYLOAD_SIZE + sizeof(STCPHeader)];
    STCPHeader *header = (STCPHeader *)data_send;

    header->th_seq = ctx->seq_num;
    header->th_ack = ctx->ack_num;
    header->th_flags = flags;
    header->th_win = ctx->cur_window_size;
    header->th_off = 5;
    
    if(flags & TH_SYN) {
        ctx->seq_num++;
    }

    if(data && len > 0) {
        memcpy(data_send + 4 * header->th_off, data, len);
        ctx->seq_num += len;
    }

    stcp_network_send(sd, data_send, sizeof(STCPHeader) + len);

}

static void check_timeout(mysocket_t sd, context_t *ctx) {
    struct timeval now;
    gettimeofday(&now, NULL);

    if(now.tv_usec - ctx->last_send_time.tv_usec >= TIMEOUT_USECONDS) {
        if(ctx->retransmit_count < 6) {
            if(ctx->cur_window_size > 0) {
                ctx->cur_window_size /= 2;
            }
            ctx->retransmit_count++;
            switch (ctx->connection_state) {
                case SYN_SENT:
                    packet_send(sd, ctx, NULL, 0, TH_SYN);
                    break;
                case SYN_RECEIVED:
                    packet_send(sd, ctx, NULL, 0, TH_SYN | TH_ACK);
                    break;
                case ESTABLISHED:
                    if(ctx->send_buffer_idx > 0) {
                        packet_send(sd, ctx, ctx->send_buffer, ctx->send_buffer_idx, TH_ACK);
                    } else {
                        packet_send(sd, ctx, NULL, 0, TH_ACK);
                    }
                    break;
                case FIN_WAIT_1:
                    packet_send(sd, ctx, NULL, 0, TH_FIN | TH_ACK);
                    break;
                case LAST_ACK:
                    packet_send(sd, ctx, NULL, 0, TH_FIN | TH_ACK);
                    break;
                default:
                    break;
            }
        } else {
            ctx->done = TRUE;
            errno = ETIMEDOUT;
            stcp_unblock_application(sd);
        }
    }
}

static void handle_fin(mysocket_t sd, context_t *ctx) {
    if(ctx->connection_state == ESTABLISHED) {
        ctx->connection_state = CLOSE_WAIT;
        packet_send(sd, ctx, NULL, 0, TH_ACK);
    } else if(ctx->connection_state == FIN_WAIT_1) {
        ctx->connection_state = TIMED_WAIT;
        packet_send(sd, ctx, NULL, 0, TH_ACK);
        ctx->done = TRUE;
        stcp_fin_received(sd);
    }
}

static void process_in_data(mysocket_t sd, context_t *ctx, char *data, int len) {
    STCPHeader *header = (STCPHeader *)data;
    char *payload = data + sizeof(STCPHeader);
    int payload_len = len - sizeof(STCPHeader);

    if(header->th_flags & TH_ACK) {
        ctx->retransmit_count = 0;
    }

    if(header->th_flags & TH_FIN) {
        handle_fin(sd, ctx);
    }
    
    if(payload_len > 0 && ctx->connection_state == ESTABLISHED) {
        tcp_seq window_start = ctx->ack_num;
        tcp_seq window_end = window_start + RECV_WINDOW_SIZE - 1;

        if(header->th_seq >= window_start && header->th_seq <= window_end) {
            int valid_len = MIN(payload_len, window_end - header->th_seq + 1);
            assert(header->th_seq + valid_len - 1 <= RECV_BUFFER_SIZE);
            
            memcpy(ctx->recv_buffer + header->th_seq - window_start, payload, valid_len);

            for(int i = 0; i < valid_len; i++) {
                ctx->get_buffer[header->th_seq - window_start + i] = TRUE;
            }

            if(header->th_seq == window_start) {
                int new_start = 0;
                while(new_start < RECV_BUFFER_SIZE && ctx->get_buffer[new_start]) {
                    new_start++;
                }
                if(new_start < RECV_BUFFER_SIZE) {
                    memcpy(ctx->get_buffer, ctx->get_buffer + new_start, RECV_BUFFER_SIZE - new_start);
                }
                memset(ctx->get_buffer + RECV_BUFFER_SIZE - new_start, 0, new_start);
                valid_len = new_start - window_start;
                ctx->ack_num += valid_len;
                stcp_app_send(sd, payload, valid_len);
            }
            packet_send(sd, ctx, NULL, 0, TH_ACK);
        } else if(header->th_seq < window_start) {
            int message_r = MIN(window_end, header->th_seq + payload_len - 1);
            if(message_r >= window_start) {
                int overlap_len = message_r - window_start + 1;
                assert(overlap_len > 0);
                memcpy(ctx->recv_buffer, payload + window_start - header->th_seq, overlap_len);
                for(int i = 0; i < overlap_len; i++) {
                    ctx->get_buffer[i] = TRUE;
                }
                int new_start = 0;
                while(new_start < RECV_BUFFER_SIZE && ctx->get_buffer[new_start]) {
                    new_start++;
                }
                if(new_start < RECV_BUFFER_SIZE) {
                    memcpy(ctx->get_buffer, ctx->get_buffer + new_start, RECV_BUFFER_SIZE - new_start);
                }
                memset(ctx->get_buffer + RECV_BUFFER_SIZE - new_start, 0, new_start);
                int valid_len = new_start - window_start;
                ctx->ack_num += valid_len;
                stcp_app_send(sd, payload, valid_len);
            }
            packet_send(sd, ctx, NULL, 0, TH_ACK);
        }

    }
}

static void process_out_data(mysocket_t sd, context_t *ctx) {
    char buffer[MAX_PAYLOAD_SIZE];
    int len;
    uint16_t effective_window;

    gettimeofday(&ctx->last_send_time, NULL);
    len = stcp_app_recv(sd, buffer, MAX_PAYLOAD_SIZE);
    if(len > 0) {
        effective_window = MIN(ctx->cur_window_size, CONGESTION_WINDOW_SIZE);
        if(ctx->seq_num + len <= ctx->ack_num + effective_window) {
            memcpy(ctx->send_buffer + ctx->send_buffer_idx, buffer, len);
            ctx->send_buffer_idx += len;
            packet_send(sd, ctx, buffer, len, TH_ACK);
        }
    }
}

/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



