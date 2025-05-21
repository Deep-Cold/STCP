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
#include <arpa/inet.h>
#include <time.h>
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
#define TIMEOUT_MSECONDS 100

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */
    tcp_seq seq_num;
    tcp_seq ack_num;
    tcp_state connection_state;
    tcp_seq initial_sequence_num;
    uint16_t cur_window_size;
    uint16_t window_threshold;

    char *send_buffer;
    int send_buffer_idx, sent_buffer_idx;
    char *recv_buffer;
    bool_t *get_buffer;

    struct timeval last_send_time;
    int retransmit_count;
    int dup_cnt;

    bool_t is_active;
    /* any other connection-wide global variables go here */
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
static void packet_send(mysocket_t sd, context_t *ctx, char *data, int len, uint8_t flags, int seq_num);
static void check_timeout(mysocket_t sd, context_t *ctx);
static void process_in_data(mysocket_t sd, context_t *ctx, char *data, int len);
static void process_out_data(mysocket_t sd, context_t *ctx, bool_t is_retransmit);
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
    stcp_set_context(sd, ctx);

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
    ctx->dup_cnt = 0;
    ctx->send_buffer = (char *)malloc(SEND_BUFFER_SIZE);
    ctx->send_buffer_idx = 0, ctx->sent_buffer_idx = 0;
    ctx->recv_buffer = (char *)malloc(RECV_BUFFER_SIZE);
    ctx->get_buffer = (bool_t *)malloc(RECV_BUFFER_SIZE * sizeof(bool_t));
    memset(ctx->get_buffer, 0, RECV_BUFFER_SIZE * sizeof(bool_t));

    ctx->seq_num = ctx->initial_sequence_num;

    if(is_active) {
        printf("Sending SYN packet\n");
        ctx->seq_num = ctx->initial_sequence_num;
        packet_send(sd, ctx, NULL, 0, TH_SYN, ctx->seq_num);
        ctx->seq_num++;
        gettimeofday(&ctx->last_send_time, NULL);
        while(ctx->connection_state == SYN_SENT) {
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 1000000 * TIMEOUT_MSECONDS;
            event = stcp_wait_for_event(sd, NETWORK_DATA, &ts);
            if(event & NETWORK_DATA) {
                recv_len = stcp_network_recv(sd, recv_buffer, sizeof(recv_buffer));
                if(recv_len > 0) {
                    STCPHeader *header = (STCPHeader *)recv_buffer;
                    if(header->th_flags & TH_SYN && header->th_flags & TH_ACK) {
                        ctx->ack_num = header->th_seq + 1;
                        ctx->connection_state = SYN_RECEIVED;
                        ctx->cur_window_size = MIN(header->th_win, CONGESTION_WINDOW_SIZE) / MAX_PAYLOAD_SIZE + 1; 
                        ctx->window_threshold = ctx->cur_window_size;
                        packet_send(sd, ctx, NULL, 0, TH_ACK, ctx->seq_num);
                        gettimeofday(&ctx->last_send_time, NULL);
                        printf("SYN+ACK received, sending ACK\n");
                        ctx->connection_state = ESTABLISHED;
                        stcp_unblock_application(sd);
                        break;
                    }
                }
            }
            check_timeout(sd, ctx);
        }
    } else {
        printf("Waiting for SYN packet\n");
        while(ctx->connection_state == LISTEN) {
            event = stcp_wait_for_event(sd, NETWORK_DATA, NULL);
            if(event & NETWORK_DATA) {
                recv_len = stcp_network_recv(sd, recv_buffer, sizeof(recv_buffer));
                if(recv_len > 0) {
                    STCPHeader *header = (STCPHeader *)recv_buffer;
                    if(header->th_flags & TH_SYN) {
                        ctx->ack_num = header->th_seq + 1;
                        ctx->connection_state = SYN_RECEIVED;
                        printf("SYN packet received\n");
                        ctx->seq_num = ctx->initial_sequence_num;
                        ctx->cur_window_size = MIN(CONGESTION_WINDOW_SIZE, header->th_win) / MAX_PAYLOAD_SIZE + 1;
                        ctx->window_threshold = ctx->cur_window_size;
                        packet_send(sd, ctx, NULL, 0, TH_SYN | TH_ACK, ctx->seq_num);
                        ctx->seq_num++;
                        gettimeofday(&ctx->last_send_time, NULL);
                        while(ctx->connection_state == SYN_RECEIVED) {
                            struct timespec ts;
                            ts.tv_sec = 0;
                            ts.tv_nsec = 1000000 * TIMEOUT_MSECONDS;
                            event = stcp_wait_for_event(sd, NETWORK_DATA, &ts);
                            if(event & NETWORK_DATA) {
                                recv_len = stcp_network_recv(sd, recv_buffer, sizeof(recv_buffer));
                                process_in_data(sd, ctx, recv_buffer, recv_len);
                            }
                            check_timeout(sd, ctx);
                        }
                        break;
                    }
                }
            }
        }
        printf("SYN packet received\n");
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

    printf("Control loop started\n");
    while (!ctx->done)
    {
        //printf("Control loop running\n");
        unsigned int event;
        char recv_buffer[MAX_PAYLOAD_SIZE + sizeof(STCPHeader)];
        ssize_t recv_len;
        
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 1000000 * TIMEOUT_MSECONDS;
        event = stcp_wait_for_event(sd, APP_DATA | NETWORK_DATA, &ts);
        //printf("Event received: 0x%x\n", event);

        if(ctx->connection_state == TIMED_WAIT) {
            ts.tv_nsec *= 5;
            event = stcp_wait_for_event(sd, APP_DATA | NETWORK_DATA, &ts);
            if(!(event & NETWORK_DATA)) {
                ctx->done = TRUE;
                ctx->connection_state = CLOSED;
                printf("Client Ended\n");
                break;
            }
        }

        /* check whether it was the network, app, or a close request */
        check_timeout(sd, ctx);
        
        if(event & NETWORK_DATA)
        {
            //printf("Received network data\n");
            recv_len = stcp_network_recv(sd, recv_buffer, sizeof(recv_buffer));
            if (recv_len > 0) {
                process_in_data(sd, ctx, recv_buffer, recv_len);
            }
        }

        if (event & APP_DATA)
        {
            //printf("Received app data\n");
            process_out_data(sd, ctx, FALSE);
        }

        if(event & APP_CLOSE_REQUESTED) {
            //printf("Received app close requested\n");
            //printf("ctx->connection_state: %d\n", ctx->connection_state);
            if(ctx->connection_state == ESTABLISHED) {
                ctx->connection_state = FIN_WAIT_1;
                packet_send(sd, ctx, NULL, 0, TH_FIN, ctx->seq_num);
                ctx->seq_num++;
                gettimeofday(&ctx->last_send_time, NULL);
            } else if(ctx->connection_state == CLOSE_WAIT) {
                ctx->connection_state = LAST_ACK;
                packet_send(sd, ctx, NULL, 0, TH_FIN, ctx->seq_num);
                ctx->seq_num++;
                gettimeofday(&ctx->last_send_time, NULL);
            }
        }
    }
}

static void packet_send(mysocket_t sd, context_t *ctx, char *data, int len, uint8_t flags, int seq_num) {
    char data_send[MAX_PAYLOAD_SIZE + sizeof(STCPHeader)];
    STCPHeader *header = (STCPHeader *)data_send;

    memset(data_send, 0, sizeof(data_send));
    header->th_seq = seq_num;
    header->th_ack = ctx->ack_num;
    header->th_flags = flags;
    header->th_win = RECV_WINDOW_SIZE;
    header->th_off = 5;
    
    //printf("Sending packet: seq=%d, ack=%d, flags=0x%x, win=%d\n", 
    //       header->th_seq, header->th_ack, header->th_flags, header->th_win);

    if(data && len > 0) {
        memmove(data_send + sizeof(STCPHeader), data, len);
    }

    //printf("Sending packet with length %ld\n", sizeof(STCPHeader) + len);
    stcp_network_send(sd, data_send, sizeof(STCPHeader) + len, NULL);
}

static void check_timeout(mysocket_t sd, context_t *ctx) {
    struct timeval now;
    gettimeofday(&now, NULL);
    if(ctx->connection_state == ESTABLISHED && ctx->send_buffer_idx == 0) return;
    if((now.tv_sec - ctx->last_send_time.tv_sec) * 1000 + (now.tv_usec - ctx->last_send_time.tv_usec) / 1000 >= TIMEOUT_MSECONDS) {
        if(ctx->retransmit_count < 6) {
            ctx->cur_window_size = 1;
            if(ctx->window_threshold > 1) {
                ctx->window_threshold /= 2;
            }
            ctx->retransmit_count++;
            switch (ctx->connection_state) {
                case SYN_SENT:
                    packet_send(sd, ctx, NULL, 0, TH_SYN, ctx->seq_num - 1);
                    break;
                case SYN_RECEIVED:
                    packet_send(sd, ctx, NULL, 0, TH_SYN | TH_ACK, ctx->seq_num - 1);
                    break;
                case CLOSE_WAIT:
                case ESTABLISHED:
                    printf("Retransmitting data, retransmit_count: %d\n", ctx->retransmit_count);
                    ctx->sent_buffer_idx = 0;
                    process_out_data(sd, ctx, TRUE);
                    break;
                case FIN_WAIT_1:
                    packet_send(sd, ctx, NULL, 0, TH_FIN, ctx->seq_num - 1);
                    break;
                case LAST_ACK:
                    packet_send(sd, ctx, NULL, 0, TH_FIN, ctx->seq_num - 1);
                    break;
                default:
                    break;
            }
            gettimeofday(&ctx->last_send_time, NULL);
        } else {
            printf("Timeout, closing connection\n");
            ctx->done = TRUE;
            errno = ETIMEDOUT;
        }
    }
}

static void handle_fin(mysocket_t sd, context_t *ctx) {
    if(ctx->connection_state == ESTABLISHED) {
        ctx->connection_state = CLOSE_WAIT;
        ctx->ack_num++;
        //printf("ESTABLISHED -> CLOSE_WAIT\n");
        packet_send(sd, ctx, NULL, 0, TH_ACK, ctx->seq_num);
        stcp_fin_received(sd);
    } else if(ctx->connection_state == FIN_WAIT_2) {
        ctx->connection_state = TIMED_WAIT;
        //printf("FIN_WAIT_2 -> TIMED_WAIT\n");
        ctx->ack_num++;
        packet_send(sd, ctx, NULL, 0, TH_ACK, ctx->seq_num);
        stcp_fin_received(sd);
    }
}

static void process_in_data(mysocket_t sd, context_t *ctx, char *data, int len) {
    STCPHeader *header = (STCPHeader *)data;
    char *payload = data + sizeof(STCPHeader);
    int payload_len = len - sizeof(STCPHeader);

    // printf("Processing incoming data, flags: 0x%x, seq: %d, ack: %d, payload_len: %d\n", 
    //        header->th_flags, header->th_seq, header->th_ack, payload_len);

    if(header->th_flags & TH_ACK) {
        //printf("header->th_ack: %d, ctx->seq_num: %d\n", header->th_ack, ctx->seq_num);
        if(ctx -> connection_state == ESTABLISHED || ctx -> connection_state == CLOSE_WAIT) {
            ctx->retransmit_count = 0;
            if(ctx->cur_window_size < ctx->window_threshold) {
                ctx->cur_window_size = MIN(ctx->cur_window_size * 2, ctx->window_threshold);
            } else {
                ctx->cur_window_size = MIN(ctx->cur_window_size + 1, MIN(CONGESTION_WINDOW_SIZE, header->th_win) / MAX_PAYLOAD_SIZE + 1);
            }
            int del = header->th_ack - ctx->seq_num;
            //printf("ctx->seq_num: %d, header->th_ack: %d\n", ctx->seq_num, header->th_ack);
            if(del == 0) {
                ctx->dup_cnt++;
                if(ctx->dup_cnt == 3) {
                    int siz = MIN(MAX_PAYLOAD_SIZE, ctx->send_buffer_idx);
                    if(siz) packet_send(sd, ctx, ctx->send_buffer, siz, TH_ACK, ctx->seq_num);
                    ctx->dup_cnt = 0;
                }
            } else if(del > 0) {
                ctx->dup_cnt = 0;
                if(del < RECV_WINDOW_SIZE)
                    memmove(ctx->send_buffer, ctx->send_buffer + del, RECV_WINDOW_SIZE - del);
                //printf("Moving send buffer, del: %d, new_idx: %ld\n", del, ctx->send_buffer_idx - del);
                assert(ctx->send_buffer_idx >= del);
                ctx->send_buffer_idx -= del;
                if(ctx->sent_buffer_idx < del) ctx->sent_buffer_idx = 0;
                else ctx->sent_buffer_idx -= del;
                ctx->seq_num = header->th_ack;
            }
            printf("Updated window size to: %d\n", ctx->cur_window_size);
        }
        if(ctx -> connection_state == SYN_RECEIVED && header->th_ack == ctx->seq_num) {
            ctx->connection_state = ESTABLISHED;
            stcp_unblock_application(sd);
        }
        if(ctx->connection_state == FIN_WAIT_1 && header->th_ack == ctx->seq_num) {
            ctx->connection_state = FIN_WAIT_2;
            //printf("FIN_WAIT_1 -> FIN_WAIT_2\n");
        }
        if(ctx->connection_state == LAST_ACK && header->th_ack == ctx->seq_num) {
            printf("Server Ended\n");
            ctx->connection_state = CLOSED;
            //printf("LAST_ACK -> CLOSED\n");
            ctx->done = TRUE;
            return;
        }
    }

    if(payload_len > 0) {
        printf("Received data packet, seq: %d, ack: %d, len: %d\n", 
            header->th_seq, header->th_ack, payload_len);
            
        tcp_seq window_start = ctx->ack_num;
        //printf("Current ack: %d\n", window_start);
        tcp_seq window_end = window_start + RECV_WINDOW_SIZE;
            
        if(header->th_seq >= window_start && header->th_seq < window_end) {
            int valid_len = MIN(payload_len, (int)(window_end - header->th_seq));
            //assert(header->th_seq - window_start + valid_len <= RECV_BUFFER_SIZE);
            
            memmove(ctx->recv_buffer + (header->th_seq - window_start), payload, valid_len);
            
            for(int i = 0; i < valid_len; i++) {
                ctx->get_buffer[header->th_seq - window_start + i] = TRUE;
            }
            
            if(header->th_seq == window_start) {
                int new_start = 0;
                while(new_start < RECV_BUFFER_SIZE && ctx->get_buffer[new_start]) {
                    new_start++;
                }
                if(new_start < RECV_BUFFER_SIZE) {
                    memmove(ctx->get_buffer, ctx->get_buffer + new_start, (RECV_BUFFER_SIZE - new_start) * sizeof(bool_t));
                }
                memset(ctx->get_buffer + RECV_BUFFER_SIZE - new_start, 0, new_start * sizeof(bool_t));
                int valid_len = new_start;
                if(valid_len > 0) {
                    ctx->ack_num += valid_len;
                    printf("Sending data to application, len: %d\n", valid_len);
                    stcp_app_send(sd, ctx->recv_buffer, valid_len);
                    memmove(ctx->recv_buffer, ctx->recv_buffer + valid_len, RECV_BUFFER_SIZE - valid_len);
                }
            }
            packet_send(sd, ctx, NULL, 0, TH_ACK, ctx->seq_num);
        } else if(header->th_seq < window_start) {
            printf("Packet with seq %d is before window start %d\n", header->th_seq, window_start);
            tcp_seq message_end = header->th_seq + payload_len - 1;
            if(message_end >= window_start) {
                int overlap_start = window_start - header->th_seq;
                int overlap_len = MIN(payload_len - overlap_start, RECV_WINDOW_SIZE);
                assert(overlap_len > 0);
                
                memmove(ctx->recv_buffer, payload + overlap_start, overlap_len);
                for(int i = 0; i < overlap_len; i++) {
                    ctx->get_buffer[i] = TRUE;
                }
                
                int new_start = 0;
                while(new_start < RECV_BUFFER_SIZE && ctx->get_buffer[new_start]) {
                    new_start++;
                }
                if(new_start < RECV_BUFFER_SIZE) {
                    memmove(ctx->get_buffer, ctx->get_buffer + new_start, (RECV_BUFFER_SIZE - new_start) * sizeof(bool_t));
                }
                memset(ctx->get_buffer + RECV_BUFFER_SIZE - new_start, 0, new_start * sizeof(bool_t));
                int valid_len = new_start;
                if(valid_len > 0) {
                    ctx->ack_num += valid_len;
                    printf("Sending data to application, len: %d\n", valid_len);
                    stcp_app_send(sd, ctx->recv_buffer, valid_len);
                    memmove(ctx->recv_buffer, ctx->recv_buffer + valid_len, RECV_BUFFER_SIZE - valid_len);
                }
            }
            packet_send(sd, ctx, NULL, 0, TH_ACK, ctx->seq_num);
        } else {
            printf("Packet with seq %d is after window end %d\n", header->th_seq, window_end);
        }
    }
    if(header->th_flags & TH_FIN) {
        handle_fin(sd, ctx);
    }
}
    
static void process_out_data(mysocket_t sd, context_t *ctx, bool_t is_retransmit) {
    if(ctx->connection_state != ESTABLISHED && ctx->connection_state != CLOSE_WAIT) {
        printf("Connection not established, cannot send data\n");
        return;
    }
    if(is_retransmit) {
        //printf("process_out_data, is_retransmit: %d\n", is_retransmit);
    } else {
    //printf("process_out_data\n");
    }
    int len = RECV_WINDOW_SIZE - ctx->send_buffer_idx;
    if(len > 0 && !is_retransmit) {
        //printf("Receiving data from application, len: %d\n", len);
        len = stcp_app_recv(sd, ctx->send_buffer + ctx->send_buffer_idx, len);
        //printf("Received data from application, len: %d\n", len);
        if(len > 0) {
            ctx->send_buffer_idx += len;
        }
    }

    //printf("sent_buffer_idx: %d, send_buffer_idx: %d\n", ctx->sent_buffer_idx, ctx->send_buffer_idx);
    tcp_seq window_start = ctx->sent_buffer_idx;
    tcp_seq window_end = MIN(ctx->cur_window_size * MAX_PAYLOAD_SIZE, ctx->send_buffer_idx);
    //printf("ctx->cur_window_size: %ld, ctx->send_buffer_idx: %ld\n", ctx->sent_buffer_idx, ctx->send_buffer_idx);
    //printf("window_start: %d, window_end: %d\n", window_start, window_end);

    for(unsigned int i = window_start; i < window_end;) {
        int size = MIN(window_end - i, MAX_PAYLOAD_SIZE);
        printf("Sending data packet, seq: %d, len: %d, i: %d\n", ctx->seq_num + i, size, i);
        packet_send(sd, ctx, ctx->send_buffer + i, size, TH_ACK, ctx->seq_num + i);
        i += size;
        gettimeofday(&ctx->last_send_time, NULL);
    }
    ctx->sent_buffer_idx = window_end;
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



