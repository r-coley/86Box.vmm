#pragma once
#include <stdint.h>

#define VMN_SOCK_PATH "/var/run/vmnet-helper.sock"

enum {
    VMN_MODE_SHARED    = 1,
    VMN_MODE_HOST      = 2,
    VMN_MODE_BRIDGED   = 3,
    VMN_MODE_PUBLISHED = 4
};

enum {
    VMN_MSG_START      = 1,
    VMN_MSG_START_OK   = 2,
    VMN_MSG_START_ERR  = 3,
    VMN_MSG_SEND_FRAME = 4,
    VMN_MSG_RX_FRAME   = 5,
    VMN_MSG_STOP       = 6,
    VMN_MSG_STOPPED    = 7
};

typedef struct {
    uint32_t type;
    uint32_t length;
} vmn_msg_hdr_t;

typedef struct {
    uint32_t mode;
    uint32_t published_ip; /* network byte order; used by published mode */
    char     guest_ip[16]; /* dotted-quad guest static IP chosen in UI */
} vmn_start_req_t;

typedef struct {
    int32_t code;
} vmn_start_err_t;
