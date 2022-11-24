#pragma once

//#include "task.h"
//#include "portmacro.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "esp_crt_bundle.h"

#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"


#define WEB_SERVER  "d5di58c3noai2uije3r3.apigw.yandexcloud.net"
#define WEB_PORT    "443"
#define WEB_URL     "https://d5di58c3noai2uije3r3.apigw.yandexcloud.net"

#define MAX_RX_BUF_LEN  1024
#define HASH_LEN        32

#define CONFIG_EXAMPLE_SKIP_VERSION_CHECK 1



void yandex_ota_init(void (*cb_check_fw_header_success)(void *context), void (*cb_fw_write_success)(void *context));
void yandex_ota_task_wake_up(void);

