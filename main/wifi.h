#pragma once

#include "main.h"

#define APP_WIFI_SSID "Netzwerk"
#define APP_WIFI_SSID "ubuntu56@brahamDC"
#define APP_MAX_RETRY 5


typedef struct {
    void (*wifi_sta_start_callback)(void *context);
    void (*wifi_connected_callback)(void *context);
    void (*wifi_disconnected_callback)(void *context);
    void (*wifi_got_ip_callback)(void *context);
} WiFiHandler_t;

void wifi_init_sta(WiFiHandler_t *wifi_handler);