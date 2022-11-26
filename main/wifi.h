#pragma once

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"



#define APP_WIFI_SSID CONFIG_WIFI_SSID
#define APP_WIFI_PASS CONFIG_WIFI_PASSWORD
#define APP_MAX_RETRY 5


typedef struct {
    void (*wifi_sta_start_callback)(void *context);
    void (*wifi_connected_callback)(void *context);
    void (*wifi_disconnected_callback)(void *context);
    void (*wifi_got_ip_callback)(void *context);
} WiFiHandler_t;

void wifi_init_sta(WiFiHandler_t *wifi_handler);