#include <stdio.h>

#include "nvs_flash.h"
#include "wifi.h"

#include "yandex_ota.h"

static const char *TAG = "APP";

WiFiHandler_t wifi_handler;
TaskHandle_t *xOtaTaskHandle;

void wifi_sta_start_cb(void *context){
    ESP_LOGI(TAG, "START WIFI STA");
}
void wifi_connected_cb(void *context){
    ESP_LOGI(TAG, "CONNECTED TO WI-FI");
}
void wifi_disconnected_cb(void *context){
    ESP_LOGI(TAG, "DISCONNECTED FROM WI-FI");
}
void wifi_got_ip_cb(void *context){
    ESP_LOGI(TAG, "GOT IP");
    yandex_ota_task_wake_up();
}

void firmware_upgrade_before_cb(void *context){

}


void app_main(void)
{
    ESP_LOGI(TAG, "APP STARTED!");

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND){
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    yandex_ota_init(firmware_upgrade_before_cb, NULL);

    wifi_handler.wifi_connected_callback    = wifi_connected_cb;
    wifi_handler.wifi_disconnected_callback = wifi_disconnected_cb;
    wifi_handler.wifi_sta_start_callback    = wifi_sta_start_cb;
    wifi_handler.wifi_got_ip_callback       = wifi_got_ip_cb;

    wifi_init_sta(&wifi_handler);
}