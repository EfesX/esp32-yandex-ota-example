#include "yandex_ota.h"

void (*ota_before_cb)(void *context) = NULL;
void (*ota_after_cb)(void *context) = NULL;

static const char REQUEST[] = "GET https://" WEB_SERVER " HTTP/1.1\r\n"
    "Host: "WEB_SERVER"\r\n"
    "User-Agent: esp-idf/1.0 esp32\r\n"
    "Connection: close\r\n"
    "\r\n";

static TaskHandle_t xTaskFirmwareUpgrade = NULL;

static const char *OTA_TAG = "OTA";

char ota_write_data[MAX_RX_BUF_LEN + 1] = {0};

void print_sha256(const uint8_t *image_hash, const char *label){
    char hash_print[HASH_LEN];
    for (int i = 0; i < HASH_LEN - 1; ++i) {
        sprintf(&hash_print[i], "%x", image_hash[i]);
    }
    ESP_LOGI(OTA_TAG, "%s: %s", label, hash_print);
}

static void ota_upgrade_firmware_task(void *p){
    int tls_ret, flags, len;

    esp_err_t ota_err = ESP_FAIL;

    esp_ota_handle_t update_handle = 0;
    const esp_partition_t *update_partition = NULL;

    const esp_partition_t *configured   = esp_ota_get_boot_partition();
    const esp_partition_t *running      = esp_ota_get_running_partition();

    if (configured != running){
        ESP_LOGI(OTA_TAG, "Configured OTA boot partition at offset 0x%08x, but running from offset 0x%08x", configured->address, running->address);
        ESP_LOGI(OTA_TAG, "(This can happen if either the OTA boot data or preferred boot image become corrupted somehow.)");
    }
    ESP_LOGI(OTA_TAG, "Running partition type %d subtype %d (offset 0x%08x)", running->type, running->subtype, running->address);


    update_partition = esp_ota_get_next_update_partition(NULL);
    assert(update_partition != 0);
    ESP_LOGI(OTA_TAG, "Subtype of update partition %d at offset 0x%x", update_partition->subtype, update_partition->address);

    bool image_header_was_checked = false;

    int binary_file_length = 0;
    int magic_byte_position = 0;


    mbedtls_entropy_context     entropy;
    mbedtls_ctr_drbg_context    ctr_drbg;
    mbedtls_ssl_context         ssl;
    mbedtls_x509_crt            cacert;
    mbedtls_ssl_config          conf;
    mbedtls_net_context         server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(OTA_TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if((tls_ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0){
        ESP_LOGE(OTA_TAG, "mbedtls_ctr_drbg_seed returned %d [%s]", tls_ret, esp_err_to_name(tls_ret));
        abort();
    }
    ESP_LOGI(OTA_TAG, "Attaching the certificate bundle...");

    tls_ret = esp_crt_bundle_attach(&conf);
    if (tls_ret < 0){
        ESP_LOGE(OTA_TAG, "esp_crt_bundle_attach returned -0x%x [%s]\n\n", -tls_ret, esp_err_to_name(tls_ret));
        abort();
    }
    ESP_LOGI(OTA_TAG, "Setting hostname for TLS session...");

    if((tls_ret = mbedtls_ssl_set_hostname(&ssl, WEB_SERVER)) != 0){
        ESP_LOGE(OTA_TAG, "mbedtls_ssl_set_hostname returned -0x%x [%s]", -tls_ret, esp_err_to_name(tls_ret));
        abort();
    }

    ESP_LOGI(OTA_TAG, "Setting up the SSL/TLS structure...");

    if((tls_ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0){
        ESP_LOGE(OTA_TAG, "mbedtls_ssl_config_defaults returned %d [%s]", tls_ret, esp_err_to_name(tls_ret));
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    #ifdef CONFIG_MBEDTLS_DEBUG
        mbedtls_esp_enable_debug_log(&conf, CONFIG_MBEDTLS_DEBUG_LEVEL);
    #endif

    if ((tls_ret = mbedtls_ssl_setup(&ssl, &conf)) != 0){
        ESP_LOGE(OTA_TAG, "mbedtls_ssl_setup returned -0x%x [%s]\n\n", -tls_ret, esp_err_to_name(tls_ret));
        goto exit;
    }

    while(1){
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        mbedtls_net_init(&server_fd);

        ESP_LOGI(OTA_TAG, "Connecting to %s:%s", WEB_SERVER, WEB_PORT);
        if ((tls_ret = mbedtls_net_connect(&server_fd, WEB_SERVER, WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0){
            ESP_LOGE(OTA_TAG, "mbedtls_net_connect returned -%x", -tls_ret);
            goto exit;
        }
        ESP_LOGI(OTA_TAG, "Connected.");

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        ESP_LOGI(OTA_TAG, "Performing the SSL/TLS handshake...");
        while ((tls_ret = mbedtls_ssl_handshake(&ssl)) != 0){
            if (tls_ret != MBEDTLS_ERR_SSL_WANT_READ && tls_ret != MBEDTLS_ERR_SSL_WANT_WRITE){
                ESP_LOGE(OTA_TAG, "mbedtls_ssl_handshake returned -0x%x [%s]", -tls_ret, esp_err_to_name(tls_ret));
                goto exit;
            }
        }
        ESP_LOGI(OTA_TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0){
            ESP_LOGW(OTA_TAG, "Failed to verify peer certificate!");
            bzero(ota_write_data, sizeof(ota_write_data));
            mbedtls_x509_crt_verify_info(ota_write_data, sizeof(ota_write_data), "  ! ", flags);
            ESP_LOGW(OTA_TAG, "verification info: %s", ota_write_data);
        }
        else {
            ESP_LOGI(OTA_TAG, "Certificate verified.");
        }
        ESP_LOGI(OTA_TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ssl));
        ESP_LOGI(OTA_TAG, "Writing HTTP request...");

        size_t written_bytes = 0;
        do {
            tls_ret = mbedtls_ssl_write(&ssl, (const unsigned char *)REQUEST + written_bytes, strlen(REQUEST) - written_bytes);
            if (tls_ret >= 0) {
                ESP_LOGI(OTA_TAG, "%d bytes written", tls_ret);
                written_bytes += tls_ret;
            } else if (tls_ret != MBEDTLS_ERR_SSL_WANT_WRITE && tls_ret != MBEDTLS_ERR_SSL_WANT_READ) {
                ESP_LOGE(OTA_TAG, "mbedtls_ssl_write returned -0x%x [%s]", -tls_ret, esp_err_to_name(tls_ret));
                goto exit;
            }
        } while(written_bytes < strlen(REQUEST));
        ESP_LOGI(OTA_TAG, "Reading HTTP response...");

        do {
            len = sizeof(ota_write_data) - 1;
            bzero(ota_write_data, sizeof(ota_write_data));
            tls_ret = mbedtls_ssl_read(&ssl, (unsigned char *)ota_write_data, len);

            if(tls_ret == MBEDTLS_ERR_SSL_WANT_READ || tls_ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if(tls_ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                tls_ret = 0;
                break;
            }

            if(tls_ret < 0){
                ESP_LOGE(OTA_TAG, "mbedtls_ssl_read returned -0x%x [%s]", -tls_ret, esp_err_to_name(tls_ret));
                break;
            }
            if(tls_ret == 0){
                ESP_LOGI(OTA_TAG, "connection closed");
                break;
            }

            len = tls_ret;

            if(image_header_was_checked == false){
                
                for (int i = 0; i < MAX_RX_BUF_LEN; i++){
                    if ((uint8_t)ota_write_data[i] == 0xe9){
                        magic_byte_position = i;
                        break;
                    }
                }

                esp_app_desc_t new_app_info;
                if (len > magic_byte_position + sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t)) {
                    memcpy(&new_app_info, &ota_write_data[magic_byte_position + sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t)], sizeof(esp_app_desc_t));
                    print_sha256(new_app_info.app_elf_sha256, "New firmware SHA256");

                    esp_app_desc_t running_app_info;
                    if (esp_ota_get_partition_description(running, &running_app_info) == ESP_OK) {
                        print_sha256(running_app_info.app_elf_sha256, "Running firmware SHA256");
                    }

                    const esp_partition_t* last_invalid_app = esp_ota_get_last_invalid_partition();
                    esp_app_desc_t invalid_app_info;
                    if (esp_ota_get_partition_description(last_invalid_app, &invalid_app_info) == ESP_OK) {
                        ESP_LOGI(OTA_TAG, "Last invalid firmware SHA256: %s", invalid_app_info.app_elf_sha256);
                    }

                    if (last_invalid_app != NULL) {
                        if (memcmp(invalid_app_info.version, new_app_info.version, sizeof(new_app_info.version)) == 0) {
                            ESP_LOGW(OTA_TAG, "New version is the same as invalid version.");
                            ESP_LOGW(OTA_TAG, "Previously, there was an attempt to launch the firmware with %s version, but it failed.", invalid_app_info.version);
                            ESP_LOGW(OTA_TAG, "The firmware has been rolled back to the previous version.");
                            goto exit;
                        }
                    }
#ifndef CONFIG_EXAMPLE_SKIP_VERSION_CHECK
                    if (memcmp(new_app_info.app_elf_sha256, running_app_info.app_elf_sha256, sizeof(new_app_info.app_elf_sha256)) == 0) {
                        ESP_LOGI(OTA_TAG, "Current running version is the same as a new. We will not continue the update.");
                        goto exit;
                    }
#endif

                    image_header_was_checked = true;
                    
                    ota_err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &update_handle);
                    if (ota_err != ESP_OK) {
                        ESP_LOGE(OTA_TAG, "esp_ota_begin failed (%s)", esp_err_to_name(ota_err));
                        esp_ota_abort(update_handle);
                        goto exit;
                    }
                    ESP_LOGI(OTA_TAG, "esp_ota_begin succeeded");
                    if (ota_before_cb != NULL){
                        ota_before_cb(&new_app_info);
                    }
                } else {
                    ESP_LOGE(OTA_TAG, "received package is not fit len");
                    ESP_LOGE(OTA_TAG, "%d < %d", len, magic_byte_position + sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t));
                    esp_ota_abort(update_handle);
                    goto exit;
                }
            } else {
                magic_byte_position = 0;
            }

            ota_err = esp_ota_write( update_handle, &ota_write_data[magic_byte_position], len - magic_byte_position);
            if (ota_err != ESP_OK) {
                esp_ota_abort(update_handle);
                goto exit;
            }

            binary_file_length += len;
            ESP_LOGD(OTA_TAG, "Written image length %d", binary_file_length);

        } while(1);

        ESP_LOGI(OTA_TAG, "Total Write binary data length: %d", binary_file_length);

        ota_err = esp_ota_end(update_handle);
        if (ota_err != ESP_OK) {
            if (ota_err == ESP_ERR_OTA_VALIDATE_FAILED) {
                ESP_LOGE(OTA_TAG, "Image validation failed, image is corrupted");
            } else {
                ESP_LOGE(OTA_TAG, "esp_ota_end failed (%s)!", esp_err_to_name(ota_err));
            }
            goto exit;
        }

        ota_err = esp_ota_set_boot_partition(update_partition);
        if (ota_err != ESP_OK) {
            ESP_LOGE(OTA_TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(ota_err));
            goto exit;
        }
        ESP_LOGI(OTA_TAG, "Prepare to restart system!");

        if (ota_after_cb != NULL){
            ota_after_cb(&update_partition);
        }
        
        break;
    }

    exit:
        mbedtls_ssl_close_notify(&ssl);
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if(tls_ret != 0){
            mbedtls_strerror(tls_ret, ota_write_data, 100);
            ESP_LOGE(OTA_TAG, "Last tls error was: -0x%x - %s", -tls_ret, ota_write_data);
        }

        static int request_count;
        ESP_LOGI(OTA_TAG, "Completed %d requests", ++request_count);
        printf("Minimum free heap size: %d bytes\n", esp_get_minimum_free_heap_size());

        for(int countdown = 10; countdown >= 0; countdown--) {
            ESP_LOGI(OTA_TAG, "%d...", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        
        if (ota_err == ESP_OK){
            esp_restart();
        }

        vTaskDelete(NULL);
        ESP_LOGI(OTA_TAG, "Upgrade's task is deleted");
}

void yandex_ota_init(void (*cb_check_fw_header_success)(void *context), void (*cb_fw_write_success)(void *context)){
    ota_before_cb   = cb_check_fw_header_success;
    ota_after_cb    = cb_fw_write_success;

    xTaskCreate(&ota_upgrade_firmware_task, "https_ota_task", 8192, NULL, 5, &xTaskFirmwareUpgrade);
}

void yandex_ota_task_wake_up(void){
    xTaskNotifyGive(xTaskFirmwareUpgrade);
}
