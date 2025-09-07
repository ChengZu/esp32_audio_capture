/*
 * SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_err.h"
#include "esp_check.h"

static const char *TAG = "OTA";

const esp_partition_t *ota_partition;
esp_ota_handle_t ota_handle;

void ota_update(uint8_t *data, size_t size)
{
    ESP_ERROR_CHECK(esp_ota_write(ota_handle, data, size));
}

void ota_begin(void)
{
    ota_partition = esp_ota_get_next_update_partition(NULL);
    if (!ota_partition)
    {
        ESP_LOGE(TAG, "No OTA partition found");
        return;
    }

    ESP_ERROR_CHECK(esp_ota_begin(ota_partition, OTA_SIZE_UNKNOWN, &ota_handle));
    ESP_LOGI(TAG, "OTA process started");
}

void ota_end(void)
{
    ESP_ERROR_CHECK(esp_ota_end(ota_handle));
    ESP_ERROR_CHECK(esp_ota_set_boot_partition(ota_partition));
    ESP_LOGI(TAG, "OTA update successful. Rebooting...");
    esp_restart();
}
