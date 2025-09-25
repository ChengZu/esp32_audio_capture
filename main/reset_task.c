#include <stdint.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/i2s_std.h"
#include "driver/gpio.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_check.h"
#include "sdkconfig.h"

#define GPIO_NUM_RESET (7)
static const char *TAG = "device_reset";
int last_read_rest_time = 0;

static bool reset_device()
{
    esp_err_t ret;
    nvs_handle_t wifi_nvs_handle;
    // 初始化 NVS
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // 打开 'my_nvs' 分区
    ret = nvs_open("wifi_nvs", NVS_READWRITE, &wifi_nvs_handle);
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "Error (%d) opening NVS handle!", ret);
    }
    else
    {
        // 写入新的字符串
        ret = nvs_set_i32(wifi_nvs_handle, "wifi_mode", 1);
        if (ret != ESP_OK)
        {
            ESP_LOGE(TAG, "Error (%d) writing to NVS", ret);
        }
        else
        {
            // 将更改保存到 NVS
            ret = nvs_commit(wifi_nvs_handle);
            if (ret != ESP_OK)
            {
                ESP_LOGE(TAG, "Error (%d) committing NVS", ret);
            }
        }

        ret = nvs_set_str(wifi_nvs_handle, "wifi_ssid", "");
        if (ret != ESP_OK)
        {
            ESP_LOGE(TAG, "Error (%d) writing to NVS", ret);
        }
        else
        {
            // 将更改保存到 NVS
            ret = nvs_commit(wifi_nvs_handle);
            if (ret != ESP_OK)
            {
                ESP_LOGE(TAG, "Error (%d) committing NVS", ret);
            }
        }

        ret = nvs_set_str(wifi_nvs_handle, "wifi_password", "");
        if (ret != ESP_OK)
        {
            ESP_LOGE(TAG, "Error (%d) writing to NVS", ret);
        }
        else
        {
            // 将更改保存到 NVS
            ret = nvs_commit(wifi_nvs_handle);
            if (ret != ESP_OK)
            {
                ESP_LOGE(TAG, "Error (%d) committing NVS", ret);
            }
        }

        // 关闭 NVS 句柄
        nvs_close(wifi_nvs_handle);
    }
    ESP_LOGI(TAG, "rebooting...");
    // 延迟2秒后重启
    vTaskDelay(10 / portTICK_PERIOD_MS);
    esp_restart(); // 触发重启
    return ESP_OK;
}

static void reset_io_read_task(void *args)
{
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << GPIO_NUM_RESET),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE, // 启用上拉电阻
        .pull_down_en = GPIO_PULLDOWN_ENABLE,
        .intr_type = GPIO_INTR_DISABLE};
    gpio_config(&io_conf);

    while (1)
    {
        int gpio_state = gpio_get_level(GPIO_NUM_RESET); // 读取GPIO状态，0为低电平，非0为高电平
        if (gpio_state == 1)
        {
            last_read_rest_time += 100;
            if (last_read_rest_time >= 3000)
            {
                ESP_LOGI(TAG, "last_read_rest_time:%d", last_read_rest_time);
                reset_device();
            }
        }
        else
        {
            if (last_read_rest_time > 0 && last_read_rest_time < 3000)
            {
                ESP_LOGI(TAG, "key press rebooting...");
                esp_restart(); // 触发重启
            }
            last_read_rest_time = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    vTaskDelete(NULL);
}

void reset_app_main(void)
{
    xTaskCreate(reset_io_read_task, "reset_io_read_task", 4096, NULL, 5, NULL);
}