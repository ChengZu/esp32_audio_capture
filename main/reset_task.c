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

#define GPIO_NUM_RESET (8)
static const char *TAG = "reset_device";
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
    vTaskDelay(2000 / portTICK_PERIOD_MS);
    esp_restart(); // 触发重启
    return ESP_OK;
}

static void reset_io_read_task(void *args)
{
    while (1)
    {
        int gpio_state = gpio_get_level(GPIO_NUM_RESET); // 读取GPIO状态，0为低电平，非0为高电平
        if (gpio_state == 1)
        {
            last_read_rest_time += 500;
            if (last_read_rest_time >= 3000)
            {
                reset_device();
            }
        }
        else
        {
            last_read_rest_time = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    vTaskDelete(NULL);
}

void reset_app_main(void)
{
    esp_rom_gpio_pad_select_gpio(GPIO_NUM_RESET);        // 选择GPIO编号
    gpio_set_direction(GPIO_NUM_RESET, GPIO_MODE_INPUT); // 设置GPIO方向为输入
    xTaskCreate(reset_io_read_task, "reset_io_read_task", 4096, NULL, 5, NULL);
}