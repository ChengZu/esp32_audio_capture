#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"

extern void softap_app_main(void);
extern void station_app_main(void);
void reset_app_main(void);
extern void i2s_app_main(void);
extern void htpp_server_app_main(void);

int wifi_mode = 1; // 0: Station, 1: SoftAP, 2: Both
static const char *TAG = "main";

void read_config(void)
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
        // 读取并输出字符串
        ret = nvs_get_i32(wifi_nvs_handle, "wifi_mode", (int32_t *)&wifi_mode);
        switch (ret)
        {
        case ESP_OK:
            ESP_LOGI(TAG, "Read string from NVS: %i", wifi_mode);
            break;
        case ESP_ERR_NVS_NOT_FOUND:
            ESP_LOGW(TAG, "Value not found in NVS");
            break;
        default:
            ESP_LOGE(TAG, "Error (%d) reading from NVS", ret);
        }

        // 关闭 NVS 句柄
        nvs_close(wifi_nvs_handle);
    }
}

void app_main(void)
{
    read_config();
    ESP_LOGI(TAG, "Starting application with wifi_mode: %d", wifi_mode);
    if (wifi_mode == 0)
    {
        ESP_LOGI(TAG, "Starting Station mode");
        station_app_main();
    }
    else if (wifi_mode == 1)
    {
        ESP_LOGI(TAG, "Starting SoftAP mode");
        softap_app_main();
    }
    
    htpp_server_app_main();
    i2s_app_main();
    reset_app_main();
}