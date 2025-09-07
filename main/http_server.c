/* Simple HTTP Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <esp_log.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "esp_system.h"
#include "esp_netif.h"
#include "esp_tls_crypto.h"
#include <esp_http_server.h>
#include "esp_http_server.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_tls.h"
#include "esp_check.h"
#include "esp_random.h"
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include "cJSON.h"
#include "esp_check.h"
#include "sdkconfig.h"
#if !CONFIG_IDF_TARGET_LINUX
#include <esp_wifi.h>
#include <esp_system.h>
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_eth.h"
#endif // !CONFIG_IDF_TARGET_LINUX
#include "lwip/sockets.h"
#include "lwip/priv/sockets_priv.h"
#include "i2s_std.h"

#define EXAMPLE_HTTP_QUERY_KEY_MAX_LEN (64)
#define WS_CLIENT_NUM (4)

static const char *TAG = "http_server";
extern QueueHandle_t audio_queue;

int ws_data_send_task = -1;

/*
 * Structure holding server handle
 * and internal socket fd in order
 * to use out of request send
 */
struct async_resp_arg
{
    httpd_handle_t hd;
    int fd;
    bool active;
};
struct async_resp_arg ws_client[WS_CLIENT_NUM];

void vTaskSendAudio(void *pvParameters)
{
    uint8_t *buf = (uint8_t *)malloc(BUFF_SIZE * AUDIO_QUEUE_SIZE);

    audio_data_t audio_data = {0};
    bool noError = true;
    while (noError)
    {
        size_t size = 0;
        for (int i = 0; i < AUDIO_QUEUE_SIZE; i++)
        {
            if (xQueueReceive(audio_queue, &audio_data, pdMS_TO_TICKS(0)) == pdPASS)
            {
                memcpy(buf + size, &audio_data, audio_data.size);
                size += audio_data.size;
            }
            else
            {
                break;
            }
        }

        bool hasClient = false;
        if (size > 0)
        {
            httpd_ws_frame_t ws_pkt;
            memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
            ws_pkt.payload = (uint8_t *)buf;
            ws_pkt.len = size;
            ws_pkt.type = HTTPD_WS_TYPE_BINARY;
            for (int i = 0; i < WS_CLIENT_NUM; i++)
            {
                if (ws_client[i].active)
                {
                    int status = lwip_fcntl(ws_client[i].fd, F_GETFL, 0);
                    if (status != -1)
                    {
                        esp_err_t result = httpd_ws_send_frame_async(ws_client[i].hd, ws_client[i].fd, &ws_pkt);
                        if (result != ESP_OK)
                        {
                            ws_client[i].active = false;
                            ESP_LOGE("WebSocket", "Frame send request failed");
                        }
                        else
                        {
                            hasClient = true;
                        }
                    }
                    else
                    {
                        ws_client[i].active = false;
                    }
                }
            }
            if (!hasClient)
            {
                noError = false;
            }
        }
        else
        {
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }

    free(buf);
    ws_data_send_task = -1;
    ESP_LOGI("WebSocket", "All client diconnect.");
    vTaskDelete(NULL); // 删除当前任务
}

/*
 * async send function, which we put into the httpd work queue
 */
static void ws_async_send(void *arg)
{
    struct async_resp_arg *resp_arg = arg;
    bool active = false;
    for (int i = 0; i < WS_CLIENT_NUM; i++)
    {
        if (!ws_client[i].active)
        {
            ws_client[i].fd = resp_arg->fd;
            ws_client[i].hd = resp_arg->hd;
            ws_client[i].active = true;
            active = true;
            break;
        }
    }
    if (active == false)
    {
        ws_client[0].fd = resp_arg->fd;
        ws_client[0].hd = resp_arg->hd;
        ws_client[0].active = true;
    }

    if (ws_data_send_task == -1)
    {
        xQueueReset(audio_queue);
        ws_data_send_task = xTaskCreate(vTaskSendAudio, "vTaskSendAudio", 8192, NULL, 5, NULL);
    }
    free(resp_arg);
}

static esp_err_t trigger_async_send(httpd_handle_t handle, httpd_req_t *req)
{
    struct async_resp_arg *resp_arg = malloc(sizeof(struct async_resp_arg));
    if (resp_arg == NULL)
    {
        return ESP_ERR_NO_MEM;
    }
    resp_arg->hd = req->handle;
    resp_arg->fd = httpd_req_to_sockfd(req);
    esp_err_t ret = httpd_queue_work(handle, ws_async_send, resp_arg);
    if (ret != ESP_OK)
    {
        free(resp_arg);
    }
    return ret;
}

/*
 * This handler echos back the received ws data
 * and triggers an async send if certain message received
 */
static esp_err_t audio_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET)
    {
        ESP_LOGI(TAG, "Handshake done, the new connection was opened");
        return ESP_OK;
    }
    httpd_ws_frame_t ws_pkt;
    uint8_t *buf = NULL;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;
    /* Set max_len = 0 to get the frame len */
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "httpd_ws_recv_frame failed to get frame len with %d", ret);
        return ret;
    }
    // ESP_LOGI(TAG, "frame len is %d", ws_pkt.len);
    if (ws_pkt.len)
    {
        /* ws_pkt.len + 1 is for NULL termination as we are expecting a string */
        buf = calloc(1, ws_pkt.len + 1);
        if (buf == NULL)
        {
            ESP_LOGE(TAG, "Failed to calloc memory for buf");
            return ESP_ERR_NO_MEM;
        }
        ws_pkt.payload = buf;
        /* Set max_len = ws_pkt.len to get the frame payload */
        ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
        if (ret != ESP_OK)
        {
            ESP_LOGE(TAG, "httpd_ws_recv_frame failed with %d", ret);
            free(buf);
            return ret;
        }
        // ESP_LOGI(TAG, "Got packet with message: %s", ws_pkt.payload);
    }
    // ESP_LOGI(TAG, "Packet type: %d", ws_pkt.type);
    if (ws_pkt.type == HTTPD_WS_TYPE_TEXT &&
        strcmp((char *)ws_pkt.payload, "Trigger async") == 0)
    {
        free(buf);
        return trigger_async_send(req->handle, req);
    }

    ret = httpd_ws_send_frame(req, &ws_pkt);
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "httpd_ws_send_frame failed with %d", ret);
    }
    free(buf);
    return ret;
}

static const httpd_uri_t ws_audio = {
    .uri = "/audio",
    .method = HTTP_GET,
    .handler = audio_handler,
    .user_ctx = NULL,
    .is_websocket = true};

#if CONFIG_EXAMPLE_BASIC_AUTH

typedef struct
{
    char *username;
    char *password;
} basic_auth_info_t;

#define HTTPD_401 "401 UNAUTHORIZED" /*!< HTTP Response 401 */

static char *http_auth_basic(const char *username, const char *password)
{
    size_t out;
    char *user_info = NULL;
    char *digest = NULL;
    size_t n = 0;
    int rc = asprintf(&user_info, "%s:%s", username, password);
    if (rc < 0)
    {
        ESP_LOGE(TAG, "asprintf() returned: %d", rc);
        return NULL;
    }

    if (!user_info)
    {
        ESP_LOGE(TAG, "No enough memory for user information");
        return NULL;
    }
    esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *)user_info, strlen(user_info));

    /* 6: The length of the "Basic " string
     * n: Number of bytes for a base64 encode format
     * 1: Number of bytes for a reserved which be used to fill zero
     */
    digest = calloc(1, 6 + n + 1);
    if (digest)
    {
        strcpy(digest, "Basic ");
        esp_crypto_base64_encode((unsigned char *)digest + 6, n, &out, (const unsigned char *)user_info, strlen(user_info));
    }
    free(user_info);
    return digest;
}

/* An HTTP GET handler */
static esp_err_t basic_auth_get_handler(httpd_req_t *req)
{
    char *buf = NULL;
    size_t buf_len = 0;
    basic_auth_info_t *basic_auth_info = req->user_ctx;

    buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
    if (buf_len > 1)
    {
        buf = calloc(1, buf_len);
        if (!buf)
        {
            ESP_LOGE(TAG, "No enough memory for basic authorization");
            return ESP_ERR_NO_MEM;
        }

        if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK)
        {
            ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
        }
        else
        {
            ESP_LOGE(TAG, "No auth value received");
        }

        char *auth_credentials = http_auth_basic(basic_auth_info->username, basic_auth_info->password);
        if (!auth_credentials)
        {
            ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
            free(buf);
            return ESP_ERR_NO_MEM;
        }

        if (strncmp(auth_credentials, buf, buf_len))
        {
            ESP_LOGE(TAG, "Not authenticated");
            httpd_resp_set_status(req, HTTPD_401);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
            httpd_resp_send(req, NULL, 0);
        }
        else
        {
            ESP_LOGI(TAG, "Authenticated!");
            char *basic_auth_resp = NULL;
            httpd_resp_set_status(req, HTTPD_200);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            int rc = asprintf(&basic_auth_resp, "{\"authenticated\": true,\"user\": \"%s\"}", basic_auth_info->username);
            if (rc < 0)
            {
                ESP_LOGE(TAG, "asprintf() returned: %d", rc);
                free(auth_credentials);
                return ESP_FAIL;
            }
            if (!basic_auth_resp)
            {
                ESP_LOGE(TAG, "No enough memory for basic authorization response");
                free(auth_credentials);
                free(buf);
                return ESP_ERR_NO_MEM;
            }
            httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
            free(basic_auth_resp);
        }
        free(auth_credentials);
        free(buf);
    }
    else
    {
        ESP_LOGE(TAG, "No auth header received");
        httpd_resp_set_status(req, HTTPD_401);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "keep-alive");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
        httpd_resp_send(req, NULL, 0);
    }

    return ESP_OK;
}

static httpd_uri_t basic_auth = {
    .uri = "/basic_auth",
    .method = HTTP_GET,
    .handler = basic_auth_get_handler,
};

static void httpd_register_basic_auth(httpd_handle_t server)
{
    basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
    if (basic_auth_info)
    {
        basic_auth_info->username = CONFIG_EXAMPLE_BASIC_AUTH_USERNAME;
        basic_auth_info->password = CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD;

        basic_auth.user_ctx = basic_auth_info;
        httpd_register_uri_handler(server, &basic_auth);
    }
}
#endif

static esp_err_t index_get_handler(httpd_req_t *req)
{
    extern const unsigned char index_html_start[] asm("_binary_index_html_start");
    extern const unsigned char index_html_end[] asm("_binary_index_html_end");
    const size_t index_html_size = (index_html_end - index_html_start);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, (const char *)index_html_start, index_html_size);
    return ESP_OK;
}

static const httpd_uri_t index_html = {
    .uri = "/index.html",
    .method = HTTP_GET,
    .handler = index_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

static const httpd_uri_t index_root = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = index_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

static esp_err_t favicon_get_handler(httpd_req_t *req)
{
    extern const unsigned char favicon_ico_start[] asm("_binary_favicon_ico_start");
    extern const unsigned char favicon_ico_end[] asm("_binary_favicon_ico_end");
    const size_t favicon_ico_size = (favicon_ico_end - favicon_ico_start);
    httpd_resp_set_type(req, "image/ico");
    httpd_resp_send(req, (const char *)favicon_ico_start, favicon_ico_size);
    return ESP_OK;
}

static const httpd_uri_t favicon = {
    .uri = "/favicon.ico",
    .method = HTTP_GET,
    .handler = favicon_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

static esp_err_t connect_wifi_get_handler(httpd_req_t *req)
{
    extern const unsigned char connect_wifi_html_start[] asm("_binary_connect_wifi_html_start");
    extern const unsigned char connect_wifi_html_end[] asm("_binary_connect_wifi_html_end");
    const size_t connect_wifi_html_size = (connect_wifi_html_end - connect_wifi_html_start);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, (const char *)connect_wifi_html_start, connect_wifi_html_size);
    return ESP_OK;
}

static const httpd_uri_t connect_wifi = {
    .uri = "/connect-wifi.html",
    .method = HTTP_GET,
    .handler = connect_wifi_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

static esp_err_t setwifi_post_handler(httpd_req_t *req)
{
    char wifi_ssid[32] = {0};
    char wifi_password[32] = {0};
    char buf[100];
    int ret, remaining = req->content_len;

    while (remaining > 0)
    {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf,
                                  MIN(remaining, sizeof(buf)))) <= 0)
        {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT)
            {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }
        remaining -= ret;

        /* Log data received */
        ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        ESP_LOGI(TAG, "%.*s", ret, buf);
        ESP_LOGI(TAG, "====================================");
    }

    // 解析 JSON 字符串
    cJSON *proot = cJSON_Parse(buf);
    if (proot == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "cJSON_Parse failed, %s", error_ptr);
    }
    else
    {
        ESP_LOGI(TAG, "cJSON_Parse success.");
        // 提取字段
        cJSON *ssid = cJSON_GetObjectItemCaseSensitive(proot, "ssid");
        cJSON *password = cJSON_GetObjectItemCaseSensitive(proot, "wifi_password");

        if (cJSON_IsString(ssid) && (ssid->valuestring != NULL) &&
            cJSON_IsString(password) && (password->valuestring != NULL))
        {
            strncpy(wifi_ssid, ssid->valuestring, sizeof(wifi_ssid));
            ESP_LOGI(TAG, "ssid: %s", ssid->valuestring);
            strncpy(wifi_password, password->valuestring, sizeof(wifi_password));
            ESP_LOGI(TAG, "wifi password: %s", password->valuestring);

            esp_err_t ret2;
            nvs_handle_t wifi_nvs_handle;
            // 初始化 NVS
            ret2 = nvs_flash_init();
            if (ret2 == ESP_ERR_NVS_NO_FREE_PAGES || ret2 == ESP_ERR_NVS_NEW_VERSION_FOUND)
            {
                ESP_ERROR_CHECK(nvs_flash_erase());
                ret2 = nvs_flash_init();
            }
            ESP_ERROR_CHECK(ret2);

            // 打开 'my_nvs' 分区
            ret2 = nvs_open("wifi_nvs", NVS_READWRITE, &wifi_nvs_handle);
            if (ret2 != ESP_OK)
            {
                ESP_LOGE(TAG, "Error (%d) opening NVS handle!", ret2);
            }
            else
            {
                // 写入新的字符串
                ret2 = nvs_set_i32(wifi_nvs_handle, "wifi_mode", 0);
                if (ret2 != ESP_OK)
                {
                    ESP_LOGE(TAG, "Error (%d) writing to NVS", ret2);
                }
                else
                {
                    // 将更改保存到 NVS
                    ret2 = nvs_commit(wifi_nvs_handle);
                    if (ret2 != ESP_OK)
                    {
                        ESP_LOGE(TAG, "Error (%d) committing NVS", ret2);
                    }
                }

                ret2 = nvs_set_str(wifi_nvs_handle, "wifi_ssid", wifi_ssid);
                if (ret2 != ESP_OK)
                {
                    ESP_LOGE(TAG, "Error (%d) writing to NVS", ret2);
                }
                else
                {
                    // 将更改保存到 NVS
                    ret2 = nvs_commit(wifi_nvs_handle);
                    if (ret2 != ESP_OK)
                    {
                        ESP_LOGE(TAG, "Error (%d) committing NVS", ret2);
                    }
                }

                ret2 = nvs_set_str(wifi_nvs_handle, "wifi_password", wifi_password);
                if (ret2 != ESP_OK)
                {
                    ESP_LOGE(TAG, "Error (%d) writing to NVS", ret2);
                }
                else
                {
                    // 将更改保存到 NVS
                    ret2 = nvs_commit(wifi_nvs_handle);
                    if (ret2 != ESP_OK)
                    {
                        ESP_LOGE(TAG, "Error (%d) committing NVS", ret2);
                    }
                }

                // 关闭 NVS 句柄
                nvs_close(wifi_nvs_handle);
            }

            // 创建 JSON 对象
            cJSON *root = cJSON_CreateObject();
            if (root == NULL)
            {
                ESP_LOGE(TAG, "cJSON_CreateObject failed.");
            }
            else
            {
                // 添加键值对
                cJSON_AddStringToObject(root, "code", "0");
                cJSON_AddStringToObject(root, "msg", "wifi setup success");

                // 转换为字符串并打印
                char *json_str = cJSON_Print(root);
                if (json_str == NULL)
                {
                    ESP_LOGE(TAG, "cJSON_Print failed.");
                }
                else
                {
                    httpd_resp_set_type(req, "text/json");
                    httpd_resp_send(req, (const char *)json_str, strlen(json_str));
                }
                // 释放资源
                cJSON_free(json_str);
            }
            cJSON_Delete(root);
            ESP_LOGI(TAG, "rebooting...");
            // 延迟2秒后重启
            vTaskDelay(2000 / portTICK_PERIOD_MS);
            esp_restart(); // 触发重启
        }
    }
    // 释放资源
    cJSON_Delete(proot);

    return ESP_OK;
}

static const httpd_uri_t setwifi = {
    .uri = "/setwifi.json",
    .method = HTTP_POST,
    .handler = setwifi_post_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

static esp_err_t paly_audio_get_handler(httpd_req_t *req)
{
    extern const unsigned char paly_audio_html_start[] asm("_binary_play_audio_html_start");
    extern const unsigned char paly_audio_html_end[] asm("_binary_play_audio_html_end");
    const size_t paly_audio_html_size = (paly_audio_html_end - paly_audio_html_start);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, (const char *)paly_audio_html_start, paly_audio_html_size);
    return ESP_OK;
}

static const httpd_uri_t paly_audio = {
    .uri = "/play-audio.html",
    .method = HTTP_GET,
    .handler = paly_audio_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

static esp_err_t reset_get_handler(httpd_req_t *req)
{
    extern const unsigned char reset_html_start[] asm("_binary_reset_html_start");
    extern const unsigned char reset_html_end[] asm("_binary_reset_html_end");
    const size_t reset_html_size = (reset_html_end - reset_html_start);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, (const char *)reset_html_start, reset_html_size);
    return ESP_OK;
}

static const httpd_uri_t reset = {
    .uri = "/reset.html",
    .method = HTTP_GET,
    .handler = reset_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

static esp_err_t reset_config_post_handler(httpd_req_t *req)
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

    // 创建 JSON 对象
    cJSON *root = cJSON_CreateObject();
    if (root == NULL)
    {
        ESP_LOGE(TAG, "cJSON_CreateObject failed.");
    }
    else
    {
        // 添加键值对
        cJSON_AddStringToObject(root, "code", "0");
        cJSON_AddStringToObject(root, "msg", "audio capture reset success");

        // 转换为字符串并打印
        char *json_str = cJSON_Print(root);
        if (json_str == NULL)
        {
            ESP_LOGE(TAG, "cJSON_Print failed.");
        }
        else
        {
            httpd_resp_set_type(req, "text/json");
            httpd_resp_send(req, (const char *)json_str, strlen(json_str));
        }
        // 释放资源
        cJSON_free(json_str);
    }
    cJSON_Delete(root);
    ESP_LOGI(TAG, "rebooting...");
    // 延迟2秒后重启
    vTaskDelay(2000 / portTICK_PERIOD_MS);
    esp_restart(); // 触发重启
    return ESP_OK;
}

static const httpd_uri_t reset_config = {
    .uri = "/reset.json",
    .method = HTTP_POST,
    .handler = reset_config_post_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

static esp_err_t reboot_post_handler(httpd_req_t *req)
{
    // 创建 JSON 对象
    cJSON *root = cJSON_CreateObject();
    if (root == NULL)
    {
        ESP_LOGE(TAG, "cJSON_CreateObject failed.");
    }
    else
    {
        // 添加键值对
        cJSON_AddStringToObject(root, "code", "0");
        cJSON_AddStringToObject(root, "msg", "audio capture reboot success");

        // 转换为字符串并打印
        char *json_str = cJSON_Print(root);
        if (json_str == NULL)
        {
            ESP_LOGE(TAG, "cJSON_Print failed.");
        }
        else
        {
            httpd_resp_set_type(req, "text/json");
            httpd_resp_send(req, (const char *)json_str, strlen(json_str));
        }
        // 释放资源
        cJSON_free(json_str);
    }
    cJSON_Delete(root);
    ESP_LOGI(TAG, "rebooting...");
    // 延迟2秒后重启
    vTaskDelay(2000 / portTICK_PERIOD_MS);
    esp_restart(); // 触发重启
    return ESP_OK;
}

static const httpd_uri_t reboot = {
    .uri = "/reboot.json",
    .method = HTTP_POST,
    .handler = reboot_post_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

static esp_err_t device_info_post_handler(httpd_req_t *req)
{
    int32_t wifi_mode = 0;
    char wifi_ssid[32] = {0};
    char wifi_password[32] = {0};
    char wifi_ip[30] = "192.168.4.1";
    esp_err_t ret;
    nvs_handle_t wifi_nvs_handle;

    esp_netif_t *esp_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (esp_netif == NULL)
    {
        ESP_LOGE("IP_GET", "STA netif not found");
    }
    else
    {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(esp_netif, &ip_info) == ESP_OK)
        {
            sprintf(wifi_ip, IPSTR, IP2STR(&ip_info.ip));
        }
        else
        {
            ESP_LOGE("IP_GET", "Failed to get IP info");
        }
    }

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
            ESP_LOGI(TAG, "Read wifi_mode from NVS: %i", wifi_mode);
            break;
        case ESP_ERR_NVS_NOT_FOUND:
            ESP_LOGW(TAG, "Value not found in NVS");
            break;
        default:
            ESP_LOGE(TAG, "Error (%d) reading from NVS", ret);
        }

        // 读取并输出字符串
        size_t string_size = sizeof(wifi_ssid);
        ret = nvs_get_str(wifi_nvs_handle, "wifi_ssid", wifi_ssid, &string_size);
        switch (ret)
        {
        case ESP_OK:
            ESP_LOGI(TAG, "Read wifi_ssid from NVS: %i", wifi_ssid);
            break;
        case ESP_ERR_NVS_NOT_FOUND:
            ESP_LOGW(TAG, "Value not found in NVS");
            break;
        default:
            ESP_LOGE(TAG, "Error (%d) reading from NVS", ret);
        }

        // 读取并输出字符串
        string_size = sizeof(wifi_password);
        ret = nvs_get_str(wifi_nvs_handle, "wifi_password", wifi_password, &string_size);
        switch (ret)
        {
        case ESP_OK:
            ESP_LOGI(TAG, "Read wifi_password from NVS: %i", wifi_password);
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

    // 创建 JSON 对象
    cJSON *root = cJSON_CreateObject();
    if (root == NULL)
    {
        ESP_LOGE(TAG, "cJSON_CreateObject failed.");
    }
    else
    {
        // 添加键值对
        cJSON_AddStringToObject(root, "code", "0");
        cJSON_AddStringToObject(root, "msg", "get device info success");
        cJSON_AddNumberToObject(root, "wifi_mode", wifi_mode);
        cJSON_AddStringToObject(root, "wifi_ssid", wifi_ssid);
        cJSON_AddStringToObject(root, "wifi_password", wifi_password);
        cJSON_AddStringToObject(root, "wifi_ip", wifi_ip);

        // 转换为字符串并打印
        char *json_str = cJSON_Print(root);
        if (json_str == NULL)
        {
            ESP_LOGE(TAG, "cJSON_Print failed.");
        }
        else
        {
            httpd_resp_set_type(req, "text/json");
            httpd_resp_send(req, (const char *)json_str, strlen(json_str));
        }
        // 释放资源
        cJSON_free(json_str);
    }
    cJSON_Delete(root);
    return ESP_OK;
}

static const httpd_uri_t device_info = {
    .uri = "/device-info.json",
    .method = HTTP_POST,
    .handler = device_info_post_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

static esp_err_t styles_get_handler(httpd_req_t *req)
{
    extern const unsigned char styles_css_start[] asm("_binary_styles_css_start");
    extern const unsigned char styles_css_end[] asm("_binary_styles_css_end");
    const size_t styles_css_size = (styles_css_end - styles_css_start);
    httpd_resp_set_type(req, "text/css");
    httpd_resp_send(req, (const char *)styles_css_start, styles_css_size);
    return ESP_OK;
}

static const httpd_uri_t styles = {
    .uri = "/styles.css",
    .method = HTTP_GET,
    .handler = styles_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx = NULL};

/* This handler allows the custom error handling functionality to be
 * tested from client side. For that, when a PUT request 0 is sent to
 * URI /ctrl, the /hello and /echo URIs are unregistered and following
 * custom error handler http_404_error_handler() is registered.
 * Afterwards, when /hello or /echo is requested, this custom error
 * handler is invoked which, after sending an error message to client,
 * either closes the underlying socket (when requested URI is /echo)
 * or keeps it open (when requested URI is /hello). This allows the
 * client to infer if the custom error handler is functioning as expected
 * by observing the socket state.
 */
esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/hello", req->uri) == 0)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/hello URI is not available");
        /* Return ESP_OK to keep underlying socket open */
        return ESP_OK;
    }
    else if (strcmp("/echo", req->uri) == 0)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not available");
        /* Return ESP_FAIL to close underlying socket */
        return ESP_FAIL;
    }
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}

#if CONFIG_EXAMPLE_ENABLE_SSE_HANDLER
/* An HTTP GET handler for SSE */
static esp_err_t sse_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/event-stream");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    httpd_resp_set_hdr(req, "Connection", "keep-alive");

    char sse_data[64];
    while (1)
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);             // Get the current time
        int64_t time_since_boot = tv.tv_sec; // Time since boot in seconds
        esp_err_t err;
        int len = snprintf(sse_data, sizeof(sse_data), "data: Time since boot: %" PRIi64 " seconds\n\n", time_since_boot);
        if ((err = httpd_resp_send_chunk(req, sse_data, len)) != ESP_OK)
        {
            ESP_LOGE(TAG, "Failed to send sse data (returned %02X)", err);
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(1000)); // Send data every second
    }

    httpd_resp_send_chunk(req, NULL, 0); // End response
    return ESP_OK;
}

static const httpd_uri_t sse = {
    .uri = "/sse",
    .method = HTTP_GET,
    .handler = sse_handler,
    .user_ctx = NULL};
#endif // CONFIG_EXAMPLE_ENABLE_SSE_HANDLER

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 16;
#if CONFIG_IDF_TARGET_LINUX
    // Setting port as 8001 when building for Linux. Port 80 can be used only by a privileged user in linux.
    // So when a unprivileged user tries to run the application, it throws bind error and the server is not started.
    // Port 8001 can be used by an unprivileged user as well. So the application will not throw bind error and the
    // server will be started.
    config.server_port = 8001;
#endif // !CONFIG_IDF_TARGET_LINUX
    config.lru_purge_enable = true;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK)
    {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &index_root);
        httpd_register_uri_handler(server, &index_html);
        httpd_register_uri_handler(server, &favicon);
        httpd_register_uri_handler(server, &connect_wifi);
        httpd_register_uri_handler(server, &setwifi);
        httpd_register_uri_handler(server, &paly_audio);
        httpd_register_uri_handler(server, &reset);
        httpd_register_uri_handler(server, &reset_config);
        httpd_register_uri_handler(server, &reboot);
        httpd_register_uri_handler(server, &device_info);
        httpd_register_uri_handler(server, &styles);
        httpd_register_uri_handler(server, &ws_audio);
#if CONFIG_EXAMPLE_ENABLE_SSE_HANDLER
        httpd_register_uri_handler(server, &sse); // Register SSE handler
#endif
#if CONFIG_EXAMPLE_BASIC_AUTH
        httpd_register_basic_auth(server);
#endif
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

static void http_server_task(void *pvParameters)
{
    static httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    /* Start the server for the first time */
    server = start_webserver();

    while (server)
    {
        sleep(5);
    }
}

void htpp_server_app_main(void)
{
    xTaskCreate(http_server_task, "http_server_task", 4096, NULL, 5, NULL);
}
