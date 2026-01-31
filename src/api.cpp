#ifndef KD_COMMON_API_DISABLE

#include "api.h"
#include "kdmdns.h"
#include "kd_common.h"
#include "esp_http_server.h"
#include "cJSON.h"
#include <esp_app_desc.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace {
    httpd_handle_t kd_api_server = NULL;
}

static void server_init() {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 60;
    config.uri_match_fn = httpd_uri_match_wildcard;
    httpd_start(&kd_api_server, &config);
}

static esp_err_t root_handler(httpd_req_t* req) {
    const char* response = "Welcome to the KD API!";
    httpd_resp_send(req, response, strlen(response));
    return ESP_OK;
}

static esp_err_t about_handler(httpd_req_t* req) {
    const esp_app_desc_t* app_desc = esp_app_get_description();

    cJSON* json = cJSON_CreateObject();
    if (json == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    cJSON* model = cJSON_CreateString(kdmdns_get_model() ? kdmdns_get_model() : "unknown");
    cJSON* type = cJSON_CreateString(kdmdns_get_type() ? kdmdns_get_type() : "unknown");
    cJSON* version = cJSON_CreateString(app_desc->version);

    cJSON_AddItemToObject(json, "model", model);
    cJSON_AddItemToObject(json, "type", type);
    cJSON_AddItemToObject(json, "version", version);

    char* json_string = cJSON_Print(json);
    if (json_string == NULL) {
        cJSON_Delete(json);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_string, strlen(json_string));

    free(json_string);
    cJSON_Delete(json);

    return ESP_OK;
}

static esp_err_t system_config_get_handler(httpd_req_t* req) {
    char* wifi_hostname = kd_common_get_wifi_hostname();

    cJSON* json = cJSON_CreateObject();
    if (json == NULL) {
        if (wifi_hostname) free(wifi_hostname);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    cJSON_AddBoolToObject(json, "auto_timezone", kd_common_get_auto_timezone());
    cJSON_AddStringToObject(json, "timezone", kd_common_get_timezone());
    cJSON_AddStringToObject(json, "ntp_server", kd_common_get_ntp_server());
    cJSON_AddStringToObject(json, "wifi_hostname", wifi_hostname ? wifi_hostname : "");

    char* json_string = cJSON_Print(json);
    if (json_string == NULL) {
        cJSON_Delete(json);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_string, strlen(json_string));

    free(json_string);
    cJSON_Delete(json);

    return ESP_OK;
}

static esp_err_t system_config_post_handler(httpd_req_t* req) {
    char content[512];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        else {
            httpd_resp_send_500(req);
        }
        return ESP_FAIL;
    }
    content[ret] = '\0';

    cJSON* json = cJSON_Parse(content);
    if (json == NULL) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON format");
        return ESP_FAIL;
    }

    cJSON* auto_timezone_json = cJSON_GetObjectItem(json, "auto_timezone");
    cJSON* timezone_json = cJSON_GetObjectItem(json, "timezone");
    cJSON* ntp_server_json = cJSON_GetObjectItem(json, "ntp_server");
    cJSON* wifi_hostname_json = cJSON_GetObjectItem(json, "wifi_hostname");

    if (cJSON_IsBool(auto_timezone_json)) {
        kd_common_set_auto_timezone(cJSON_IsTrue(auto_timezone_json));
    }

    if (cJSON_IsString(timezone_json)) {
        const char* tz_str = cJSON_GetStringValue(timezone_json);
        if (tz_str && strlen(tz_str) < 64) {
            kd_common_set_timezone(tz_str);
        }
    }

    if (cJSON_IsString(ntp_server_json)) {
        const char* ntp_str = cJSON_GetStringValue(ntp_server_json);
        if (ntp_str && strlen(ntp_str) < 64) {
            kd_common_set_ntp_server(ntp_str);
        }
    }

    if (cJSON_IsString(wifi_hostname_json)) {
        const char* hostname_str = cJSON_GetStringValue(wifi_hostname_json);
        if (hostname_str && strlen(hostname_str) > 0 && strlen(hostname_str) <= 63) {
            kd_common_set_wifi_hostname(hostname_str);
        }
    }

    cJSON_Delete(json);

    cJSON* response_json = cJSON_CreateObject();
    cJSON_AddStringToObject(response_json, "status", "success");

    char* response_string = cJSON_Print(response_json);
    if (response_string == NULL) {
        cJSON_Delete(response_json);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, response_string, strlen(response_string));

    free(response_string);
    cJSON_Delete(response_json);

    return ESP_OK;
}

static esp_err_t time_zones_handler(httpd_req_t* req) {
    const kd_common_tz_entry_t* zones = kd_common_get_all_timezones();
    int total_zones = kd_common_get_timezone_count();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Transfer-Encoding", "chunked");

    httpd_resp_send_chunk(req, "[", 1);

    const int CHUNK_SIZE = 20;
    bool first_zone = true;

    for (int chunk_start = 0; chunk_start < total_zones; chunk_start += CHUNK_SIZE) {
        int chunk_end = chunk_start + CHUNK_SIZE;
        if (chunk_end > total_zones) {
            chunk_end = total_zones;
        }

        cJSON* chunk_array = cJSON_CreateArray();
        if (chunk_array == NULL) {
            httpd_resp_send_chunk(req, NULL, 0);
            return ESP_FAIL;
        }

        for (int i = chunk_start; i < chunk_end; i++) {
            cJSON* zone_obj = cJSON_CreateObject();
            if (zone_obj == NULL) continue;

            cJSON_AddStringToObject(zone_obj, "name", zones[i].name);
            cJSON_AddStringToObject(zone_obj, "rule", zones[i].rule);
            cJSON_AddItemToArray(chunk_array, zone_obj);
        }

        char* chunk_string = cJSON_PrintUnformatted(chunk_array);
        if (chunk_string == NULL) {
            cJSON_Delete(chunk_array);
            httpd_resp_send_chunk(req, NULL, 0);
            return ESP_FAIL;
        }

        size_t chunk_len = strlen(chunk_string);
        if (chunk_len > 2) {
            chunk_string[chunk_len - 1] = '\0';
            char* content = chunk_string + 1;

            if (!first_zone) {
                httpd_resp_send_chunk(req, ",", 1);
            }

            httpd_resp_send_chunk(req, content, strlen(content));
            first_zone = false;
        }

        free(chunk_string);
        cJSON_Delete(chunk_array);

        vTaskDelay(pdMS_TO_TICKS(10));
    }

    httpd_resp_send_chunk(req, "]", 1);
    httpd_resp_send_chunk(req, NULL, 0);

    return ESP_OK;
}

static esp_err_t wildcard_options_handler(httpd_req_t* req) {
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type,Authorization");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Credentials", "true");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

void api_init() {
    server_init();

    httpd_uri_t about_uri = {
        .uri = "/api/about",
        .method = HTTP_GET,
        .handler = about_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(kd_api_server, &about_uri);

    httpd_uri_t system_config_get_uri = {
        .uri = "/api/system/config",
        .method = HTTP_GET,
        .handler = system_config_get_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(kd_api_server, &system_config_get_uri);

    httpd_uri_t system_config_post_uri = {
        .uri = "/api/system/config",
        .method = HTTP_POST,
        .handler = system_config_post_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(kd_api_server, &system_config_post_uri);

    httpd_uri_t time_zones_uri = {
        .uri = "/api/time/zonedb",
        .method = HTTP_GET,
        .handler = time_zones_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(kd_api_server, &time_zones_uri);

    static httpd_uri_t options_uri = {
        .uri = "/api/*",
        .method = HTTP_OPTIONS,
        .handler = wildcard_options_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(kd_api_server, &options_uri);

    httpd_uri_t root_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = root_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(kd_api_server, &root_uri);
}

httpd_handle_t api_get_httpd_handle() {
    return kd_api_server;
}

#endif // KD_COMMON_API_DISABLE
