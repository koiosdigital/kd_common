#include "crypto.h"

#ifdef CONFIG_KD_COMMON_CRYPTO_ENABLE

#include "crypto_internal.h"

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <esp_log.h>
#include <esp_efuse.h>
#include <esp_random.h>
#include <esp_task_wdt.h>
#include <esp_ds.h>

#include "mbedtls/rsa.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <cstring>
#include <memory>

#include "kd_common.h"

static const char* TAG = "kd_crypto_keygen";

using namespace crypto;

void keygen_task(void* pvParameter) {
    auto* rsa = static_cast<mbedtls_rsa_context*>(pvParameter);
    xSemaphoreTake(keygen_mutex, portMAX_DELAY);

    ESP_LOGD(TAG, "generating key");

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    esp_task_wdt_config_t twdt_config = {
        .timeout_ms = 1000 * 60 * 2,  // 2 minutes
        .idle_core_mask = static_cast<uint32_t>((1 << portNUM_PROCESSORS) - 1),
        .trigger_panic = true,
    };
    esp_task_wdt_reconfigure(&twdt_config);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
    mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, 65537);
    mbedtls_rsa_complete(rsa);

    ESP_LOGD(TAG, "key generated");

    twdt_config.timeout_ms = 5000;
    esp_task_wdt_reconfigure(&twdt_config);

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    xSemaphoreGive(keygen_mutex);

    vTaskDelete(nullptr);
}

void calculate_rinv_mprime(mbedtls_mpi* N, mbedtls_mpi* rinv, uint32_t* mprime) {
    mbedtls_mpi rr, ls32, a;
    mbedtls_mpi_init(&rr);
    mbedtls_mpi_init(&ls32);
    mbedtls_mpi_init(&a);

    mbedtls_mpi_lset(&rr, 1);
    mbedtls_mpi_shift_l(&rr, KEY_SIZE * 2);

    mbedtls_mpi_mod_mpi(rinv, &rr, N);

    mbedtls_mpi_lset(&ls32, 1);
    mbedtls_mpi_shift_l(&ls32, 32);

    mbedtls_mpi_inv_mod(&a, N, &ls32);

    uint32_t a32 = 0;
    mbedtls_mpi_write_binary_le(&a, reinterpret_cast<uint8_t*>(&a32), sizeof(uint32_t));
    *mprime = (static_cast<int32_t>(a32) * -1) & 0xFFFFFFFF;

    mbedtls_mpi_free(&rr);
    mbedtls_mpi_free(&ls32);
    mbedtls_mpi_free(&a);
}

void rinv_mprime_to_ds_params(mbedtls_mpi* D, mbedtls_mpi* N, mbedtls_mpi* rinv,
    uint32_t mprime, esp_ds_p_data_t* params) {
    mbedtls_mpi_write_binary(D, reinterpret_cast<uint8_t*>(params->Y), sizeof(params->Y));
    mbedtls_mpi_write_binary(N, reinterpret_cast<uint8_t*>(params->M), sizeof(params->M));
    mbedtls_mpi_write_binary(rinv, reinterpret_cast<uint8_t*>(params->Rb), sizeof(params->Rb));

    kd_common_reverse_bytes(reinterpret_cast<uint8_t*>(params->Y), KEY_SIZE / 8);
    kd_common_reverse_bytes(reinterpret_cast<uint8_t*>(params->M), KEY_SIZE / 8);
    kd_common_reverse_bytes(reinterpret_cast<uint8_t*>(params->Rb), KEY_SIZE / 8);

    params->M_prime = mprime;
    params->length = (KEY_SIZE / 32) - 1;
}

esp_err_t store_csr(mbedtls_rsa_context* rsa) {
    mbedtls_x509write_csr req;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk = {};

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509write_csr_init(&req);

    // RAII cleanup
    struct Cleanup {
        mbedtls_x509write_csr* req;
        mbedtls_ctr_drbg_context* ctr_drbg;
        mbedtls_entropy_context* entropy;
        ~Cleanup() {
            mbedtls_x509write_csr_free(req);
            mbedtls_ctr_drbg_free(ctr_drbg);
            mbedtls_entropy_free(entropy);
        }
    } cleanup{ &req, &ctr_drbg, &entropy };

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);

    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key_usage(&req, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    mbedtls_x509write_csr_set_ns_cert_type(&req, MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT);

    char cn[128];
    snprintf(cn, sizeof(cn), "CN=%s.iotdevices.koiosdigital.net", kd_common_get_device_name());
    mbedtls_x509write_csr_set_subject_name(&req, cn);

    mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));

    int ret = mbedtls_rsa_copy(mbedtls_pk_rsa(pk), rsa);
    if (ret != 0) {
        ESP_LOGE(TAG, "rsa_copy failed: %d", ret);
        return ESP_FAIL;
    }

    mbedtls_x509write_csr_set_key(&req, &pk);

    auto csr_buffer = std::make_unique<unsigned char[]>(PEM_BUFFER_SIZE);

    ret = mbedtls_x509write_csr_pem(&req, csr_buffer.get(), PEM_BUFFER_SIZE,
        mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "csr_pem failed: %d", ret);
        return ESP_FAIL;
    }

    return crypto_storage_store_csr(csr_buffer.get(), std::strlen(reinterpret_cast<char*>(csr_buffer.get())));
}

esp_err_t ensure_key_exists() {
    keygen_mutex = xSemaphoreCreateBinary();
    xSemaphoreGive(keygen_mutex);

    esp_efuse_block_t ds_key_block = get_ds_key_block();
    bool has_fuses = esp_efuse_get_key_purpose(ds_key_block) ==
        ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE;

    if (has_fuses) {
        ESP_LOGI(TAG, "skipping keygen, key already burnt to block: %d", (ds_key_block - 4));
        return ESP_OK;
    }

    mbedtls_mpi rinv;
    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa);
    mbedtls_mpi_init(&rinv);

    // RAII cleanup for mbedtls resources
    struct MbedCleanup {
        mbedtls_rsa_context* rsa;
        mbedtls_mpi* rinv;
        ~MbedCleanup() {
            mbedtls_rsa_free(rsa);
            mbedtls_mpi_free(rinv);
        }
    } mbed_cleanup{ &rsa, &rinv };

    // Generate RSA keypair on APP_CPU
    xTaskCreatePinnedToCore(keygen_task, "keygen_task", 8192, &rsa, 5, nullptr, 1);

    vTaskDelay(pdMS_TO_TICKS(1000));

    while (xSemaphoreTake(keygen_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGI(TAG, "keygen_task still running");
    }

    uint32_t mprime = 0;
    calculate_rinv_mprime(&rsa.private_N, &rinv, &mprime);

    auto params = std::unique_ptr<esp_ds_p_data_t, decltype(&free)>(
        static_cast<esp_ds_p_data_t*>(calloc(1, sizeof(esp_ds_p_data_t))),
        free);
    if (!params) {
        ESP_LOGE(TAG, "no mem for ds params");
        return ESP_ERR_NO_MEM;
    }

    rinv_mprime_to_ds_params(&rsa.private_D, &rsa.private_N, &rinv, mprime, params.get());

    esp_err_t error = store_csr(&rsa);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "store csr failed");
        esp_restart();
        return error;
    }

    // Generate IV and HMAC key
    uint8_t iv[16];
    uint8_t hmac[32];
    esp_fill_random(iv, sizeof(iv));
    esp_fill_random(hmac, sizeof(hmac));

    auto encrypted = std::unique_ptr<esp_ds_data_t, decltype(&free)>(
        static_cast<esp_ds_data_t*>(heap_caps_calloc(1, sizeof(esp_ds_data_t), MALLOC_CAP_DMA)),
        free);
    if (!encrypted) {
        ESP_LOGE(TAG, "no mem for encrypted ds data");
        return ESP_ERR_NO_MEM;
    }

    esp_ds_encrypt_params(encrypted.get(), iv, params.get(), hmac);

    crypto_storage_store_ds_params(encrypted->c, iv, ds_key_block, (KEY_SIZE / 32) - 1);

    esp_efuse_write_key(ds_key_block, ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE, hmac, 32);
    esp_efuse_set_read_protect(ds_key_block);

    return ESP_OK;
}

#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE
