#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

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
#include <esp_heap_caps.h>

#include "psa/crypto.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/asn1.h"
#include "mbedtls/bignum.h"

#include <string.h>
#include <stdlib.h>

#include "kd_common.h"

static const char* TAG = "kd_crypto_keygen";

typedef struct {
    esp_efuse_block_t ds_key_block;
    esp_err_t result;
} crypto_setup_params_t;

static int parse_pkcs1_rsa_key(const uint8_t* der, size_t der_len,
    mbedtls_mpi* N, mbedtls_mpi* D)
{
    unsigned char* p = (unsigned char*)der;
    const unsigned char* end = der + der_len;
    size_t len;
    int ret;

    ret = mbedtls_asn1_get_tag(&p, end, &len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) return ret;

    int version;
    ret = mbedtls_asn1_get_int(&p, end, &version);
    if (ret != 0) return ret;

    ret = mbedtls_asn1_get_mpi(&p, end, N);  // modulus
    if (ret != 0) return ret;

    mbedtls_mpi e;
    mbedtls_mpi_init(&e);
    ret = mbedtls_asn1_get_mpi(&p, end, &e);  // publicExponent (skip)
    mbedtls_mpi_free(&e);
    if (ret != 0) return ret;

    ret = mbedtls_asn1_get_mpi(&p, end, D);  // privateExponent
    return ret;
}

static void calculate_ds_params(mbedtls_mpi* N, mbedtls_mpi* Rb, uint32_t* mprime) {
    mbedtls_mpi tmp, mod32;
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&mod32);

    // Rb = (2^key_bits)^2 mod N
    mbedtls_mpi_lset(&tmp, 1);
    mbedtls_mpi_shift_l(&tmp, CRYPTO_KEY_SIZE * 2);
    mbedtls_mpi_mod_mpi(Rb, &tmp, N);

    // M' = -N^(-1) mod 2^32
    mbedtls_mpi_lset(&mod32, 1);
    mbedtls_mpi_shift_l(&mod32, 32);
    mbedtls_mpi_inv_mod(&tmp, N, &mod32);

    uint32_t inv32;
    mbedtls_mpi_write_binary_le(&tmp, (uint8_t*)&inv32, 4);
    *mprime = ~inv32 + 1;

    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&mod32);
}

static void mpi_to_ds_params(mbedtls_mpi* D, mbedtls_mpi* N, mbedtls_mpi* Rb,
    uint32_t mprime, esp_ds_p_data_t* params)
{
    size_t bl = CRYPTO_KEY_SIZE / 8;
    memset(params, 0, sizeof(*params));

    mbedtls_mpi_write_binary_le(D, (uint8_t*)params->Y, bl);
    mbedtls_mpi_write_binary_le(N, (uint8_t*)params->M, bl);
    mbedtls_mpi_write_binary_le(Rb, (uint8_t*)params->Rb, bl);

    params->M_prime = mprime;
    params->length = (CRYPTO_KEY_SIZE / 32) - 1;
}

static esp_err_t psa_key_to_ds_params(psa_key_id_t key_id, esp_ds_p_data_t* params) {
    size_t der_size = PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR, CRYPTO_KEY_SIZE);
    uint8_t* der = (uint8_t*)malloc(der_size);
    if (der == NULL) {
        ESP_LOGE(TAG, "malloc failed for DER buffer");
        return ESP_ERR_NO_MEM;
    }
    size_t der_len;

    psa_status_t status = psa_export_key(key_id, der, der_size, &der_len);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_export_key failed: %d", status);
        free(der);
        return ESP_FAIL;
    }

    mbedtls_mpi N, D, Rb;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&Rb);

    int ret = parse_pkcs1_rsa_key(der, der_len, &N, &D);
    free(der);

    if (ret != 0) {
        ESP_LOGE(TAG, "PKCS#1 parse failed: -0x%04X", -ret);
        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&D);
        return ESP_FAIL;
    }

    uint32_t mprime = 0;
    calculate_ds_params(&N, &Rb, &mprime);
    mpi_to_ds_params(&D, &N, &Rb, mprime, params);

    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&Rb);

    return ESP_OK;
}

static psa_key_id_t generate_rsa_key(void) {
    psa_key_id_t key_id = 0;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes,
        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attributes, CRYPTO_KEY_SIZE);

    psa_status_t status = psa_generate_key(&attributes, &key_id);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to generate key: %d", status);
        return 0;
    }

    ESP_LOGI(TAG, "key generated");
    return key_id;
}

static esp_err_t store_csr(psa_key_id_t key_id) {
    mbedtls_x509write_csr req;
    mbedtls_pk_context pk;
    uint8_t* csr_buffer = NULL;
    esp_err_t err = ESP_FAIL;

    mbedtls_x509write_csr_init(&req);
    mbedtls_pk_init(&pk);

    int ret = mbedtls_pk_copy_from_psa(key_id, &pk);
    if (ret != 0) {
        ESP_LOGE(TAG, "pk_copy_from_psa failed: %d", ret);
        goto cleanup;
    }

    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key_usage(&req, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    mbedtls_x509write_csr_set_ns_cert_type(&req, MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT);

    char cn[128];
    snprintf(cn, sizeof(cn), "CN=%s.iotdevices.koiosdigital.net", kd_common_get_device_name());
    ret = mbedtls_x509write_csr_set_subject_name(&req, cn);
    if (ret != 0) {
        ESP_LOGE(TAG, "set_subject_name failed: %d", ret);
        goto cleanup;
    }

    mbedtls_x509write_csr_set_key(&req, &pk);

    csr_buffer = (uint8_t*)malloc(CRYPTO_PEM_BUFFER_SIZE);
    if (csr_buffer == NULL) {
        ESP_LOGE(TAG, "malloc failed");
        goto cleanup;
    }

    ret = mbedtls_x509write_csr_pem(&req, csr_buffer, CRYPTO_PEM_BUFFER_SIZE);
    if (ret != 0) {
        ESP_LOGE(TAG, "csr_pem failed: %d", ret);
        goto cleanup;
    }

    err = crypto_storage_store_csr(csr_buffer, strlen((const char*)csr_buffer));

cleanup:
    mbedtls_x509write_csr_free(&req);
    mbedtls_pk_free(&pk);
    free(csr_buffer);

    return err;
}

static void crypto_setup_task(void* pvParameter) {
    crypto_setup_params_t* params = (crypto_setup_params_t*)pvParameter;
    params->result = ESP_FAIL;

    uint8_t iv[16] = { 0 };
    uint8_t hmac[32] = { 0 };

    esp_ds_data_t* encrypted = NULL;
    esp_ds_p_data_t* ds_params = NULL;

    xSemaphoreTake(g_keygen_mutex, portMAX_DELAY);

    // Extend watchdog timeout for key generation
    esp_task_wdt_config_t twdt_config = {
        .timeout_ms = 1000 * 60 * 2,  // 2 minutes
        .idle_core_mask = (uint32_t)((1 << portNUM_PROCESSORS) - 1),
        .trigger_panic = true,
    };
    esp_task_wdt_reconfigure(&twdt_config);

    // Generate RSA key
    psa_key_id_t key_id = generate_rsa_key();
    if (key_id == 0) {
        ESP_LOGE(TAG, "key generation failed");
        goto cleanup;
    }

    // Store CSR
    if (store_csr(key_id) != ESP_OK) {
        ESP_LOGE(TAG, "store csr failed");
        psa_destroy_key(key_id);
        goto cleanup;
    }

    // Compute DS params
    ds_params = (esp_ds_p_data_t*)calloc(1, sizeof(esp_ds_p_data_t));
    if (!ds_params) {
        ESP_LOGE(TAG, "no mem for ds params");
        psa_destroy_key(key_id);
        goto cleanup;
    }

    if (psa_key_to_ds_params(key_id, ds_params) != ESP_OK) {
        ESP_LOGE(TAG, "PSA to DS failed");
        free(ds_params);
        psa_destroy_key(key_id);
        goto cleanup;
    }

    // Generate IV and HMAC key
    esp_fill_random(iv, sizeof(iv));
    esp_fill_random(hmac, sizeof(hmac));

    encrypted = (esp_ds_data_t*)heap_caps_calloc(1, sizeof(esp_ds_data_t), MALLOC_CAP_DMA);
    if (!encrypted) {
        ESP_LOGE(TAG, "no mem for encrypted ds data");
        free(ds_params);
        psa_destroy_key(key_id);
        goto cleanup;
    }

    esp_ds_encrypt_params(encrypted, iv, ds_params, hmac);
    crypto_storage_store_ds_params(encrypted->c, iv, params->ds_key_block, (CRYPTO_KEY_SIZE / 32) - 1);

    heap_caps_free(encrypted);
    free(ds_params);

    // Burn to eFuse (commented out for testing)
    esp_efuse_write_key(params->ds_key_block, ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE, hmac, 32);
    esp_efuse_set_read_protect(params->ds_key_block);

    psa_destroy_key(key_id);
    params->result = ESP_OK;

cleanup:
    twdt_config.timeout_ms = 5000;
    esp_task_wdt_reconfigure(&twdt_config);
    xSemaphoreGive(g_keygen_mutex);
    vTaskDelete(NULL);
}

// ============================================
// Main: ensure_key_exists - orchestrates all
// ============================================
esp_err_t ensure_key_exists(void) {
    g_keygen_mutex = xSemaphoreCreateBinary();
    xSemaphoreGive(g_keygen_mutex);

    esp_efuse_block_t ds_key_block = crypto_get_ds_key_block_internal();
    bool has_fuses = esp_efuse_get_key_purpose(ds_key_block) ==
        ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE;

    if (has_fuses) {
        ESP_LOGI(TAG, "skipping keygen, key already burnt to block: %d", (ds_key_block - 4));
        return kd_common_crypto_test_ds_signing();
    }

    crypto_setup_params_t task_params = {
        .ds_key_block = ds_key_block,
        .result = ESP_FAIL,
    };

    // Run all crypto operations on separate task with 16KB stack
    xTaskCreate(crypto_setup_task, "crypto_setup", 16384, &task_params, 5, NULL);

    vTaskDelay(pdMS_TO_TICKS(1000));
    while (xSemaphoreTake(g_keygen_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGI(TAG, "crypto_setup_task still running");
    }

    if (task_params.result != ESP_OK) {
        esp_restart();
    }

    return kd_common_crypto_test_ds_signing();
}

#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE
