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
#include <esp_system.h>
#include <nvs.h>

#include "psa/crypto.h"
#ifdef CONFIG_MBEDTLS_HARDWARE_RSA_DS_PERIPHERAL
#include "psa_crypto_driver_esp_rsa_ds.h"
#endif
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/pem.h"
#include "mbedtls/bignum.h"
#include "mbedtls/platform_util.h"

#include <string.h>
#include <stdlib.h>

#include <mbedtls/platform_util.h>

#include "kd_common.h"

#include <nvs_flash.h>

static const char* TAG = "kd_crypto_keygen";
#define KEYGEN_MAX_RETRIES 3

// Local equivalent of MBEDTLS_MPI_CHK (that macro lives in a private mbedtls
// header in current releases).
#define KD_MPI_CHK(f)                       \
    do {                                    \
        if ((ret = (f)) != 0) goto cleanup; \
    } while (0)

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

// Rb = (2^key_bits)^2 mod N and M' = -N^(-1) mod 2^32. Returns 0 or an
// mbedtls error; every bignum step is checked because a silently wrong Rb/M'
// would produce DS params that can never verify — and they get burnt in.
static int calculate_ds_params(mbedtls_mpi* N, mbedtls_mpi* Rb, uint32_t* mprime) {
    mbedtls_mpi tmp, mod32;
    int ret;
    uint32_t inv32 = 0;

    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_init(&mod32);

    // Rb = (2^key_bits)^2 mod N
    KD_MPI_CHK(mbedtls_mpi_lset(&tmp, 1));
    KD_MPI_CHK(mbedtls_mpi_shift_l(&tmp, CRYPTO_KEY_SIZE * 2));
    KD_MPI_CHK(mbedtls_mpi_mod_mpi(Rb, &tmp, N));

    // M' = -N^(-1) mod 2^32
    KD_MPI_CHK(mbedtls_mpi_lset(&mod32, 1));
    KD_MPI_CHK(mbedtls_mpi_shift_l(&mod32, 32));
    KD_MPI_CHK(mbedtls_mpi_inv_mod(&tmp, N, &mod32));

    KD_MPI_CHK(mbedtls_mpi_write_binary_le(&tmp, (uint8_t*)&inv32, sizeof(inv32)));
    *mprime = ~inv32 + 1;

cleanup:
    mbedtls_mpi_free(&tmp);
    mbedtls_mpi_free(&mod32);
    return ret;
}

static int mpi_to_ds_params(mbedtls_mpi* D, mbedtls_mpi* N, mbedtls_mpi* Rb,
    uint32_t mprime, esp_ds_p_data_t* params)
{
    size_t bl = CRYPTO_KEY_SIZE / 8;
    int ret;
    memset(params, 0, sizeof(*params));

    KD_MPI_CHK(mbedtls_mpi_write_binary_le(D, (uint8_t*)params->Y, bl));
    KD_MPI_CHK(mbedtls_mpi_write_binary_le(N, (uint8_t*)params->M, bl));
    KD_MPI_CHK(mbedtls_mpi_write_binary_le(Rb, (uint8_t*)params->Rb, bl));

    params->M_prime = mprime;
    params->length = (CRYPTO_KEY_SIZE / 32) - 1;

cleanup:
    return ret;
}

static esp_err_t psa_key_to_ds_params(psa_key_id_t key_id, esp_ds_p_data_t* params) {
    size_t der_size = PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_RSA_KEY_PAIR, CRYPTO_KEY_SIZE);
    uint8_t* der = (uint8_t*)malloc(der_size);
    if (der == NULL) {
        ESP_LOGE(TAG, "malloc failed for DER buffer");
        return ESP_ERR_NO_MEM;
    }
    size_t der_len = 0;
    esp_err_t err = ESP_FAIL;
    int ret = 0;
    uint32_t mprime = 0;

    mbedtls_mpi N, D, Rb;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&Rb);

    psa_status_t status = psa_export_key(key_id, der, der_size, &der_len);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_export_key failed: %d", status);
        goto cleanup;
    }

    ret = parse_pkcs1_rsa_key(der, der_len, &N, &D);
    if (ret != 0) {
        ESP_LOGE(TAG, "PKCS#1 parse failed: -0x%04X", -ret);
        goto cleanup;
    }

    ret = calculate_ds_params(&N, &Rb, &mprime);
    if (ret != 0) {
        ESP_LOGE(TAG, "DS param calculation failed: -0x%04X", -ret);
        goto cleanup;
    }

    ret = mpi_to_ds_params(&D, &N, &Rb, mprime, params);
    if (ret != 0) {
        ESP_LOGE(TAG, "DS param export failed: -0x%04X", -ret);
        memset(params, 0, sizeof(*params));
        goto cleanup;
    }

    err = ESP_OK;

cleanup:
    // The DER holds the raw private key: scrub before releasing.
    mbedtls_platform_zeroize(der, der_size);
    free(der);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&Rb);
    return err;
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
    snprintf(cn, sizeof(cn), "CN=%s", kd_common_get_device_name());
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
    mbedtls_pk_free(&pk);  // pk holds a copy of the private key
    free(csr_buffer);

    return err;
}

// ----------------------------------------------------------------------------
// Task watchdog handling for the keygen window
// ----------------------------------------------------------------------------
// RSA keygen runs for tens of seconds at priority 5 and starves the idle tasks,
// which are the TWDT's default subscribers. Rather than stretching the global
// timeout (and restoring a guessed value afterwards), unsubscribe the idle
// tasks for the duration and re-add exactly the ones we removed.

#if CONFIG_ESP_TASK_WDT_EN
static bool s_idle_wdt_removed[portNUM_PROCESSORS];

static void keygen_idle_wdt_unsubscribe(void) {
    for (int core = 0; core < portNUM_PROCESSORS; core++) {
        TaskHandle_t idle = xTaskGetIdleTaskHandleForCore(core);
        s_idle_wdt_removed[core] = (idle != NULL) && (esp_task_wdt_delete(idle) == ESP_OK);
    }
}

static void keygen_idle_wdt_resubscribe(void) {
    for (int core = 0; core < portNUM_PROCESSORS; core++) {
        if (!s_idle_wdt_removed[core]) continue;
        s_idle_wdt_removed[core] = false;
        TaskHandle_t idle = xTaskGetIdleTaskHandleForCore(core);
        esp_err_t err = (idle != NULL) ? esp_task_wdt_add(idle) : ESP_ERR_INVALID_ARG;
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "re-adding idle task %d to TWDT failed: %s", core, esp_err_to_name(err));
        }
    }
}
#else
static inline void keygen_idle_wdt_unsubscribe(void) {}
static inline void keygen_idle_wdt_resubscribe(void) {}
#endif

// Re-read what was just written to NVS and check it matches what will be
// bound to the eFuse key. Anything short of an exact match means the burn
// would pair an unrecoverable HMAC key with unusable params.
static bool verify_stored_ds_params(esp_efuse_block_t block, const esp_ds_data_t* encrypted,
    const uint8_t* iv)
{
    esp_ds_data_ctx_t* check = crypto_storage_get_ds_ctx();
    if (check == NULL) {
        ESP_LOGE(TAG, "stored DS params could not be read back");
        return false;
    }

    bool ok = true;
    if (memcmp(check->esp_ds_data->c, encrypted->c, ESP_DS_C_LEN) != 0) {
        ESP_LOGE(TAG, "stored ciphertext does not match");
        ok = false;
    }
    if (memcmp(check->esp_ds_data->iv, iv, ESP_DS_IV_LEN) != 0) {
        ESP_LOGE(TAG, "stored IV does not match");
        ok = false;
    }
    if (check->efuse_key_id != (uint8_t)(block - EFUSE_BLK_KEY0)) {
        ESP_LOGE(TAG, "stored key id %u != expected %u",
            (unsigned)check->efuse_key_id, (unsigned)(block - EFUSE_BLK_KEY0));
        ok = false;
    }
    if (check->esp_ds_data->rsa_length != (CRYPTO_KEY_SIZE / 32) - 1) {
        ESP_LOGE(TAG, "stored rsa length %u != expected %u",
            (unsigned)check->esp_ds_data->rsa_length, (unsigned)((CRYPTO_KEY_SIZE / 32) - 1));
        ok = false;
    }

    mbedtls_platform_zeroize(check->esp_ds_data, sizeof(esp_ds_data_t));
    free(check->esp_ds_data);
    free(check);
    return ok;
}

// Drop everything persisted for a key that will never be burnt so the next
// attempt (or a provisioner inspecting the device) does not see stale state.
static void discard_failed_key_material(void) {
    esp_err_t err = crypto_storage_clear_ds_params();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to erase DS params after keygen failure: %s", esp_err_to_name(err));
    }
    err = crypto_storage_clear_csr();
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "failed to erase CSR after keygen failure: %s", esp_err_to_name(err));
    }
}

static void crypto_setup_task(void* pvParameter) {
    crypto_setup_params_t* params = (crypto_setup_params_t*)pvParameter;
    esp_efuse_block_t block = params->ds_key_block;
    esp_err_t result = ESP_FAIL;
    esp_err_t err;

    uint8_t iv[ESP_DS_IV_LEN] = { 0 };
    uint8_t hmac[32] = { 0 };

    esp_ds_data_t* encrypted = NULL;
    esp_ds_p_data_t* ds_params = NULL;
    psa_key_id_t key_id = 0;

    keygen_idle_wdt_unsubscribe();

    // Generate RSA key
    key_id = generate_rsa_key();
    if (key_id == 0) {
        ESP_LOGE(TAG, "key generation failed");
        goto cleanup;
    }

    // Store CSR
    if (store_csr(key_id) != ESP_OK) {
        ESP_LOGE(TAG, "store csr failed");
        goto fail_discard;
    }

    // Compute DS params
    ds_params = (esp_ds_p_data_t*)calloc(1, sizeof(esp_ds_p_data_t));
    if (!ds_params) {
        ESP_LOGE(TAG, "no mem for ds params");
        goto fail_discard;
    }

    if (psa_key_to_ds_params(key_id, ds_params) != ESP_OK) {
        ESP_LOGE(TAG, "PSA to DS failed");
        goto fail_discard;
    }

    // Generate IV and HMAC key
    esp_fill_random(iv, sizeof(iv));
    esp_fill_random(hmac, sizeof(hmac));

    encrypted = (esp_ds_data_t*)heap_caps_calloc(1, sizeof(esp_ds_data_t), MALLOC_CAP_DMA);
    if (!encrypted) {
        ESP_LOGE(TAG, "no mem for encrypted ds data");
        goto fail_discard;
    }

    err = esp_ds_encrypt_params(encrypted, iv, ds_params, hmac);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ds_encrypt_params failed: %s", esp_err_to_name(err));
        goto fail_discard;
    }

    // Plaintext params are no longer needed once encrypted.
    mbedtls_platform_zeroize(ds_params, sizeof(esp_ds_p_data_t));
    free(ds_params);
    ds_params = NULL;

    err = crypto_storage_store_ds_params(block, (CRYPTO_KEY_SIZE / 32) - 1,
        encrypted->c, ESP_DS_C_LEN, iv, ESP_DS_IV_LEN);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "storing DS params failed: %s", esp_err_to_name(err));
        goto fail_discard;
    }

    if (!verify_stored_ds_params(block, encrypted, iv)) {
        ESP_LOGE(TAG, "DS params read-back verification failed; not burning eFuse");
        goto fail_discard;
    }

    // Everything the DS peripheral needs is durably stored and verified:
    // now (and only now) bind the HMAC key into the eFuse.
    err = esp_efuse_write_key(block, ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE, hmac, sizeof(hmac));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_efuse_write_key(BLK_KEY%d) failed: %s",
            (int)(block - EFUSE_BLK_KEY0), esp_err_to_name(err));
        // The write is a single batch: on failure nothing was committed
        // unless the purpose reads back as ours (which would mean a partial
        // commit — keep the params in that case, they are still valid).
        if (esp_efuse_get_key_purpose(block) != ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE) {
            goto fail_discard;
        }
        goto cleanup;
    }

    // esp_efuse_write_key() already read-protects HMAC_DOWN_* blocks as part
    // of its batch; only act if that somehow did not stick.
    if (!esp_efuse_get_key_dis_read(block)) {
        err = esp_efuse_set_read_protect(block);
        if (err != ESP_OK) {
            // Key is burnt and functional; params stay. Report the error so
            // the caller can decide (it currently reboots, after which the
            // key is picked up normally).
            ESP_LOGE(TAG, "esp_efuse_set_read_protect(BLK_KEY%d) failed: %s",
                (int)(block - EFUSE_BLK_KEY0), esp_err_to_name(err));
            goto cleanup;
        }
    }

    ESP_LOGI(TAG, "DS key burnt to EFUSE_BLK_KEY%d", (int)(block - EFUSE_BLK_KEY0));
    result = ESP_OK;
    goto cleanup;

fail_discard:
    discard_failed_key_material();

cleanup:
    // Securely wipe sensitive keying material on every path.
    mbedtls_platform_zeroize(hmac, sizeof(hmac));
    mbedtls_platform_zeroize(iv, sizeof(iv));
    if (ds_params) {
        mbedtls_platform_zeroize(ds_params, sizeof(esp_ds_p_data_t));
        free(ds_params);
    }
    if (encrypted) {
        mbedtls_platform_zeroize(encrypted, sizeof(esp_ds_data_t));
        heap_caps_free(encrypted);
    }
    if (key_id != 0) {
        psa_destroy_key(key_id);
    }

    keygen_idle_wdt_resubscribe();

    // Publish the result and signal completion. The caller owns *params on
    // its stack and may return as soon as the mutex is given, so nothing
    // below may touch it.
    params->result = result;
    xSemaphoreGive(g_keygen_mutex);
    vTaskDelete(NULL);
}

// ============================================
// Main: ensure_key_exists - orchestrates all
// ============================================
esp_err_t ensure_key_exists(void) {
    // Mutex already created in crypto_init() via crypto_init_mutex()

    esp_efuse_block_t ds_key_block = crypto_get_ds_key_block_internal();
    bool has_fuses = esp_efuse_get_key_purpose(ds_key_block) ==
        ESP_EFUSE_KEY_PURPOSE_HMAC_DOWN_DIGITAL_SIGNATURE;

    if (has_fuses) {
        ESP_LOGI(TAG, "skipping keygen, key already burnt to block: %d", (ds_key_block - 4));
        if (kd_common_get_device_cert(NULL, NULL) == ESP_OK) {
            esp_err_t ds_test = kd_common_crypto_test_ds_signing();
            if (ds_test != ESP_OK) {
                ESP_LOGE(TAG, "DS signing verification failed — identity may be broken");
            }
            return ds_test;
        }
        return ESP_OK;
    }

    crypto_setup_params_t task_params = {
        .ds_key_block = ds_key_block,
        .result = ESP_FAIL,
    };

    // Hold the keygen mutex for the whole window (kd_common_crypto_get_state()
    // reports UNINITIALIZED while it is held). The worker gives it back when
    // done, which is what the wait loop below blocks on — no fixed delay, no
    // window in which an early take could be mistaken for completion.
    xSemaphoreTake(g_keygen_mutex, portMAX_DELAY);

    // Run all crypto operations on a separate task with a 20KB stack
    if (xTaskCreate(crypto_setup_task, "crypto_setup", 20000, &task_params, 5, NULL) != pdPASS) {
        ESP_LOGE(TAG, "failed to create crypto_setup task");
        xSemaphoreGive(g_keygen_mutex);
        return ESP_ERR_NO_MEM;
    }

    while (xSemaphoreTake(g_keygen_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGI(TAG, "crypto_setup_task still running");
    }
    xSemaphoreGive(g_keygen_mutex);

    if (task_params.result != ESP_OK) {
        nvs_handle_t nvs;
        uint8_t retries = 0;
        if (nvs_open("kd_crypto", NVS_READWRITE, &nvs) == ESP_OK) {
            nvs_get_u8(nvs, "kg_retries", &retries);
            retries++;
            nvs_set_u8(nvs, "kg_retries", retries);
            nvs_commit(nvs);
            nvs_close(nvs);
        }
        if (retries < KEYGEN_MAX_RETRIES) {
            ESP_LOGE(TAG, "Keygen failed (attempt %d/%d), restarting", retries, KEYGEN_MAX_RETRIES);
            esp_restart();
        }
        ESP_LOGE(TAG, "Keygen failed after %d attempts, entering degraded mode", KEYGEN_MAX_RETRIES);
        return ESP_FAIL;
    }

    // Clear retry counter on success
    nvs_handle_t nvs;
    if (nvs_open("kd_crypto", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_erase_key(nvs, "kg_retries");
        nvs_commit(nvs);
        nvs_close(nvs);
    }

    return ESP_OK;
}

// ============================================
// Cert renewal: regenerate CSR from DS key
// ============================================
esp_err_t kd_common_crypto_regenerate_csr(void) {
#ifndef CONFIG_MBEDTLS_HARDWARE_RSA_DS_PERIPHERAL
    ESP_LOGE(TAG, "DS peripheral not enabled — cannot regenerate CSR");
    return ESP_ERR_NOT_SUPPORTED;
#else
    esp_ds_data_ctx_t* ds_ctx = kd_common_crypto_get_ctx();
    if (ds_ctx == NULL) {
        ESP_LOGE(TAG, "No DS context — key not provisioned");
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t ret = ESP_FAIL;
    psa_key_id_t ds_key_id = 0;
    mbedtls_x509_crt crt;
    char* cert_pem = NULL;
    uint8_t* cri_buf = NULL;
    uint8_t* der_buf = NULL;
    uint8_t* sig = NULL;
    uint8_t* pem = NULL;
    int mbret;

    mbedtls_x509_crt_init(&crt);

    // The DS peripheral never releases the private key and its PSA driver has
    // no public-key export either, so mbedtls' CSR writer (which embeds the
    // public key) cannot run on the DS key. The public half comes from the
    // device certificate and the PKCS#10 request is assembled here; only the
    // signature goes through the DS key.
    size_t cert_len = 0;
    if (crypto_storage_get_device_cert(NULL, &cert_len) != ESP_OK || cert_len == 0) {
        ESP_LOGE(TAG, "No device certificate to take the public key from");
        ret = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }
    cert_pem = malloc(cert_len + 1);
    if (cert_pem == NULL) {
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }
    if (crypto_storage_get_device_cert(cert_pem, &cert_len) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read device certificate");
        goto cleanup;
    }
    cert_pem[cert_len] = '\0';
    mbret = mbedtls_x509_crt_parse(&crt, (const uint8_t*)cert_pem, strlen(cert_pem) + 1);
    if (mbret != 0) {
        ESP_LOGE(TAG, "Device certificate parse failed: -0x%04X", (unsigned)-mbret);
        goto cleanup;
    }
    if (!mbedtls_pk_can_do_psa(&crt.pk, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
                               PSA_KEY_USAGE_VERIFY_HASH) ||
        mbedtls_pk_get_bitlen(&crt.pk) != ds_ctx->rsa_length_bits) {
        ESP_LOGE(TAG, "Device certificate key (%u bits) does not match DS key (%u bits)",
                 (unsigned)mbedtls_pk_get_bitlen(&crt.pk), ds_ctx->rsa_length_bits);
        goto cleanup;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attr, ds_ctx->rsa_length_bits);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_ANY_HASH));
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_ESP_RSA_DS);

    psa_status_t status = psa_import_key(&attr,
        (const uint8_t*)ds_ctx, sizeof(esp_ds_data_ctx_t), &ds_key_id);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "Failed to import DS key to PSA: %d (efuse=%u bits=%u rsa_len=%d)",
                 status, ds_ctx->efuse_key_id, ds_ctx->rsa_length_bits,
                 ds_ctx->esp_ds_data->rsa_length);
        goto cleanup;
    }

    const size_t rsa_bytes = ds_ctx->rsa_length_bits / 8;
    const size_t cri_size = rsa_bytes + 256;
    const size_t der_size = 2 * rsa_bytes + 320;
    cri_buf = malloc(cri_size);
    der_buf = malloc(der_size);
    sig = malloc(rsa_bytes);
    if (cri_buf == NULL || der_buf == NULL || sig == NULL) {
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }

#define CSR_ASN1_ADD(total, expr) \
    do { \
        int _r = (expr); \
        if (_r < 0) { \
            ESP_LOGE(TAG, "CSR ASN.1 write failed: -0x%04X", (unsigned)-_r); \
            goto cleanup; \
        } \
        (total) += (size_t)_r; \
    } while (0)

    // CertificationRequestInfo ::= SEQUENCE { version, subject, subjectPKInfo,
    // attributes [0] } — written back to front, as mbedtls does.
    unsigned char* c = cri_buf + cri_size;
    size_t cri_len = 0;
    CSR_ASN1_ADD(cri_len, mbedtls_asn1_write_len(&c, cri_buf, 0));
    CSR_ASN1_ADD(cri_len, mbedtls_asn1_write_tag(&c, cri_buf,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC));

    mbret = mbedtls_pk_write_pubkey_der(&crt.pk, cri_buf, (size_t)(c - cri_buf));
    if (mbret < 0) {
        ESP_LOGE(TAG, "Public key write failed: -0x%04X", (unsigned)-mbret);
        goto cleanup;
    }
    c -= mbret;
    cri_len += (size_t)mbret;

    const char* cn = kd_common_get_device_name();
    size_t name_len = 0;
    CSR_ASN1_ADD(name_len, mbedtls_asn1_write_tagged_string(&c, cri_buf,
        MBEDTLS_ASN1_UTF8_STRING, cn, strlen(cn)));
    CSR_ASN1_ADD(name_len, mbedtls_asn1_write_oid(&c, cri_buf,
        MBEDTLS_OID_AT_CN, MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)));
    CSR_ASN1_ADD(name_len, mbedtls_asn1_write_len(&c, cri_buf, name_len));
    CSR_ASN1_ADD(name_len, mbedtls_asn1_write_tag(&c, cri_buf,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    CSR_ASN1_ADD(name_len, mbedtls_asn1_write_len(&c, cri_buf, name_len));
    CSR_ASN1_ADD(name_len, mbedtls_asn1_write_tag(&c, cri_buf,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
    CSR_ASN1_ADD(name_len, mbedtls_asn1_write_len(&c, cri_buf, name_len));
    CSR_ASN1_ADD(name_len, mbedtls_asn1_write_tag(&c, cri_buf,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    cri_len += name_len;

    CSR_ASN1_ADD(cri_len, mbedtls_asn1_write_int(&c, cri_buf, 0));
    CSR_ASN1_ADD(cri_len, mbedtls_asn1_write_len(&c, cri_buf, cri_len));
    CSR_ASN1_ADD(cri_len, mbedtls_asn1_write_tag(&c, cri_buf,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    const unsigned char* cri = c;

    uint8_t hash[32];
    size_t hash_len = 0;
    status = psa_hash_compute(PSA_ALG_SHA_256, cri, cri_len, hash, sizeof(hash), &hash_len);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "CSR hash failed: %d", status);
        goto cleanup;
    }

    // The DS lock wait is 0 until a TLS handshake raises it; a 0 wait fails
    // outright if another DS operation happens to be in flight.
    esp_rsa_ds_opaque_set_session_timeout(5000);
    size_t sig_len = 0;
    status = psa_sign_hash(ds_key_id, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
                           hash, hash_len, sig, rsa_bytes, &sig_len);
    if (status != PSA_SUCCESS) {
        ESP_LOGE(TAG, "DS signature failed: %d", status);
        goto cleanup;
    }

    // CertificationRequest ::= SEQUENCE { certificationRequestInfo,
    // signatureAlgorithm (sha256WithRSAEncryption), signature BIT STRING }
    unsigned char* d = der_buf + der_size;
    size_t der_len = 0;
    CSR_ASN1_ADD(der_len, mbedtls_asn1_write_bitstring(&d, der_buf, sig, sig_len * 8));
    CSR_ASN1_ADD(der_len, mbedtls_asn1_write_algorithm_identifier_ext(&d, der_buf,
        MBEDTLS_OID_PKCS1_SHA256, MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS1_SHA256), 0, 1));
    CSR_ASN1_ADD(der_len, mbedtls_asn1_write_raw_buffer(&d, der_buf, cri, cri_len));
    CSR_ASN1_ADD(der_len, mbedtls_asn1_write_len(&d, der_buf, der_len));
    CSR_ASN1_ADD(der_len, mbedtls_asn1_write_tag(&d, der_buf,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
#undef CSR_ASN1_ADD

    // base64 (4/3 + padding), a newline per 64 chars, header/footer, NUL
    const size_t pem_size = (der_len * 4) / 3 + der_len / 48 + 160;
    pem = malloc(pem_size);
    if (pem == NULL) {
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }
    size_t pem_len = 0;
    mbret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE REQUEST-----\n",
                                     "-----END CERTIFICATE REQUEST-----\n",
                                     d, der_len, pem, pem_size, &pem_len);
    if (mbret != 0) {
        ESP_LOGE(TAG, "CSR PEM encode failed: -0x%04X", (unsigned)-mbret);
        goto cleanup;
    }

    ret = crypto_storage_store_csr(pem, strlen((const char*)pem));
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to store regenerated CSR");
        goto cleanup;
    }

    ESP_LOGI(TAG, "CSR regenerated from DS key (%u-bit RSA, CN=%s)",
             ds_ctx->rsa_length_bits, cn);
    ret = ESP_OK;

cleanup:
    if (ds_key_id != 0) {
        psa_destroy_key(ds_key_id);
    }
    mbedtls_x509_crt_free(&crt);
    free(cert_pem);
    free(cri_buf);
    free(der_buf);
    free(sig);
    free(pem);
    mbedtls_platform_zeroize(ds_ctx->esp_ds_data, sizeof(esp_ds_data_t));
    free(ds_ctx->esp_ds_data);
    free(ds_ctx);
    return ret;
#endif
}

#endif // CONFIG_KD_COMMON_CRYPTO_ENABLE
