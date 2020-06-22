#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_log.h>
#include <stdint.h>
#include <string.h>


#include <srtp.h>


#define APPTAG "ESPSRTP"


static void srtp_test_task(void *context);
static esp_err_t srtp_test(void);
static void srtp_log_handler(srtp_log_level_t level, const char *msg, void *data);

static inline void app_perror(const char *what, srtp_err_status_t status) {
	ESP_LOGE(APPTAG, "%s failed with a code of %d.", what, status);
}


void app_main()
{
	const BaseType_t res = xTaskCreate(srtp_test_task, "srtp_test_task", 2048, NULL, 10, NULL);
	if (pdTRUE != res)
		ESP_LOGE(APPTAG, "xTaskCreate failed.");
}


// static
void srtp_test_task(void *context)
{
	srtp_err_status_t status;

	status = srtp_install_log_handler(srtp_log_handler, NULL);
	if (srtp_err_status_ok == status) {

		status = srtp_init();
		if (srtp_err_status_ok == status) {

			srtp_test();

			status = srtp_shutdown();
			if (srtp_err_status_ok != status)
				app_perror("srtp_shutdown", status);
		} else
			app_perror("srtp_init", status);
	} else
		app_perror("srtp_install_log_handler", status);

	ESP_LOGI(APPTAG, "Complete.  Module will restart in 60 seconds.");

	vTaskDelay(pdMS_TO_TICKS(60000));
	esp_restart();
}


// static
esp_err_t srtp_test(void)
{
	unsigned char aes_256_test_key[46] = {
			0xf0, 0xf0, 0x49, 0x14, 0xb5, 0x13, 0xf2, 0x76,
			0x3a, 0x1b, 0x1f, 0xa1, 0x30, 0xf1, 0x0e, 0x29,
			0x98, 0xf6, 0xf6, 0xe4, 0x3e, 0x43, 0x09, 0xd1,
			0xe6, 0x22, 0xa0, 0xe3, 0x32, 0xb9, 0xf1, 0xb6,

			0x3b, 0x04, 0x80, 0x3d, 0xe5, 0x1e, 0xe7, 0xc9,
			0x64, 0x23, 0xab, 0x5b, 0x78, 0xd2
	};
	uint8_t srtp_plaintext_ref[28] = {
			0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
			0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab
	};
	uint8_t srtp_plaintext[38] = {
			0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
			0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
			0xab, 0xab, 0xab, 0xab, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	uint8_t srtp_ciphertext[38] = {
			0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
			0xca, 0xfe, 0xba, 0xbe, 0xf1, 0xd9, 0xde, 0x17,
			0xff, 0x25, 0x1f, 0xf1, 0xaa, 0x00, 0x77, 0x74,
			0xb0, 0xb4, 0xb4, 0x0d, 0xa0, 0x8d, 0x9d, 0x9a,
			0x5b, 0x3a, 0x55, 0xd8, 0x87, 0x3b
	};

	srtp_policy_t policy;
	srtp_t srtp_snd, srtp_recv;
	srtp_err_status_t status;
	esp_err_t ret = ESP_FAIL;
	int len;

	memset(&policy, 0x0, sizeof(srtp_policy_t));
	srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(&policy.rtp);
	srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(&policy.rtcp);
	policy.ssrc.type = ssrc_specific;
	policy.ssrc.value = 0xcafebabe;
	policy.key = aes_256_test_key;
	policy.ekt = NULL;
	policy.window_size = 128;
	policy.allow_repeat_tx = 0;
	policy.next = NULL;

	ESP_LOGI(APPTAG, "Cisco SRTP AES-256 Reference Packet Validation Test.");

	status = srtp_create(&srtp_snd, &policy);
	if (srtp_err_status_ok == status) {

		do {
			len = 28;
			status = srtp_protect(srtp_snd, srtp_plaintext, &len);
			if (srtp_err_status_ok != status || (len != 38)) {
				app_perror("srtp_protect", status);
				break;
			}

			if (0 != memcmp(srtp_plaintext, srtp_ciphertext, len)) {
				ESP_LOGE(APPTAG, "Packet validation failed.");
				break;
			}

			status = srtp_create(&srtp_recv, &policy);
			if (srtp_err_status_ok == status) {

				do {
					status = srtp_unprotect(srtp_recv, srtp_ciphertext, &len);
					if (srtp_err_status_ok != status) {
						app_perror("srtp_unprotect", status);
						break;
					}

					if (0 != memcmp(srtp_ciphertext, srtp_plaintext_ref, len)) {
						ESP_LOGE(APPTAG, "Packet validation failed.");
						break;
					}

					ret = ESP_OK;

				} while (0);

				status = srtp_dealloc(srtp_recv);
				if (srtp_err_status_ok != status)
					app_perror("recv srtp_dealloc", status);

			} else
				app_perror("recv srtp_create", status);

		} while (0);

		status = srtp_dealloc(srtp_snd);
		if (srtp_err_status_ok != status)
			app_perror("send srtp_dealloc", status);

	} else
		app_perror("send srtp_create", status);

	if (ESP_OK == ret)
		ESP_LOGI(APPTAG, "SUCCESS");
	else
		ESP_LOGI(APPTAG, "FAILURE");

	return ret;
}


// static
void srtp_log_handler(srtp_log_level_t level, const char *msg, void *data)
{
	switch (level) {
	case srtp_log_level_error:
		ESP_LOGE(APPTAG, "%s", msg);
		break;
	case srtp_log_level_warning:
		ESP_LOGW(APPTAG, "%s", msg);
		break;
	case srtp_log_level_info:
		ESP_LOGI(APPTAG, "%s", msg);
		break;
	case srtp_log_level_debug:
		ESP_LOGD(APPTAG, "%s", msg);
		break;
	default:
		ESP_LOGE(APPTAG, "SRTP Log Handler called with an unexpected level of %d.", level);
		ESP_LOGE(APPTAG, "%s", msg);
	}
}
