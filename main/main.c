
#line 1 "main/main.rl"
/* HTTPS GET Example using plain mbedTLS sockets
 *
 * Contacts the howsmyssl.com API via TLS v1.2 and reads a JSON
 * response.
 *
 * Adapted from the ssl_client1 example in mbedtls.
 *
 * Original Copyright (C) 2006-2016, ARM Limited, All Rights Reserved, Apache 2.0 License.
 * Additions Copyright (C) Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD, Apache 2.0 License.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_system.h"
#include "driver/i2c.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#define RELAY_PIN 18

struct app_data {
    EventGroupHandle_t net_event_group;
    QueueHandle_t event_queue;
};


/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int WIFI_CONNECTED_BIT = BIT0;
const int NATS_CONNECTED_BIT = BIT1;

static const char *TAG = "natsOLED";

const static uint8_t COFFEE = 1;

/* Root cert for howsmyssl.com, taken from server_root_cert.pem

   The PEM file was extracted from the output of this command:
   openssl s_client -showcerts -connect www.howsmyssl.com:443 </dev/null

   The CA root cert is the last cert given in the chain of certs.

   To embed it in the app binary, the PEM file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
*/
extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
extern const uint8_t server_root_cert_pem_end[]   asm("_binary_server_root_cert_pem_end");

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    struct app_data * d = (struct app_data*)ctx;
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(d->net_event_group, WIFI_CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        /* This is a workaround as ESP32 WiFi libs don't currently
           auto-reassociate. */
        esp_wifi_connect();
        xEventGroupClearBits(d->net_event_group, WIFI_CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

static void initialise_wifi(void * data)
{

    tcpip_adapter_init();
    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, data) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = CONFIG_WIFI_SSID,
            .password = CONFIG_WIFI_PASSWORD,
        },
    };
    ESP_LOGI(TAG, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK( esp_wifi_start() );

    vTaskDelete(NULL);
}

void nats_ssl_info(void * arg) {
    ESP_LOGI(TAG, "read INFO");

    const char * const REQUEST = "CONNECT {\"user\":\"" CONFIG_NATS_USER "\",\"pass\":\"" CONFIG_NATS_PASS "\"}\r\n";

    ESP_LOGE("REQUEST", "%s", REQUEST);

    mbedtls_ssl_context * ssl = (mbedtls_ssl_context*)arg;

    int written_bytes = 0;
    int ret = 0;
    do {
        ret = mbedtls_ssl_write(ssl,
                                (const unsigned char *)REQUEST + written_bytes,
                                strlen(REQUEST) - written_bytes);
        if (ret >= 0) {
            ESP_LOGI(TAG, "%d bytes written", ret);
            written_bytes += ret;
        } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
            ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
            return;
        }
    } while(written_bytes < strlen(REQUEST));

}

void nats_info(int sock) {
    ESP_LOGI(TAG, "read INFO");

    const char * const REQUEST = "CONNECT {\"user\":\"" CONFIG_NATS_USER "\",\"pass\":\"" CONFIG_NATS_PASS "\"}\r\n";

    ESP_LOGE("REQUEST", "%s", REQUEST);

    int written_bytes = 0;
    int ret = 0;
    do {
        ret = write(sock,
                                (const unsigned char *)REQUEST + written_bytes,
                                strlen(REQUEST) - written_bytes);
        if (ret >= 0) {
            ESP_LOGI(TAG, "%d bytes written", ret);
            written_bytes += ret;
        } else {
            break;
        }
    } while(written_bytes < strlen(REQUEST));

}

#ifdef NATS_SSL
void nats_ssl_pong(void * arg) {
    ESP_LOGI(TAG, "PONG!");

    const char * const REQUEST = "PONG\r\n";

    ESP_LOGE("REQUEST", "%s", REQUEST);

    mbedtls_ssl_context * ssl = (mbedtls_ssl_context*)arg;

    int written_bytes = 0;
    int ret = 0;
    do {
        ret = mbedtls_ssl_write(ssl,
                                (const unsigned char *)REQUEST + written_bytes,
                                strlen(REQUEST) - written_bytes);
        if (ret >= 0) {
            ESP_LOGI(TAG, "%d bytes written", ret);
            written_bytes += ret;
        } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
            ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
            return;
        }
    } while(written_bytes < strlen(REQUEST));

}
#else
void nats_pong(int sock) {
    ESP_LOGI(TAG, "PONG!");

    const char * const REQUEST = "PONG\r\n";

    ESP_LOGE("REQUEST", "%s", REQUEST);

    int written_bytes = 0;
    int ret = 0;
    do {
        ret = write(sock,
                                (const unsigned char *)REQUEST + written_bytes,
                                strlen(REQUEST) - written_bytes);
        if (ret >= 0) {
            ESP_LOGI(TAG, "%d bytes written", ret);
            written_bytes += ret;
        } else {
            break;
        }
    } while(written_bytes < strlen(REQUEST));

}
#endif

#ifdef NATS_SSL
void nats_ssl_subscribe(void * arg) {
    ESP_LOGI("NATSparse", "Subscribing to NATS topics...");

    const char * const REQUEST = "SUB pp.dbe.blixt 1\r\n";

    ESP_LOGE("REQUEST", "%s", REQUEST);

    mbedtls_ssl_context * ssl = (mbedtls_ssl_context*)arg;

    int written_bytes = 0;
    int ret = 0;
    do {
        ret = mbedtls_ssl_write(ssl,
                                (const unsigned char *)REQUEST + written_bytes,
                                strlen(REQUEST) - written_bytes);
        if (ret >= 0) {
            ESP_LOGI(TAG, "%d bytes written", ret);
            written_bytes += ret;
        } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
            ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
            return;
        }
    } while(written_bytes < strlen(REQUEST));

}
#else
void nats_subscribe(int sock) {
    ESP_LOGI("NATSparse", "Subscribing to NATS topics...");

    const char * const REQUEST = "SUB pp.dbe.blixt 1\r\n";

    ESP_LOGE("REQUEST", "%s", REQUEST);

    int written_bytes = 0;
    int ret = 0;
    do {
        ret = write(sock,
                                (const unsigned char *)REQUEST + written_bytes,
                                strlen(REQUEST) - written_bytes);
        if (ret >= 0) {
            ESP_LOGI(TAG, "%d bytes written", ret);
            written_bytes += ret;
        } else {
            break;
        }
    } while(written_bytes < strlen(REQUEST));

}
#endif

void nats_hi(void * arg) {
    ESP_LOGI(TAG, "HI!\n");
}


static void nats_task(void *data)
{

    
    struct app_data * d = (struct app_data*)data;

    int cs;
    char *p, *pe, *eof = NULL;
    int msg_i = 0;
    int s;
    char msg[128] = {0};
    char replyto[64];
    uint_fast8_t replyto_i = 0;
    
#line 299 "main/main.c"
static const int nats_parser_start = 1;
static const int nats_parser_first_final = 132;
static const int nats_parser_error = 0;

static const int nats_parser_en_loop = 133;
static const int nats_parser_en_main = 1;


#line 308 "main/main.c"
	{
	cs = nats_parser_start;
	}

#line 407 "main/main.rl"




    char buf[512];
    int ret, flags, len;

#ifdef NATS_SSL
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    NULL, 0)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ESP_LOGI(TAG, "Loading the CA root certificate...");

    ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start,
                                 server_root_cert_pem_end-server_root_cert_pem_start);

    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

     /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&ssl, CONFIG_NATS_HOST)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    if((ret = mbedtls_ssl_config_defaults(&conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.

       You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
    */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&conf, 4);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }


#else
    const struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *res;
    struct in_addr *addr;
#endif

    while(1) {
        /* Wait for the callback to set the WIFI_CONNECTED_BIT in the
           event group.
        */
        xEventGroupWaitBits(d->net_event_group, WIFI_CONNECTED_BIT,
                            false, true, portMAX_DELAY);
        ESP_LOGI(TAG, "Connected to AP");

#ifdef NATS_SSL
        mbedtls_net_init(&server_fd);
#endif


        ESP_LOGI(TAG, "Connecting to %s:%s...", CONFIG_NATS_HOST, CONFIG_NATS_PORT);

#ifdef NATS_SSL
        if ((ret = mbedtls_net_connect(&server_fd, CONFIG_NATS_HOST,
                                      CONFIG_NATS_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }
#else
        ret = getaddrinfo(CONFIG_NATS_HOST, CONFIG_NATS_PORT, &hints, &res);
        if(ret != 0 || res == NULL) {
            ESP_LOGE(TAG, "DNS lookup failed ret=%d res=%p", ret, res);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            assert(false);
        }
        addr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
        ESP_LOGI(TAG, "DNS lookup succeeded. IP=%s", inet_ntoa(*addr));
        s = socket(res->ai_family, res->ai_socktype, 0);
        if(s < 0) {
            ESP_LOGE(TAG, "... Failed to allocate socket.");
            freeaddrinfo(res);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            continue;
        }
        ESP_LOGI(TAG, "... allocated socket");

        if(connect(s, res->ai_addr, res->ai_addrlen) != 0) {
            ESP_LOGE(TAG, "... socket connect failed ret=%d", errno);
            close(s);
            freeaddrinfo(res);
            vTaskDelay(4000 / portTICK_PERIOD_MS);
            continue;
        }

        ESP_LOGI(TAG, "... connected");
        freeaddrinfo(res);
#endif

        ESP_LOGI(TAG, "Connected.");

#ifdef NATS_SSL
        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                goto exit;
            }
        }

        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
        {
            /* In real life, we probably want to close connection if ret != 0 */
            ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            ESP_LOGW(TAG, "verification info: %s", buf);
        }
        else {
            ESP_LOGI(TAG, "Certificate verified.");
        }

        ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ssl));
#endif


        xEventGroupSetBits(d->net_event_group, NATS_CONNECTED_BIT);

        do
        {
            len = sizeof(buf) - 1;

#ifdef NATS_SSL
            ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);

            if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;

            if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ret = 0;
                break;
            }
#else
            ret = read(s, buf, len);
#endif

            if(ret < 0)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
                break;
            }

            if(ret == 0)
            {
                ESP_LOGI(TAG, "connection closed");
                break;
            }

            p = buf;
            pe = buf + ret;
            
#line 524 "main/main.c"
	{
	if ( p == pe )
		goto _test_eof;
	switch ( cs )
	{
case 1:
	if ( (*p) == 73 )
		goto st2;
	goto tr0;
tr0:
#line 403 "main/main.rl"
	{ ESP_LOGE("NATS", "ERR: %c", *p); }
	goto st0;
tr22:
#line 401 "main/main.rl"
	{ ESP_LOGE("NATS", "ERR: %c", *p); {goto st133;} }
	goto st0;
#line 542 "main/main.c"
st0:
cs = 0;
	goto _out;
st2:
	if ( ++p == pe )
		goto _test_eof2;
case 2:
	if ( (*p) == 78 )
		goto st3;
	goto tr0;
st3:
	if ( ++p == pe )
		goto _test_eof3;
case 3:
	if ( (*p) == 70 )
		goto st4;
	goto tr0;
st4:
	if ( ++p == pe )
		goto _test_eof4;
case 4:
	if ( (*p) == 79 )
		goto st5;
	goto tr0;
st5:
	if ( ++p == pe )
		goto _test_eof5;
case 5:
	if ( (*p) == 32 )
		goto st6;
	goto tr0;
st6:
	if ( ++p == pe )
		goto _test_eof6;
case 6:
	if ( (*p) == 123 )
		goto st7;
	goto tr0;
st7:
	if ( ++p == pe )
		goto _test_eof7;
case 7:
	switch( (*p) ) {
		case 34: goto st8;
		case 95: goto st8;
	}
	if ( (*p) < 48 ) {
		if ( 44 <= (*p) && (*p) <= 46 )
			goto st8;
	} else if ( (*p) > 58 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto st8;
		} else if ( (*p) >= 65 )
			goto st8;
	} else
		goto st8;
	goto tr0;
st8:
	if ( ++p == pe )
		goto _test_eof8;
case 8:
	switch( (*p) ) {
		case 34: goto st8;
		case 95: goto st8;
		case 125: goto st9;
	}
	if ( (*p) < 48 ) {
		if ( 44 <= (*p) && (*p) <= 46 )
			goto st8;
	} else if ( (*p) > 58 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto st8;
		} else if ( (*p) >= 65 )
			goto st8;
	} else
		goto st8;
	goto tr0;
st9:
	if ( ++p == pe )
		goto _test_eof9;
case 9:
	switch( (*p) ) {
		case 13: goto st10;
		case 32: goto st21;
	}
	goto tr0;
st10:
	if ( ++p == pe )
		goto _test_eof10;
case 10:
	if ( (*p) == 10 )
		goto tr11;
	goto tr0;
tr11:
#line 303 "main/main.rl"
	{
            ESP_LOGI("NATSparse", "got INFO");
#ifdef NATS_SSL
            nats_ssl_info(&ssl);
#else
            nats_info(s);
#endif
        }
	goto st11;
st11:
	if ( ++p == pe )
		goto _test_eof11;
case 11:
#line 653 "main/main.c"
	if ( (*p) == 43 )
		goto st12;
	goto tr0;
st12:
	if ( ++p == pe )
		goto _test_eof12;
case 12:
	if ( (*p) == 79 )
		goto st13;
	goto tr0;
st13:
	if ( ++p == pe )
		goto _test_eof13;
case 13:
	if ( (*p) == 75 )
		goto st14;
	goto tr0;
st14:
	if ( ++p == pe )
		goto _test_eof14;
case 14:
	if ( (*p) == 13 )
		goto st15;
	goto tr0;
st15:
	if ( ++p == pe )
		goto _test_eof15;
case 15:
	if ( (*p) == 10 )
		goto tr16;
	goto tr0;
tr16:
#line 325 "main/main.rl"
	{
            ESP_LOGI("NATSparse", "Subscribing to NATS topics...");
#ifdef NATS_SSL
            nats_ssl_subscribe(&ssl);
#else
            nats_subscribe(s);
#endif

        }
	goto st16;
st16:
	if ( ++p == pe )
		goto _test_eof16;
case 16:
#line 701 "main/main.c"
	if ( (*p) == 43 )
		goto st17;
	goto tr0;
st17:
	if ( ++p == pe )
		goto _test_eof17;
case 17:
	if ( (*p) == 79 )
		goto st18;
	goto tr0;
st18:
	if ( ++p == pe )
		goto _test_eof18;
case 18:
	if ( (*p) == 75 )
		goto st19;
	goto tr0;
st19:
	if ( ++p == pe )
		goto _test_eof19;
case 19:
	if ( (*p) == 13 )
		goto st20;
	goto tr0;
st20:
	if ( ++p == pe )
		goto _test_eof20;
case 20:
	if ( (*p) == 10 )
		goto tr21;
	goto tr0;
tr21:
#line 403 "main/main.rl"
	{ {goto st133;} }
	goto st132;
st132:
	if ( ++p == pe )
		goto _test_eof132;
case 132:
#line 741 "main/main.c"
	goto tr0;
st21:
	if ( ++p == pe )
		goto _test_eof21;
case 21:
	if ( (*p) == 13 )
		goto st10;
	goto tr0;
tr58:
#line 344 "main/main.rl"
	{
            ESP_LOGI("NATSparse", "disable");
        }
	goto st133;
tr60:
#line 352 "main/main.rl"
	{
            ESP_LOGI("NATSparse", "enable");
            xQueueSend(d->event_queue, &COFFEE, 0);
        }
	goto st133;
tr67:
#line 378 "main/main.rl"
	{
            replyto[replyto_i++] = 0;
            replyto_i = 0;
        }
#line 348 "main/main.rl"
	{
            ESP_LOGI("NATSparse", "query");
        }
	goto st133;
tr134:
#line 335 "main/main.rl"
	{
            ESP_LOGI("NATSparse", "PING! (PONG!)");
#ifdef NATS_SSL
            nats_ssl_pong(&ssl);
#else
            nats_pong(s);
#endif
        }
	goto st133;
st133:
	if ( ++p == pe )
		goto _test_eof133;
case 133:
#line 789 "main/main.c"
	switch( (*p) ) {
		case 73: goto st22;
		case 77: goto st32;
		case 80: goto st127;
	}
	goto tr22;
st22:
	if ( ++p == pe )
		goto _test_eof22;
case 22:
	if ( (*p) == 78 )
		goto st23;
	goto tr22;
st23:
	if ( ++p == pe )
		goto _test_eof23;
case 23:
	if ( (*p) == 70 )
		goto st24;
	goto tr22;
st24:
	if ( ++p == pe )
		goto _test_eof24;
case 24:
	if ( (*p) == 79 )
		goto st25;
	goto tr22;
st25:
	if ( ++p == pe )
		goto _test_eof25;
case 25:
	if ( (*p) == 32 )
		goto st26;
	goto tr22;
st26:
	if ( ++p == pe )
		goto _test_eof26;
case 26:
	if ( (*p) == 123 )
		goto st27;
	goto tr22;
st27:
	if ( ++p == pe )
		goto _test_eof27;
case 27:
	switch( (*p) ) {
		case 34: goto st28;
		case 95: goto st28;
	}
	if ( (*p) < 48 ) {
		if ( 44 <= (*p) && (*p) <= 46 )
			goto st28;
	} else if ( (*p) > 58 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto st28;
		} else if ( (*p) >= 65 )
			goto st28;
	} else
		goto st28;
	goto tr22;
st28:
	if ( ++p == pe )
		goto _test_eof28;
case 28:
	switch( (*p) ) {
		case 34: goto st28;
		case 95: goto st28;
		case 125: goto st29;
	}
	if ( (*p) < 48 ) {
		if ( 44 <= (*p) && (*p) <= 46 )
			goto st28;
	} else if ( (*p) > 58 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto st28;
		} else if ( (*p) >= 65 )
			goto st28;
	} else
		goto st28;
	goto tr22;
st29:
	if ( ++p == pe )
		goto _test_eof29;
case 29:
	switch( (*p) ) {
		case 13: goto st30;
		case 32: goto st31;
	}
	goto tr22;
st30:
	if ( ++p == pe )
		goto _test_eof30;
case 30:
	if ( (*p) == 10 )
		goto st133;
	goto tr22;
st31:
	if ( ++p == pe )
		goto _test_eof31;
case 31:
	if ( (*p) == 13 )
		goto st30;
	goto tr22;
st32:
	if ( ++p == pe )
		goto _test_eof32;
case 32:
	if ( (*p) == 83 )
		goto st33;
	goto tr22;
st33:
	if ( ++p == pe )
		goto _test_eof33;
case 33:
	if ( (*p) == 71 )
		goto st34;
	goto tr22;
st34:
	if ( ++p == pe )
		goto _test_eof34;
case 34:
	if ( (*p) == 32 )
		goto st35;
	goto tr22;
st35:
	if ( ++p == pe )
		goto _test_eof35;
case 35:
	if ( (*p) == 112 )
		goto st36;
	goto tr22;
st36:
	if ( ++p == pe )
		goto _test_eof36;
case 36:
	if ( (*p) == 112 )
		goto st37;
	goto tr22;
st37:
	if ( ++p == pe )
		goto _test_eof37;
case 37:
	if ( (*p) == 46 )
		goto st38;
	goto tr22;
st38:
	if ( ++p == pe )
		goto _test_eof38;
case 38:
	if ( (*p) == 100 )
		goto st39;
	goto tr22;
st39:
	if ( ++p == pe )
		goto _test_eof39;
case 39:
	if ( (*p) == 98 )
		goto st40;
	goto tr22;
st40:
	if ( ++p == pe )
		goto _test_eof40;
case 40:
	if ( (*p) == 101 )
		goto st41;
	goto tr22;
st41:
	if ( ++p == pe )
		goto _test_eof41;
case 41:
	if ( (*p) == 46 )
		goto st42;
	goto tr22;
st42:
	if ( ++p == pe )
		goto _test_eof42;
case 42:
	if ( (*p) == 98 )
		goto st43;
	goto tr22;
st43:
	if ( ++p == pe )
		goto _test_eof43;
case 43:
	if ( (*p) == 108 )
		goto st44;
	goto tr22;
st44:
	if ( ++p == pe )
		goto _test_eof44;
case 44:
	if ( (*p) == 105 )
		goto st45;
	goto tr22;
st45:
	if ( ++p == pe )
		goto _test_eof45;
case 45:
	if ( (*p) == 120 )
		goto st46;
	goto tr22;
st46:
	if ( ++p == pe )
		goto _test_eof46;
case 46:
	if ( (*p) == 116 )
		goto st47;
	goto tr22;
st47:
	if ( ++p == pe )
		goto _test_eof47;
case 47:
	if ( (*p) == 32 )
		goto st48;
	goto tr22;
st48:
	if ( ++p == pe )
		goto _test_eof48;
case 48:
	if ( (*p) == 49 )
		goto st49;
	goto tr22;
st49:
	if ( ++p == pe )
		goto _test_eof49;
case 49:
	if ( (*p) == 32 )
		goto st50;
	goto tr22;
st50:
	if ( ++p == pe )
		goto _test_eof50;
case 50:
	switch( (*p) ) {
		case 49: goto st51;
		case 95: goto tr52;
	}
	if ( (*p) > 90 ) {
		if ( 97 <= (*p) && (*p) <= 122 )
			goto tr52;
	} else if ( (*p) >= 65 )
		goto tr52;
	goto tr22;
st51:
	if ( ++p == pe )
		goto _test_eof51;
case 51:
	if ( (*p) == 13 )
		goto st52;
	goto tr22;
st52:
	if ( ++p == pe )
		goto _test_eof52;
case 52:
	if ( (*p) == 10 )
		goto st53;
	goto tr22;
st53:
	if ( ++p == pe )
		goto _test_eof53;
case 53:
	switch( (*p) ) {
		case 48: goto st54;
		case 49: goto st56;
	}
	goto tr22;
st54:
	if ( ++p == pe )
		goto _test_eof54;
case 54:
	if ( (*p) == 13 )
		goto st55;
	goto tr22;
st55:
	if ( ++p == pe )
		goto _test_eof55;
case 55:
	if ( (*p) == 10 )
		goto tr58;
	goto tr22;
st56:
	if ( ++p == pe )
		goto _test_eof56;
case 56:
	if ( (*p) == 13 )
		goto st57;
	goto tr22;
st57:
	if ( ++p == pe )
		goto _test_eof57;
case 57:
	if ( (*p) == 10 )
		goto tr60;
	goto tr22;
tr52:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st58;
st58:
	if ( ++p == pe )
		goto _test_eof58;
case 58:
#line 1096 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr62;
		case 95: goto tr62;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr62;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr62;
		} else if ( (*p) >= 65 )
			goto tr62;
	} else
		goto tr62;
	goto tr22;
st59:
	if ( ++p == pe )
		goto _test_eof59;
case 59:
	if ( (*p) == 48 )
		goto st60;
	goto tr22;
st60:
	if ( ++p == pe )
		goto _test_eof60;
case 60:
	if ( (*p) == 13 )
		goto st61;
	goto tr22;
st61:
	if ( ++p == pe )
		goto _test_eof61;
case 61:
	if ( (*p) == 10 )
		goto st62;
	goto tr22;
st62:
	if ( ++p == pe )
		goto _test_eof62;
case 62:
	if ( (*p) == 13 )
		goto st63;
	goto tr22;
st63:
	if ( ++p == pe )
		goto _test_eof63;
case 63:
	if ( (*p) == 10 )
		goto tr67;
	goto tr22;
tr62:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st64;
st64:
	if ( ++p == pe )
		goto _test_eof64;
case 64:
#line 1159 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr68;
		case 95: goto tr68;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr68;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr68;
		} else if ( (*p) >= 65 )
			goto tr68;
	} else
		goto tr68;
	goto tr22;
tr68:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st65;
st65:
	if ( ++p == pe )
		goto _test_eof65;
case 65:
#line 1187 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr69;
		case 95: goto tr69;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr69;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr69;
		} else if ( (*p) >= 65 )
			goto tr69;
	} else
		goto tr69;
	goto tr22;
tr69:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st66;
st66:
	if ( ++p == pe )
		goto _test_eof66;
case 66:
#line 1215 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr70;
		case 95: goto tr70;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr70;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr70;
		} else if ( (*p) >= 65 )
			goto tr70;
	} else
		goto tr70;
	goto tr22;
tr70:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st67;
st67:
	if ( ++p == pe )
		goto _test_eof67;
case 67:
#line 1243 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr71;
		case 95: goto tr71;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr71;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr71;
		} else if ( (*p) >= 65 )
			goto tr71;
	} else
		goto tr71;
	goto tr22;
tr71:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st68;
st68:
	if ( ++p == pe )
		goto _test_eof68;
case 68:
#line 1271 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr72;
		case 95: goto tr72;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr72;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr72;
		} else if ( (*p) >= 65 )
			goto tr72;
	} else
		goto tr72;
	goto tr22;
tr72:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st69;
st69:
	if ( ++p == pe )
		goto _test_eof69;
case 69:
#line 1299 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr73;
		case 95: goto tr73;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr73;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr73;
		} else if ( (*p) >= 65 )
			goto tr73;
	} else
		goto tr73;
	goto tr22;
tr73:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st70;
st70:
	if ( ++p == pe )
		goto _test_eof70;
case 70:
#line 1327 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr74;
		case 95: goto tr74;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr74;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr74;
		} else if ( (*p) >= 65 )
			goto tr74;
	} else
		goto tr74;
	goto tr22;
tr74:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st71;
st71:
	if ( ++p == pe )
		goto _test_eof71;
case 71:
#line 1355 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr75;
		case 95: goto tr75;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr75;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr75;
		} else if ( (*p) >= 65 )
			goto tr75;
	} else
		goto tr75;
	goto tr22;
tr75:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st72;
st72:
	if ( ++p == pe )
		goto _test_eof72;
case 72:
#line 1383 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr76;
		case 95: goto tr76;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr76;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr76;
		} else if ( (*p) >= 65 )
			goto tr76;
	} else
		goto tr76;
	goto tr22;
tr76:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st73;
st73:
	if ( ++p == pe )
		goto _test_eof73;
case 73:
#line 1411 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr77;
		case 95: goto tr77;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr77;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr77;
		} else if ( (*p) >= 65 )
			goto tr77;
	} else
		goto tr77;
	goto tr22;
tr77:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st74;
st74:
	if ( ++p == pe )
		goto _test_eof74;
case 74:
#line 1439 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr78;
		case 95: goto tr78;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr78;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr78;
		} else if ( (*p) >= 65 )
			goto tr78;
	} else
		goto tr78;
	goto tr22;
tr78:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st75;
st75:
	if ( ++p == pe )
		goto _test_eof75;
case 75:
#line 1467 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr79;
		case 95: goto tr79;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr79;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr79;
		} else if ( (*p) >= 65 )
			goto tr79;
	} else
		goto tr79;
	goto tr22;
tr79:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st76;
st76:
	if ( ++p == pe )
		goto _test_eof76;
case 76:
#line 1495 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr80;
		case 95: goto tr80;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr80;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr80;
		} else if ( (*p) >= 65 )
			goto tr80;
	} else
		goto tr80;
	goto tr22;
tr80:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st77;
st77:
	if ( ++p == pe )
		goto _test_eof77;
case 77:
#line 1523 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr81;
		case 95: goto tr81;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr81;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr81;
		} else if ( (*p) >= 65 )
			goto tr81;
	} else
		goto tr81;
	goto tr22;
tr81:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st78;
st78:
	if ( ++p == pe )
		goto _test_eof78;
case 78:
#line 1551 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr82;
		case 95: goto tr82;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr82;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr82;
		} else if ( (*p) >= 65 )
			goto tr82;
	} else
		goto tr82;
	goto tr22;
tr82:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st79;
st79:
	if ( ++p == pe )
		goto _test_eof79;
case 79:
#line 1579 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr83;
		case 95: goto tr83;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr83;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr83;
		} else if ( (*p) >= 65 )
			goto tr83;
	} else
		goto tr83;
	goto tr22;
tr83:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st80;
st80:
	if ( ++p == pe )
		goto _test_eof80;
case 80:
#line 1607 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr84;
		case 95: goto tr84;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr84;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr84;
		} else if ( (*p) >= 65 )
			goto tr84;
	} else
		goto tr84;
	goto tr22;
tr84:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st81;
st81:
	if ( ++p == pe )
		goto _test_eof81;
case 81:
#line 1635 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr85;
		case 95: goto tr85;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr85;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr85;
		} else if ( (*p) >= 65 )
			goto tr85;
	} else
		goto tr85;
	goto tr22;
tr85:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st82;
st82:
	if ( ++p == pe )
		goto _test_eof82;
case 82:
#line 1663 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr86;
		case 95: goto tr86;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr86;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr86;
		} else if ( (*p) >= 65 )
			goto tr86;
	} else
		goto tr86;
	goto tr22;
tr86:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st83;
st83:
	if ( ++p == pe )
		goto _test_eof83;
case 83:
#line 1691 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr87;
		case 95: goto tr87;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr87;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr87;
		} else if ( (*p) >= 65 )
			goto tr87;
	} else
		goto tr87;
	goto tr22;
tr87:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st84;
st84:
	if ( ++p == pe )
		goto _test_eof84;
case 84:
#line 1719 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr88;
		case 95: goto tr88;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr88;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr88;
		} else if ( (*p) >= 65 )
			goto tr88;
	} else
		goto tr88;
	goto tr22;
tr88:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st85;
st85:
	if ( ++p == pe )
		goto _test_eof85;
case 85:
#line 1747 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr89;
		case 95: goto tr89;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr89;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr89;
		} else if ( (*p) >= 65 )
			goto tr89;
	} else
		goto tr89;
	goto tr22;
tr89:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st86;
st86:
	if ( ++p == pe )
		goto _test_eof86;
case 86:
#line 1775 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr90;
		case 95: goto tr90;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr90;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr90;
		} else if ( (*p) >= 65 )
			goto tr90;
	} else
		goto tr90;
	goto tr22;
tr90:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st87;
st87:
	if ( ++p == pe )
		goto _test_eof87;
case 87:
#line 1803 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr91;
		case 95: goto tr91;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr91;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr91;
		} else if ( (*p) >= 65 )
			goto tr91;
	} else
		goto tr91;
	goto tr22;
tr91:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st88;
st88:
	if ( ++p == pe )
		goto _test_eof88;
case 88:
#line 1831 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr92;
		case 95: goto tr92;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr92;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr92;
		} else if ( (*p) >= 65 )
			goto tr92;
	} else
		goto tr92;
	goto tr22;
tr92:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st89;
st89:
	if ( ++p == pe )
		goto _test_eof89;
case 89:
#line 1859 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr93;
		case 95: goto tr93;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr93;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr93;
		} else if ( (*p) >= 65 )
			goto tr93;
	} else
		goto tr93;
	goto tr22;
tr93:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st90;
st90:
	if ( ++p == pe )
		goto _test_eof90;
case 90:
#line 1887 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr94;
		case 95: goto tr94;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr94;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr94;
		} else if ( (*p) >= 65 )
			goto tr94;
	} else
		goto tr94;
	goto tr22;
tr94:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st91;
st91:
	if ( ++p == pe )
		goto _test_eof91;
case 91:
#line 1915 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr95;
		case 95: goto tr95;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr95;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr95;
		} else if ( (*p) >= 65 )
			goto tr95;
	} else
		goto tr95;
	goto tr22;
tr95:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st92;
st92:
	if ( ++p == pe )
		goto _test_eof92;
case 92:
#line 1943 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr96;
		case 95: goto tr96;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr96;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr96;
		} else if ( (*p) >= 65 )
			goto tr96;
	} else
		goto tr96;
	goto tr22;
tr96:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st93;
st93:
	if ( ++p == pe )
		goto _test_eof93;
case 93:
#line 1971 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr97;
		case 95: goto tr97;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr97;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr97;
		} else if ( (*p) >= 65 )
			goto tr97;
	} else
		goto tr97;
	goto tr22;
tr97:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st94;
st94:
	if ( ++p == pe )
		goto _test_eof94;
case 94:
#line 1999 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr98;
		case 95: goto tr98;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr98;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr98;
		} else if ( (*p) >= 65 )
			goto tr98;
	} else
		goto tr98;
	goto tr22;
tr98:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st95;
st95:
	if ( ++p == pe )
		goto _test_eof95;
case 95:
#line 2027 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr99;
		case 95: goto tr99;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr99;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr99;
		} else if ( (*p) >= 65 )
			goto tr99;
	} else
		goto tr99;
	goto tr22;
tr99:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st96;
st96:
	if ( ++p == pe )
		goto _test_eof96;
case 96:
#line 2055 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr100;
		case 95: goto tr100;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr100;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr100;
		} else if ( (*p) >= 65 )
			goto tr100;
	} else
		goto tr100;
	goto tr22;
tr100:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st97;
st97:
	if ( ++p == pe )
		goto _test_eof97;
case 97:
#line 2083 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr101;
		case 95: goto tr101;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr101;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr101;
		} else if ( (*p) >= 65 )
			goto tr101;
	} else
		goto tr101;
	goto tr22;
tr101:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st98;
st98:
	if ( ++p == pe )
		goto _test_eof98;
case 98:
#line 2111 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr102;
		case 95: goto tr102;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr102;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr102;
		} else if ( (*p) >= 65 )
			goto tr102;
	} else
		goto tr102;
	goto tr22;
tr102:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st99;
st99:
	if ( ++p == pe )
		goto _test_eof99;
case 99:
#line 2139 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr103;
		case 95: goto tr103;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr103;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr103;
		} else if ( (*p) >= 65 )
			goto tr103;
	} else
		goto tr103;
	goto tr22;
tr103:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st100;
st100:
	if ( ++p == pe )
		goto _test_eof100;
case 100:
#line 2167 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr104;
		case 95: goto tr104;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr104;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr104;
		} else if ( (*p) >= 65 )
			goto tr104;
	} else
		goto tr104;
	goto tr22;
tr104:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st101;
st101:
	if ( ++p == pe )
		goto _test_eof101;
case 101:
#line 2195 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr105;
		case 95: goto tr105;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr105;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr105;
		} else if ( (*p) >= 65 )
			goto tr105;
	} else
		goto tr105;
	goto tr22;
tr105:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st102;
st102:
	if ( ++p == pe )
		goto _test_eof102;
case 102:
#line 2223 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr106;
		case 95: goto tr106;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr106;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr106;
		} else if ( (*p) >= 65 )
			goto tr106;
	} else
		goto tr106;
	goto tr22;
tr106:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st103;
st103:
	if ( ++p == pe )
		goto _test_eof103;
case 103:
#line 2251 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr107;
		case 95: goto tr107;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr107;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr107;
		} else if ( (*p) >= 65 )
			goto tr107;
	} else
		goto tr107;
	goto tr22;
tr107:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st104;
st104:
	if ( ++p == pe )
		goto _test_eof104;
case 104:
#line 2279 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr108;
		case 95: goto tr108;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr108;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr108;
		} else if ( (*p) >= 65 )
			goto tr108;
	} else
		goto tr108;
	goto tr22;
tr108:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st105;
st105:
	if ( ++p == pe )
		goto _test_eof105;
case 105:
#line 2307 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr109;
		case 95: goto tr109;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr109;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr109;
		} else if ( (*p) >= 65 )
			goto tr109;
	} else
		goto tr109;
	goto tr22;
tr109:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st106;
st106:
	if ( ++p == pe )
		goto _test_eof106;
case 106:
#line 2335 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr110;
		case 95: goto tr110;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr110;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr110;
		} else if ( (*p) >= 65 )
			goto tr110;
	} else
		goto tr110;
	goto tr22;
tr110:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st107;
st107:
	if ( ++p == pe )
		goto _test_eof107;
case 107:
#line 2363 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr111;
		case 95: goto tr111;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr111;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr111;
		} else if ( (*p) >= 65 )
			goto tr111;
	} else
		goto tr111;
	goto tr22;
tr111:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st108;
st108:
	if ( ++p == pe )
		goto _test_eof108;
case 108:
#line 2391 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr112;
		case 95: goto tr112;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr112;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr112;
		} else if ( (*p) >= 65 )
			goto tr112;
	} else
		goto tr112;
	goto tr22;
tr112:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st109;
st109:
	if ( ++p == pe )
		goto _test_eof109;
case 109:
#line 2419 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr113;
		case 95: goto tr113;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr113;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr113;
		} else if ( (*p) >= 65 )
			goto tr113;
	} else
		goto tr113;
	goto tr22;
tr113:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st110;
st110:
	if ( ++p == pe )
		goto _test_eof110;
case 110:
#line 2447 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr114;
		case 95: goto tr114;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr114;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr114;
		} else if ( (*p) >= 65 )
			goto tr114;
	} else
		goto tr114;
	goto tr22;
tr114:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st111;
st111:
	if ( ++p == pe )
		goto _test_eof111;
case 111:
#line 2475 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr115;
		case 95: goto tr115;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr115;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr115;
		} else if ( (*p) >= 65 )
			goto tr115;
	} else
		goto tr115;
	goto tr22;
tr115:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st112;
st112:
	if ( ++p == pe )
		goto _test_eof112;
case 112:
#line 2503 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr116;
		case 95: goto tr116;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr116;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr116;
		} else if ( (*p) >= 65 )
			goto tr116;
	} else
		goto tr116;
	goto tr22;
tr116:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st113;
st113:
	if ( ++p == pe )
		goto _test_eof113;
case 113:
#line 2531 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr117;
		case 95: goto tr117;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr117;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr117;
		} else if ( (*p) >= 65 )
			goto tr117;
	} else
		goto tr117;
	goto tr22;
tr117:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st114;
st114:
	if ( ++p == pe )
		goto _test_eof114;
case 114:
#line 2559 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr118;
		case 95: goto tr118;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr118;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr118;
		} else if ( (*p) >= 65 )
			goto tr118;
	} else
		goto tr118;
	goto tr22;
tr118:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st115;
st115:
	if ( ++p == pe )
		goto _test_eof115;
case 115:
#line 2587 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr119;
		case 95: goto tr119;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr119;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr119;
		} else if ( (*p) >= 65 )
			goto tr119;
	} else
		goto tr119;
	goto tr22;
tr119:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st116;
st116:
	if ( ++p == pe )
		goto _test_eof116;
case 116:
#line 2615 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr120;
		case 95: goto tr120;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr120;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr120;
		} else if ( (*p) >= 65 )
			goto tr120;
	} else
		goto tr120;
	goto tr22;
tr120:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st117;
st117:
	if ( ++p == pe )
		goto _test_eof117;
case 117:
#line 2643 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr121;
		case 95: goto tr121;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr121;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr121;
		} else if ( (*p) >= 65 )
			goto tr121;
	} else
		goto tr121;
	goto tr22;
tr121:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st118;
st118:
	if ( ++p == pe )
		goto _test_eof118;
case 118:
#line 2671 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr122;
		case 95: goto tr122;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr122;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr122;
		} else if ( (*p) >= 65 )
			goto tr122;
	} else
		goto tr122;
	goto tr22;
tr122:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st119;
st119:
	if ( ++p == pe )
		goto _test_eof119;
case 119:
#line 2699 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr123;
		case 95: goto tr123;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr123;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr123;
		} else if ( (*p) >= 65 )
			goto tr123;
	} else
		goto tr123;
	goto tr22;
tr123:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st120;
st120:
	if ( ++p == pe )
		goto _test_eof120;
case 120:
#line 2727 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr124;
		case 95: goto tr124;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr124;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr124;
		} else if ( (*p) >= 65 )
			goto tr124;
	} else
		goto tr124;
	goto tr22;
tr124:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st121;
st121:
	if ( ++p == pe )
		goto _test_eof121;
case 121:
#line 2755 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr125;
		case 95: goto tr125;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr125;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr125;
		} else if ( (*p) >= 65 )
			goto tr125;
	} else
		goto tr125;
	goto tr22;
tr125:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st122;
st122:
	if ( ++p == pe )
		goto _test_eof122;
case 122:
#line 2783 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr126;
		case 95: goto tr126;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr126;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr126;
		} else if ( (*p) >= 65 )
			goto tr126;
	} else
		goto tr126;
	goto tr22;
tr126:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st123;
st123:
	if ( ++p == pe )
		goto _test_eof123;
case 123:
#line 2811 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr127;
		case 95: goto tr127;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr127;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr127;
		} else if ( (*p) >= 65 )
			goto tr127;
	} else
		goto tr127;
	goto tr22;
tr127:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st124;
st124:
	if ( ++p == pe )
		goto _test_eof124;
case 124:
#line 2839 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr128;
		case 95: goto tr128;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr128;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr128;
		} else if ( (*p) >= 65 )
			goto tr128;
	} else
		goto tr128;
	goto tr22;
tr128:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st125;
st125:
	if ( ++p == pe )
		goto _test_eof125;
case 125:
#line 2867 "main/main.c"
	switch( (*p) ) {
		case 32: goto st59;
		case 43: goto tr129;
		case 95: goto tr129;
	}
	if ( (*p) < 48 ) {
		if ( 45 <= (*p) && (*p) <= 46 )
			goto tr129;
	} else if ( (*p) > 57 ) {
		if ( (*p) > 90 ) {
			if ( 97 <= (*p) && (*p) <= 122 )
				goto tr129;
		} else if ( (*p) >= 65 )
			goto tr129;
	} else
		goto tr129;
	goto tr22;
tr129:
#line 374 "main/main.rl"
	{
            replyto[replyto_i++] = *p;
        }
	goto st126;
st126:
	if ( ++p == pe )
		goto _test_eof126;
case 126:
#line 2895 "main/main.c"
	if ( (*p) == 32 )
		goto st59;
	goto tr22;
st127:
	if ( ++p == pe )
		goto _test_eof127;
case 127:
	if ( (*p) == 73 )
		goto st128;
	goto tr22;
st128:
	if ( ++p == pe )
		goto _test_eof128;
case 128:
	if ( (*p) == 78 )
		goto st129;
	goto tr22;
st129:
	if ( ++p == pe )
		goto _test_eof129;
case 129:
	if ( (*p) == 71 )
		goto st130;
	goto tr22;
st130:
	if ( ++p == pe )
		goto _test_eof130;
case 130:
	if ( (*p) == 13 )
		goto st131;
	goto tr22;
st131:
	if ( ++p == pe )
		goto _test_eof131;
case 131:
	if ( (*p) == 10 )
		goto tr134;
	goto tr22;
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof132: cs = 132; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof133: cs = 133; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof50: cs = 50; goto _test_eof; 
	_test_eof51: cs = 51; goto _test_eof; 
	_test_eof52: cs = 52; goto _test_eof; 
	_test_eof53: cs = 53; goto _test_eof; 
	_test_eof54: cs = 54; goto _test_eof; 
	_test_eof55: cs = 55; goto _test_eof; 
	_test_eof56: cs = 56; goto _test_eof; 
	_test_eof57: cs = 57; goto _test_eof; 
	_test_eof58: cs = 58; goto _test_eof; 
	_test_eof59: cs = 59; goto _test_eof; 
	_test_eof60: cs = 60; goto _test_eof; 
	_test_eof61: cs = 61; goto _test_eof; 
	_test_eof62: cs = 62; goto _test_eof; 
	_test_eof63: cs = 63; goto _test_eof; 
	_test_eof64: cs = 64; goto _test_eof; 
	_test_eof65: cs = 65; goto _test_eof; 
	_test_eof66: cs = 66; goto _test_eof; 
	_test_eof67: cs = 67; goto _test_eof; 
	_test_eof68: cs = 68; goto _test_eof; 
	_test_eof69: cs = 69; goto _test_eof; 
	_test_eof70: cs = 70; goto _test_eof; 
	_test_eof71: cs = 71; goto _test_eof; 
	_test_eof72: cs = 72; goto _test_eof; 
	_test_eof73: cs = 73; goto _test_eof; 
	_test_eof74: cs = 74; goto _test_eof; 
	_test_eof75: cs = 75; goto _test_eof; 
	_test_eof76: cs = 76; goto _test_eof; 
	_test_eof77: cs = 77; goto _test_eof; 
	_test_eof78: cs = 78; goto _test_eof; 
	_test_eof79: cs = 79; goto _test_eof; 
	_test_eof80: cs = 80; goto _test_eof; 
	_test_eof81: cs = 81; goto _test_eof; 
	_test_eof82: cs = 82; goto _test_eof; 
	_test_eof83: cs = 83; goto _test_eof; 
	_test_eof84: cs = 84; goto _test_eof; 
	_test_eof85: cs = 85; goto _test_eof; 
	_test_eof86: cs = 86; goto _test_eof; 
	_test_eof87: cs = 87; goto _test_eof; 
	_test_eof88: cs = 88; goto _test_eof; 
	_test_eof89: cs = 89; goto _test_eof; 
	_test_eof90: cs = 90; goto _test_eof; 
	_test_eof91: cs = 91; goto _test_eof; 
	_test_eof92: cs = 92; goto _test_eof; 
	_test_eof93: cs = 93; goto _test_eof; 
	_test_eof94: cs = 94; goto _test_eof; 
	_test_eof95: cs = 95; goto _test_eof; 
	_test_eof96: cs = 96; goto _test_eof; 
	_test_eof97: cs = 97; goto _test_eof; 
	_test_eof98: cs = 98; goto _test_eof; 
	_test_eof99: cs = 99; goto _test_eof; 
	_test_eof100: cs = 100; goto _test_eof; 
	_test_eof101: cs = 101; goto _test_eof; 
	_test_eof102: cs = 102; goto _test_eof; 
	_test_eof103: cs = 103; goto _test_eof; 
	_test_eof104: cs = 104; goto _test_eof; 
	_test_eof105: cs = 105; goto _test_eof; 
	_test_eof106: cs = 106; goto _test_eof; 
	_test_eof107: cs = 107; goto _test_eof; 
	_test_eof108: cs = 108; goto _test_eof; 
	_test_eof109: cs = 109; goto _test_eof; 
	_test_eof110: cs = 110; goto _test_eof; 
	_test_eof111: cs = 111; goto _test_eof; 
	_test_eof112: cs = 112; goto _test_eof; 
	_test_eof113: cs = 113; goto _test_eof; 
	_test_eof114: cs = 114; goto _test_eof; 
	_test_eof115: cs = 115; goto _test_eof; 
	_test_eof116: cs = 116; goto _test_eof; 
	_test_eof117: cs = 117; goto _test_eof; 
	_test_eof118: cs = 118; goto _test_eof; 
	_test_eof119: cs = 119; goto _test_eof; 
	_test_eof120: cs = 120; goto _test_eof; 
	_test_eof121: cs = 121; goto _test_eof; 
	_test_eof122: cs = 122; goto _test_eof; 
	_test_eof123: cs = 123; goto _test_eof; 
	_test_eof124: cs = 124; goto _test_eof; 
	_test_eof125: cs = 125; goto _test_eof; 
	_test_eof126: cs = 126; goto _test_eof; 
	_test_eof127: cs = 127; goto _test_eof; 
	_test_eof128: cs = 128; goto _test_eof; 
	_test_eof129: cs = 129; goto _test_eof; 
	_test_eof130: cs = 130; goto _test_eof; 
	_test_eof131: cs = 131; goto _test_eof; 

	_test_eof: {}
	if ( p == eof )
	{
	switch ( cs ) {
	case 22: 
	case 23: 
	case 24: 
	case 25: 
	case 26: 
	case 27: 
	case 28: 
	case 29: 
	case 30: 
	case 31: 
	case 32: 
	case 33: 
	case 34: 
	case 35: 
	case 36: 
	case 37: 
	case 38: 
	case 39: 
	case 40: 
	case 41: 
	case 42: 
	case 43: 
	case 44: 
	case 45: 
	case 46: 
	case 47: 
	case 48: 
	case 49: 
	case 50: 
	case 51: 
	case 52: 
	case 53: 
	case 54: 
	case 55: 
	case 56: 
	case 57: 
	case 58: 
	case 59: 
	case 60: 
	case 61: 
	case 62: 
	case 63: 
	case 64: 
	case 65: 
	case 66: 
	case 67: 
	case 68: 
	case 69: 
	case 70: 
	case 71: 
	case 72: 
	case 73: 
	case 74: 
	case 75: 
	case 76: 
	case 77: 
	case 78: 
	case 79: 
	case 80: 
	case 81: 
	case 82: 
	case 83: 
	case 84: 
	case 85: 
	case 86: 
	case 87: 
	case 88: 
	case 89: 
	case 90: 
	case 91: 
	case 92: 
	case 93: 
	case 94: 
	case 95: 
	case 96: 
	case 97: 
	case 98: 
	case 99: 
	case 100: 
	case 101: 
	case 102: 
	case 103: 
	case 104: 
	case 105: 
	case 106: 
	case 107: 
	case 108: 
	case 109: 
	case 110: 
	case 111: 
	case 112: 
	case 113: 
	case 114: 
	case 115: 
	case 116: 
	case 117: 
	case 118: 
	case 119: 
	case 120: 
	case 121: 
	case 122: 
	case 123: 
	case 124: 
	case 125: 
	case 126: 
	case 127: 
	case 128: 
	case 129: 
	case 130: 
	case 131: 
#line 401 "main/main.rl"
	{ ESP_LOGE("NATS", "ERR: %c", *p); {goto st133;} }
	break;
	case 1: 
	case 2: 
	case 3: 
	case 4: 
	case 5: 
	case 6: 
	case 7: 
	case 8: 
	case 9: 
	case 10: 
	case 11: 
	case 12: 
	case 13: 
	case 14: 
	case 15: 
	case 16: 
	case 17: 
	case 18: 
	case 19: 
	case 20: 
	case 21: 
#line 403 "main/main.rl"
	{ ESP_LOGE("NATS", "ERR: %c", *p); }
	break;
#line 3209 "main/main.c"
	}
	}

	_out: {}
	}

#line 617 "main/main.rl"

            len = ret;
            ESP_LOGI(TAG, "%d bytes read", len);
            /* Print response directly to stdout as it is read */
            for(int i = 0; i < len; i++) {
                putchar(buf[i]);
            }

            if (ret == len) {
                continue;
            }

            break;

        } while(1);

#ifdef NATS_SSL
        mbedtls_ssl_close_notify(&ssl);

    exit:
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if(ret != 0)
        {
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        }
        putchar('\n'); // JSON output doesn't have a newline at end

        static int request_count;
        ESP_LOGI(TAG, "Completed %d requests", ++request_count);

        for(int countdown = 10; countdown >= 0; countdown--) {
            ESP_LOGI(TAG, "%d...", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
#endif
    }
}

void task_relay(void * data)
{
    struct app_data * d = data;
    BaseType_t qres;
    uint_fast8_t count = 0;
    uint_fast8_t event;
    while (true) {
        qres = xQueueReceive(d->event_queue, &event, 500 / portTICK_PERIOD_MS);
        if (pdFALSE == qres) {
            continue;
        }

        if (1 == event) {
            gpio_set_level(RELAY_PIN, 0);
            vTaskDelay(4000 / portTICK_PERIOD_MS);
            gpio_set_level(RELAY_PIN, 1);
        }
    }
}

void app_main()
{
    gpio_config_t relay_conf;
    relay_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    relay_conf.mode = GPIO_MODE_OUTPUT;
    relay_conf.pin_bit_mask = 1ULL << RELAY_PIN;
    relay_conf.pull_down_en = 0;
    relay_conf.pull_up_en = 1;
    gpio_config(&relay_conf);
    gpio_set_level(RELAY_PIN, 1);

    /* FreeRTOS event group to signal when we are connected & ready to make a request */
    EventGroupHandle_t wifi_event_group = xEventGroupCreate();
    QueueHandle_t event_queue = xQueueCreate(2, 1);

    struct app_data d = {
        .net_event_group = wifi_event_group,
        .event_queue = event_queue
    };

    ESP_ERROR_CHECK( nvs_flash_init() );
    xTaskCreatePinnedToCore(initialise_wifi, "wifi init task", 8192, &d, 5, NULL, 0);
    xTaskCreatePinnedToCore(nats_task, "nats task", 8192, &d, 4, NULL, 0);
    xTaskCreatePinnedToCore(task_relay, "relay task", 8192, &d, 4, NULL, 1);

    while (true) {
        vTaskDelay(10000/portTICK_PERIOD_MS);
    }
    vTaskSuspend(NULL);

}
