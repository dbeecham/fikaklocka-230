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
    %%{

        machine nats_parser;

        action debug {
            ESP_LOGI("NATS", "%c", *p);
        }

        action info {
            ESP_LOGI("NATSparse", "got INFO");
#ifdef NATS_SSL
            nats_ssl_info(&ssl);
#else
            nats_info(s);
#endif
        }

        action dance {
            BaseType_t ret = xQueueSend(d->event_queue, &COFFEE, 0);
            if (pdTRUE == ret) {
                ESP_LOGI("NATSparse", "DANCE!");
            } else if (errQUEUE_FULL == ret) {
                ESP_LOGI("NATSparse", "FULL!");
            }
        }

        action hi {
            ESP_LOGI("NATSparse", "Hello!");
        }

        action subscribe {
            ESP_LOGI("NATSparse", "Subscribing to NATS topics...");
#ifdef NATS_SSL
            nats_ssl_subscribe(&ssl);
#else
            nats_subscribe(s);
#endif

        }

        action pong {
            ESP_LOGI("NATSparse", "PING! (PONG!)");
#ifdef NATS_SSL
            nats_ssl_pong(&ssl);
#else
            nats_pong(s);
#endif
        }

        action disable {
            ESP_LOGI("NATSparse", "disable");
        }

        action query {
            ESP_LOGI("NATSparse", "query");
        }

        action enable {
            ESP_LOGI("NATSparse", "enable");
            xQueueSend(d->event_queue, &COFFEE, 0);
        }

        action copy_msg {
            msg[msg_i++] = *p;
        }

        action msg {
            msg[msg_i++] = 0;
        }

        action init_msg {
            char *msg = heap_caps_malloc(128, MALLOC_CAP_8BIT);
            if (NULL == msg) {
                ESP_LOGE("NATSparse", "MALLOC FAILED!\n");
                // TODO: exit
            }
            msg_i = 0;
        }

        action copy_replyto {
            replyto[replyto_i++] = *p;
        }

        action close_replyto {
            replyto[replyto_i++] = 0;
            replyto_i = 0;
        }

        subject = [A-Za-z0-9.]+;

        sid = digit+;

        replyto = ('_' | alpha)@copy_replyto ([A-Za-z0-9._+\-]){0,63} $copy_replyto;

        bytes = digit+;

        enable_msg = 'pp.dbe.blixt 1 1\r\n1\r\n' @enable;
        disable_msg = 'pp.dbe.blixt 1 1\r\n0\r\n' @disable;
        query = 'pp.dbe.blixt 1 ' replyto ' 0\r\n\r\n' @close_replyto @query;

        msg = 'MSG ' (query | enable_msg | disable_msg);

        ping = 'PING\r\n' @pong;

        info = 'INFO {' [A-Za-z0-9.:"_,\-]+ '}' ' '? '\r\n';

        loop := (info | ping | msg)* $err{ ESP_LOGE("NATS", "ERR: %c", *p); fgoto loop; };

        main := (info @info '+OK\r\n' @subscribe '+OK\r\n') $err{ ESP_LOGE("NATS", "ERR: %c", *p); } @{ fgoto loop; };

        write data;
        write init;
    }%%



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
            %% write exec;

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
