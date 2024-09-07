#include <stdio.h>

#include "esp_random.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "driver/uart_vfs.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "sdkconfig.h"

#include "system.h"

#include "c25519.h"
#include "omemo.h"

void ConnectWifi(void);

static void ParseBundle(struct omemoBundle *bundle, struct omemoStore *store) {
  int pk_id = 42; // Something truly random :)
  memcpy(bundle->spks, store->cursignedprekey.sig, sizeof(omemoCurveSignature));
  memcpy(bundle->spk, store->cursignedprekey.kp.pub, sizeof(omemoKey));
  memcpy(bundle->ik, store->identity.pub, sizeof(omemoKey));
  memcpy(bundle->pk, store->prekeys[pk_id-1].kp.pub, sizeof(omemoKey));
  assert(store->prekeys[pk_id-1].id == 42);
  bundle->pk_id = store->prekeys[pk_id-1].id;
  bundle->spk_id = store->cursignedprekey.id;
}

// user is either a or b
#define Send(user, id) do { \
    SystemRandom(messages[id].payload, OMEMO_PAYLOAD_SIZE); \
    omemoEncryptRatchet(&session##user, &store##user, &messages[id].msg, messages[id].payload); \
  } while (0)

#define Recv(user, id, isprekey) do { \
    omemoPayload dec; \
    omemoDecryptAnyMessage(&session##user, &store##user, dec, isprekey, messages[id].msg.p, messages[id].msg.n); \
    assert(!memcmp(messages[id].payload, dec, OMEMO_PAYLOAD_SIZE)); \
  } while (0);

static void TestSession() {
  static struct {
    omemoPayload payload;
    struct omemoKeyMessage msg;
  } messages[100];

  static struct omemoStore storea, storeb;
  omemoSetupStore(&storea);
  omemoSetupStore(&storeb);

  static struct omemoBundle bundleb;
  ParseBundle(&bundleb, &storeb);

  static struct omemoSession sessiona, sessionb;
  assert(!omemoSetupSession(&sessiona, 100));
  assert(!omemoSetupSession(&sessionb, 100));
  assert(omemoInitFromBundle(&sessiona, &storea, &bundleb) == 0);

  Send(a, 0);
  Recv(b, 0, true);

  Send(b, 1);
  Recv(a, 1, false);

  Send(b, 2);
  Recv(a, 2, false);

  Send(b, 3);
  Send(b, 4);

  assert(sessiona.mkskipped.n == 0);
  Recv(a, 4, false);

  assert(sessiona.mkskipped.n == 1);
  Recv(a, 3, false);
  assert(sessiona.mkskipped.n == 0);

  omemoFreeSession(&sessiona);
  omemoFreeSession(&sessionb);
}

void app_main(void)
{
  setvbuf(stdin, NULL, _IONBF, 0);
  ESP_ERROR_CHECK( uart_driver_install( (uart_port_t)CONFIG_ESP_CONSOLE_UART_NUM,
        256, 0, 0, NULL, 0) );
  uart_vfs_dev_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);
  uart_vfs_dev_port_set_rx_line_endings(CONFIG_ESP_CONSOLE_UART_NUM, ESP_LINE_ENDINGS_CR);
  uart_vfs_dev_port_set_tx_line_endings(CONFIG_ESP_CONSOLE_UART_NUM, ESP_LINE_ENDINGS_CRLF);

  ConnectWifi();

  //const unsigned MEASUREMENTS = 1;
  //omemoKey pub, prv;
  //esp_fill_random(prv, 32);
  //c25519_prepare(prv);
  //uint64_t start = esp_timer_get_time();
  //for (int retries = 0; retries < MEASUREMENTS; retries++) {
  //  curve25519(pub, prv, c25519_base_x);
  //}
  //uint64_t end = esp_timer_get_time();
  //printf("%u iterations took %llu milliseconds (%llu microseconds per invocation)\n",
  //   MEASUREMENTS, (end - start)/1000, (end - start)/MEASUREMENTS);

  //TestSession();

  RunIm();
}
