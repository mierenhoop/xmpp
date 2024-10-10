/**
 * Copyright 2024 mierenhoop
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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

#include "../config.h"

#include "c25519.h"
#include "omemo.h"

void ConnectWifi(void);

int omemoRandom(void *p, size_t n) { esp_fill_random(p, n); return 0; }
int xmppRandom(void *p, size_t n) { esp_fill_random(p, n); return 0; }

void LoadSession() {}
void SaveSession() {}

static void SetupStdio(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  ESP_ERROR_CHECK( uart_driver_install( (uart_port_t)CONFIG_ESP_CONSOLE_UART_NUM,
        256, 0, 0, NULL, 0) );
  uart_vfs_dev_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);
  uart_vfs_dev_port_set_rx_line_endings(CONFIG_ESP_CONSOLE_UART_NUM, ESP_LINE_ENDINGS_CR);
  uart_vfs_dev_port_set_tx_line_endings(CONFIG_ESP_CONSOLE_UART_NUM, ESP_LINE_ENDINGS_CRLF);
}

void app_main(void)
{
  SetupStdio();
  ConnectWifi();
  RunIm(IM_SERVER_IP);
}
