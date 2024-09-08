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
