#include <stdio.h>

#include "esp_random.h"
#include "esp_timer.h"

#include "system.h"

#include "c25519.h"
#include "omemo.h"

//bool SystemPoll() {
//  return true;
//}

void app_main(void)
{
  const unsigned MEASUREMENTS = 5;
  omemoKey pub, prv;
  esp_fill_random(prv, 32);
  c25519_prepare(prv);
  uint64_t start = esp_timer_get_time();
  for (int retries = 0; retries < MEASUREMENTS; retries++) {
    curve25519(pub, prv, c25519_base_x);
  }
  uint64_t end = esp_timer_get_time();
  printf("%u iterations took %llu milliseconds (%llu microseconds per invocation)\n",
     MEASUREMENTS, (end - start)/1000, (end - start)/MEASUREMENTS);

  //RunIm();
}
