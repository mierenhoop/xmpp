#include <stdio.h>

#include "esp_random.h"

#include "system.h"

#include "c25519.h"
#include "omemo.h"

//bool SystemPoll() {
//  return true;
//}

void app_main(void)
{
  omemoKey pub, prv;
  puts("Starting calc");
  esp_fill_random(prv, 32);
  c25519_prepare(prv);
  c25519_smult(pub, c25519_base_x, prv);
  puts("Done calc");
  //RunIm();
}
