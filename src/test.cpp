#include "hidapi/hidapi.h"
#include "univalue.h"
#include "crypto/aes.h"

#include <assert.h>
#include <string.h>

int main() {
  
  uint8_t key[32] = {0};
  uint8_t test_in[32]= {0};
  uint8_t test_out[32]= {0};
  AES256Encrypt enc(&key[0]);
  enc.Encrypt(&test_out[0], &test_in[0]);
  AES256Decrypt dec(&key[0]);
  dec.Decrypt(&test_out[0], &test_out[0]);
  
  assert(memcmp(&test_out[0], &test_in[0], 32) == 0);
  return 1;
}