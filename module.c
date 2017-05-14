#include <stdint.h>
#include <stdbool.h>

bool myfilter(uint8_t *buf) {
  buf[0] = 0xaa;
  return true;
}
