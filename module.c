#include <stdint.h>
#include <stdbool.h>

struct eth {
  uint8_t dst[6];
  uint8_t src[6];
  uint16_t type;
};

bool myfilter(uint8_t *buf) {
  struct eth *eth;

  eth = (struct eth *)buf;

  eth->dst[0] = 0xaa;
  eth->dst[1] = 0xaa;
  eth->dst[2] = 0xaa;
  eth->dst[3] = 0xaa;
  eth->dst[4] = 0xaa;
  eth->dst[5] = 0xaa;

  return true;
}
