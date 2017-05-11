/*
 * (C) 2011-2014 Luigi Rizzo, Matteo Landi
 *
 * BSD license
 *
 * A netmap client to bridge two network interfaces
 * (or one interface and the host stack).
 *
 * $FreeBSD: head/tools/tools/netmap/bridge.c 228975 2011-12-30 00:04:11Z uqs $
 */

#include <elf.h>
#include <stdbool.h>
#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <ubpf.h>

typedef bool (*filter_func_t)(uint8_t *, uint16_t);
static bool default_filter(uint8_t *buf, uint16_t len);

struct ubpf_bridge_meta {
  uint16_t pkt_len;
  uint8_t src_port;
};

static struct {
  int verbose;
  int do_abort;
  int zero_copy;
  struct ubpf_vm *ubpf_vm;
  filter_func_t filter;
} ginfo;

static void init_ginfo(void) {
  ginfo.verbose = 0;
  ginfo.do_abort = 0;
  ginfo.zero_copy = 1;
  ginfo.ubpf_vm = NULL;
  ginfo.filter = default_filter;
}

static void sigint_h(int sig) {
  (void)sig; /* UNUSED */
  ginfo.do_abort = 1;
  signal(SIGINT, SIG_DFL);
}

static void *load_bpf_prog(const char *path, size_t maxlen, size_t *len) {
  FILE *file;
  if (!strcmp(path, "-")) {
    file = fdopen(STDIN_FILENO, "r");
  } else {
    file = fopen(path, "r");
  }

  if (file == NULL) {
    fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
    return NULL;
  }

  void *data = calloc(maxlen, 1);
  size_t offset = 0;
  size_t rv;
  while ((rv = fread(data + offset, 1, maxlen - offset, file)) > 0) {
    offset += rv;
  }

  if (ferror(file)) {
    fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
    fclose(file);
    free(data);
    return NULL;
  }

  if (!feof(file)) {
    fprintf(stderr,
            "Failed to read %s because it is too large (max %u bytes)\n", path,
            (unsigned)maxlen);
    fclose(file);
    free(data);
    return NULL;
  }

  fclose(file);
  if (len) {
    *len = offset;
  }
  return data;
}

static bool default_filter(uint8_t *buf, uint16_t len) { return false; }

int set_ubpf_filter(const char *prog) {
  size_t code_len;
  void *code;

  code = load_bpf_prog(prog, 1024 * 1024, &code_len);
  if (code == NULL) {
    fprintf(stderr, "Failed to load external bpf program");
    ginfo.filter = default_filter;
    return -1;
  }

  ginfo.ubpf_vm = ubpf_create();
  if (!ginfo.ubpf_vm) {
    fprintf(stderr, "Failed to create VM\n");
    ginfo.filter = default_filter;
    return -1;
  }

  bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);

  char *errmsg;
  int rv;
  if (elf) {
    rv = ubpf_load_elf(ginfo.ubpf_vm, code, code_len, &errmsg);
  } else {
    rv = ubpf_load(ginfo.ubpf_vm, code, code_len, &errmsg);
  }

  free(code);

  if (rv < 0) {
    fprintf(stderr, "Failed to load code: %s\n", errmsg);
    free(errmsg);
    ubpf_destroy(ginfo.ubpf_vm);
    ginfo.filter = default_filter;
    return -1;
  }

  ubpf_jit_fn fn = ubpf_compile(ginfo.ubpf_vm, &errmsg);
  if (fn == NULL) {
    fprintf(stderr, "Failed to compile: %s\n", errmsg);
    free(errmsg);
    return -1;
  }

  ginfo.filter = (filter_func_t)fn;

  return 0;
}

/*
 * how many packets on this set of queues ?
 */
int pkt_queued(struct nm_desc *d, int tx) {
  u_int i, tot = 0;

  if (tx) {
    for (i = d->first_tx_ring; i <= d->last_tx_ring; i++) {
      tot += nm_ring_space(NETMAP_TXRING(d->nifp, i));
    }
  } else {
    for (i = d->first_rx_ring; i <= d->last_rx_ring; i++) {
      tot += nm_ring_space(NETMAP_RXRING(d->nifp, i));
    }
  }
  return tot;
}

/*
 * move up to 'limit' pkts from rxring to txring swapping buffers.
 */
static int process_rings(struct netmap_ring *rxring, struct netmap_ring *txring,
                         u_int limit, const char *msg) {
  u_int j, k, m = 0;

  /* print a warning if any of the ring flags is set (e.g. NM_REINIT) */
  if (rxring->flags || txring->flags)
    D("%s rxflags %x txflags %x", msg, rxring->flags, txring->flags);
  j = rxring->cur; /* RX */
  k = txring->cur; /* TX */
  m = nm_ring_space(rxring);
  if (m < limit)
    limit = m;
  m = nm_ring_space(txring);
  if (m < limit)
    limit = m;
  m = limit;
  while (limit-- > 0) {
    bool pass = false;
    struct netmap_slot *rs = &rxring->slot[j];
    struct netmap_slot *ts = &txring->slot[k];
    char *rxbuf = NETMAP_BUF(rxring, rs->buf_idx);

    pass = ginfo.filter(rxbuf, rs->len);
    if (!pass) {
      D("packet drop");
      j = nm_ring_next(rxring, j);
      k = nm_ring_next(rxring, k);
      continue;
    }

    /* swap packets */
    if (ts->buf_idx < 2 || rs->buf_idx < 2) {
      D("wrong index rx[%d] = %d  -> tx[%d] = %d", j, rs->buf_idx, k,
        ts->buf_idx);
      sleep(2);
    }
    /* copy the packet length. */
    if (rs->len > 2048) {
      D("wrong len %d rx[%d] -> tx[%d]", rs->len, j, k);
      rs->len = 0;
    } else if (ginfo.verbose > 1) {
      D("%s send len %d rx[%d] -> tx[%d]", msg, rs->len, j, k);
    }
    ts->len = rs->len;
    if (ginfo.zero_copy) {
      uint32_t pkt = ts->buf_idx;
      ts->buf_idx = rs->buf_idx;
      rs->buf_idx = pkt;
      /* report the buffer change. */
      ts->flags |= NS_BUF_CHANGED;
      rs->flags |= NS_BUF_CHANGED;
    } else {
      char *txbuf = NETMAP_BUF(txring, ts->buf_idx);
      nm_pkt_copy(rxbuf, txbuf, ts->len);
    }
    j = nm_ring_next(rxring, j);
    k = nm_ring_next(txring, k);
  }
  rxring->head = rxring->cur = j;
  txring->head = txring->cur = k;
  if (ginfo.verbose && m > 0)
    D("%s sent %d packets to %p", msg, m, txring);

  return (m);
}

/* move packts from src to destination */
static int move(struct nm_desc *src, struct nm_desc *dst, u_int limit) {
  struct netmap_ring *txring, *rxring;
  u_int m = 0, si = src->first_rx_ring, di = dst->first_tx_ring;
  const char *msg =
      (src->req.nr_flags == NR_REG_SW) ? "host->net" : "net->host";

  while (si <= src->last_rx_ring && di <= dst->last_tx_ring) {
    rxring = NETMAP_RXRING(src->nifp, si);
    txring = NETMAP_TXRING(dst->nifp, di);
    ND("txring %p rxring %p", txring, rxring);
    if (nm_ring_empty(rxring)) {
      si++;
      continue;
    }
    if (nm_ring_empty(txring)) {
      di++;
      continue;
    }
    m += process_rings(rxring, txring, limit, msg);
  }

  return (m);
}

/*
void *filter_loader(void *arg) {
  int ssock, csock;
  struct sockaddr_un sa = {0};
  struct sockaddr_un ca = {0};

  if ((ssock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    return arg;
  }

  sa.sun_family = AF_UNIX;
  strcpy(sa.sun_path, USOCK_PATH);

  remove(sa.sun_path);

  if (bind(ssock, (struct sockaddr *)&sa, sizeof(struct sockaddr_un)) == -1) {
    perror("bind");
    goto end;
  }

  if (listen(ssock, 1) == -1) {
    perror("listen");
    goto end;
  }

  int err;
  socklen_t addrlen;
  struct pollfd pfd = {ssock, POLLIN, 0};
  while (!ginfo.do_abort) {
    err = poll(&pfd, 1, 2500);
    if (err == 0) {
      continue;
    } else if (err < 0) {
      goto end;
    }

    csock = accept(ssock, (struct sockaddr *)&ca, &addrlen);
    if (csock < 0) {
      goto end;
    }

    D("accepted client socket");
  }

  D("abort!");

end:
  close(ssock);
  return arg;
}
*/

static void usage(void) {
  fprintf(stderr, "netmap bridge program: forward packets between two "
                  "network interfaces\n"
                  "    usage(1): bridge [-v] [-i ifa] [-i ifb] [-b burst] "
                  "[-w wait_time] [-L]\n"
                  "    usage(2): bridge [-v] [-w wait_time] [-L] "
                  "[ifa [ifb [burst]]]\n"
                  "\n"
                  "    ifa and ifb are specified using the nm_open() syntax.\n"
                  "    When ifb is missing (or is equal to ifa), bridge will\n"
                  "    forward between between ifa and the host stack if -L\n"
                  "    is not specified, otherwise loopback traffic on ifa.\n"
                  "\n"
                  "    example: bridge -w 10 -i netmap:eth3 -i netmap:eth1\n"
                  "\n"
                  "You can set your own ebpf(ubpf) filter by specifying ebpf"
                  "program binary file using -f option\n");
  exit(1);
}

/*
 * bridge [-v] if1 [if2]
 *
 * If only one name, or the two interfaces are the same,
 * bridges userland and the adapter. Otherwise bridge
 * two intefaces.
 */
int main(int argc, char **argv) {
  struct pollfd pollfd[2];
  int ch, err;
  u_int burst = 1024, wait_link = 4;
  struct nm_desc *pa = NULL, *pb = NULL;
  char *ifa = NULL, *ifb = NULL;
  char ifabuf[64] = {0};
  int loopback = 0;

  fprintf(stderr, "%s built %s %s\n\n", argv[0], __DATE__, __TIME__);

  init_ginfo();

  while ((ch = getopt(argc, argv, "hb:ci:vw:Lf:")) != -1) {
    switch (ch) {
    default:
      D("bad option %c %s", ch, optarg);
    /* fallthrough */
    case 'h':
      usage();
      break;
    case 'b': /* burst */
      burst = atoi(optarg);
      break;
    case 'i': /* interface */
      if (ifa == NULL)
        ifa = optarg;
      else if (ifb == NULL)
        ifb = optarg;
      else
        D("%s ignored, already have 2 interfaces", optarg);
      break;
    case 'c':
      ginfo.zero_copy = 0; /* do not zero copy */
      break;
    case 'v':
      ginfo.verbose++;
      break;
    case 'w':
      wait_link = atoi(optarg);
      break;
    case 'L':
      loopback = 1;
      break;
    case 'f':
      err = set_ubpf_filter(optarg);
      if (err < 0) {
        fprintf(stderr, "Fallback to default filter");
      }
      break;
    }
  }

  argc -= optind;
  argv += optind;

  if (argc > 0)
    ifa = argv[0];
  if (argc > 1)
    ifb = argv[1];
  if (argc > 2)
    burst = atoi(argv[2]);
  if (!ifb)
    ifb = ifa;
  if (!ifa) {
    D("missing interface");
    usage();
  }
  if (burst < 1 || burst > 8192) {
    D("invalid burst %d, set to 1024", burst);
    burst = 1024;
  }
  if (wait_link > 100) {
    D("invalid wait_link %d, set to 4", wait_link);
    wait_link = 4;
  }
  if (!strcmp(ifa, ifb)) {
    if (!loopback) {
      D("same interface, endpoint 0 goes to host");
      snprintf(ifabuf, sizeof(ifabuf) - 1, "%s^", ifa);
      ifa = ifabuf;
    } else {
      D("same interface, loopbacking traffic");
    }
  } else {
    /* two different interfaces. Take all rings on if1 */
  }

  pa = nm_open(ifa, NULL, 0, NULL);
  if (pa == NULL) {
    D("cannot open %s", ifa);
    return (1);
  }
  /* try to reuse the mmap() of the first interface, if possible */
  pb = nm_open(ifb, NULL, NM_OPEN_NO_MMAP, pa);
  if (pb == NULL) {
    D("cannot open %s", ifb);
    nm_close(pa);
    return (1);
  }
  ginfo.zero_copy = ginfo.zero_copy && (pa->mem == pb->mem);
  D("------- zerocopy %ssupported", ginfo.zero_copy ? "" : "NOT ");

  /* setup poll(2) array */
  memset(pollfd, 0, sizeof(pollfd));
  pollfd[0].fd = pa->fd;
  pollfd[1].fd = pb->fd;

  D("Wait %d secs for link to come up...", wait_link);
  sleep(wait_link);
  D("Ready to go, %s 0x%x/%d <-> %s 0x%x/%d.", pa->req.nr_name,
    pa->first_rx_ring, pa->req.nr_rx_rings, pb->req.nr_name, pb->first_rx_ring,
    pb->req.nr_rx_rings);

  /* main loop */
  signal(SIGINT, sigint_h);
  while (!ginfo.do_abort) {
    int n0, n1, ret;
    pollfd[0].events = pollfd[1].events = 0;
    pollfd[0].revents = pollfd[1].revents = 0;
    n0 = pkt_queued(pa, 0);
    n1 = pkt_queued(pb, 0);
#if defined(_WIN32) || defined(BUSYWAIT)
    if (n0) {
      ioctl(pollfd[1].fd, NIOCTXSYNC, NULL);
      pollfd[1].revents = POLLOUT;
    } else {
      ioctl(pollfd[0].fd, NIOCRXSYNC, NULL);
    }
    if (n1) {
      ioctl(pollfd[0].fd, NIOCTXSYNC, NULL);
      pollfd[0].revents = POLLOUT;
    } else {
      ioctl(pollfd[1].fd, NIOCRXSYNC, NULL);
    }
    ret = 1;
#else
    if (n0)
      pollfd[1].events |= POLLOUT;
    else
      pollfd[0].events |= POLLIN;
    if (n1)
      pollfd[0].events |= POLLOUT;
    else
      pollfd[1].events |= POLLIN;

    /* poll() also cause kernel to txsync/rxsync the NICs */
    ret = poll(pollfd, 2, 2500);
#endif /* defined(_WIN32) || defined(BUSYWAIT) */
    if (ret <= 0 || ginfo.verbose)
      D("poll %s [0] ev %x %x rx %d@%d tx %d,"
        " [1] ev %x %x rx %d@%d tx %d",
        ret <= 0 ? "timeout" : "ok", pollfd[0].events, pollfd[0].revents,
        pkt_queued(pa, 0), NETMAP_RXRING(pa->nifp, pa->cur_rx_ring)->cur,
        pkt_queued(pa, 1), pollfd[1].events, pollfd[1].revents,
        pkt_queued(pb, 0), NETMAP_RXRING(pb->nifp, pb->cur_rx_ring)->cur,
        pkt_queued(pb, 1));
    if (ret < 0)
      continue;
    if (pollfd[0].revents & POLLERR) {
      struct netmap_ring *rx = NETMAP_RXRING(pa->nifp, pa->cur_rx_ring);
      D("error on fd0, rx [%d,%d,%d)", rx->head, rx->cur, rx->tail);
    }
    if (pollfd[1].revents & POLLERR) {
      struct netmap_ring *rx = NETMAP_RXRING(pb->nifp, pb->cur_rx_ring);
      D("error on fd1, rx [%d,%d,%d)", rx->head, rx->cur, rx->tail);
    }
    if (pollfd[0].revents & POLLOUT)
      move(pb, pa, burst);

    if (pollfd[1].revents & POLLOUT)
      move(pa, pb, burst);

    /* We don't need ioctl(NIOCTXSYNC) on the two file descriptors here,
     * kernel will txsync on next poll(). */
  }
  nm_close(pb);
  nm_close(pa);

  return (0);
}
