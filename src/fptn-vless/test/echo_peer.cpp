// Test peer: a second lwIP instance (10.0.0.2) in its own process. It plays the
// "remote host behind the FPTN server". IP packets travel over stdin/stdout as
// frames: [u16 big-endian length][packet].
//   port 7  : echo (small messages)
//   port 9  : source - sends kSourceBytes of pattern (i % 251), then closes
//   port 19 : sink   - counts bytes + byte sum, answers [u32 count][u32 sum] on FIN
#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" {
#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
u32_t sys_now(void) {
  static const auto t0 = std::chrono::steady_clock::now();
  return (u32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - t0).count();
}
}

static constexpr std::size_t kSourceBytes = 4 * 1024 * 1024;

static bool WriteAll(int fd, const void* d, size_t n) {
  const char* p = static_cast<const char*>(d);
  while (n > 0) {
    ssize_t w = write(fd, p, n);
    if (w <= 0) return false;
    p += w; n -= (size_t)w;
  }
  return true;
}

static err_t IpOut(struct netif*, struct pbuf* p, const ip4_addr_t*) {
  std::vector<uint8_t> f(2 + p->tot_len);
  f[0] = (uint8_t)(p->tot_len >> 8); f[1] = (uint8_t)p->tot_len;
  pbuf_copy_partial(p, f.data() + 2, p->tot_len, 0);
  WriteAll(1, f.data(), f.size());
  return ERR_OK;
}
static err_t NetifInit(struct netif* n) {
  n->name[0] = 'p'; n->name[1] = 'r'; n->output = IpOut; n->mtu = 1420;
  n->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP; return ERR_OK;
}

struct Conn { uint16_t port; size_t sent = 0; uint32_t count = 0, sum = 0; };

static void SourcePump(tcp_pcb* pcb, Conn* c) {
  while (c->sent < kSourceBytes && tcp_sndbuf(pcb) > 0) {
    size_t n = std::min<size_t>({tcp_sndbuf(pcb), kSourceBytes - c->sent, 8192});
    std::vector<uint8_t> buf(n);
    for (size_t i = 0; i < n; ++i) buf[i] = (uint8_t)((c->sent + i) % 251);
    if (tcp_write(pcb, buf.data(), (u16_t)n, TCP_WRITE_FLAG_COPY) != ERR_OK) break;
    c->sent += n;
  }
  tcp_output(pcb);
  if (c->sent >= kSourceBytes) {
    tcp_arg(pcb, nullptr); tcp_sent(pcb, nullptr); tcp_recv(pcb, nullptr);
    tcp_close(pcb); delete c;
  }
}
static err_t OnSent(void* a, tcp_pcb* pcb, u16_t) {
  if (a) { SourcePump(pcb, static_cast<Conn*>(a)); }
  return ERR_OK;
}
static err_t OnRecv(void* a, tcp_pcb* pcb, pbuf* p, err_t) {
  Conn* c = static_cast<Conn*>(a);
  if (!c) { if (p) pbuf_free(p); return ERR_OK; }
  if (!p) {  // FIN
    if (c->port == 19) {
      uint8_t r[8] = {(uint8_t)(c->count >> 24), (uint8_t)(c->count >> 16), (uint8_t)(c->count >> 8), (uint8_t)c->count,
                      (uint8_t)(c->sum >> 24), (uint8_t)(c->sum >> 16), (uint8_t)(c->sum >> 8), (uint8_t)c->sum};
      tcp_write(pcb, r, 8, TCP_WRITE_FLAG_COPY); tcp_output(pcb);
    }
    tcp_arg(pcb, nullptr); tcp_recv(pcb, nullptr); tcp_close(pcb); delete c; return ERR_OK;
  }
  std::vector<uint8_t> d(p->tot_len); pbuf_copy_partial(p, d.data(), p->tot_len, 0);
  u16_t len = p->tot_len; pbuf_free(p); tcp_recved(pcb, len);
  if (c->port == 7) { tcp_write(pcb, d.data(), len, TCP_WRITE_FLAG_COPY); tcp_output(pcb); }
  else if (c->port == 19) { c->count += len; for (auto b : d) c->sum += b; }
  return ERR_OK;
}
static err_t OnAccept(void* a, tcp_pcb* pcb, err_t) {
  uint16_t port = (uint16_t)(uintptr_t)a;
  auto* c = new Conn{port};
  tcp_arg(pcb, c); tcp_recv(pcb, OnRecv); tcp_sent(pcb, OnSent); tcp_nagle_disable(pcb);
  if (port == 9) SourcePump(pcb, c);
  return ERR_OK;
}
static void Listen(uint16_t port) {
  tcp_pcb* l = tcp_new(); tcp_bind(l, IP_ANY_TYPE, port); l = tcp_listen(l);
  tcp_arg(l, (void*)(uintptr_t)port); tcp_accept(l, OnAccept);
}

int main() {
  lwip_init();
  static netif nif; ip4_addr_t ip, mask, gw;
  IP4_ADDR(&ip, 10, 0, 0, 2); IP4_ADDR(&mask, 255, 255, 255, 255); ip4_addr_set_zero(&gw);
  netif_add(&nif, &ip, &mask, &gw, nullptr, NetifInit, ip_input);
  netif_set_default(&nif); netif_set_up(&nif);
  Listen(7); Listen(9); Listen(19);
  std::vector<uint8_t> in; uint8_t tmp[65536];
  for (;;) {
    pollfd pfd{0, POLLIN, 0};
    u32_t ms = sys_timeouts_sleeptime(); if (ms > 20) ms = 20;
    int r = poll(&pfd, 1, (int)ms);
    if (r > 0) {
      ssize_t n = read(0, tmp, sizeof(tmp));
      if (n <= 0) return 0;
      in.insert(in.end(), tmp, tmp + n);
      size_t off = 0;
      while (in.size() - off >= 2) {
        size_t len = ((size_t)in[off] << 8) | in[off + 1];
        if (in.size() - off - 2 < len) break;
        pbuf* p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
        if (p) { pbuf_take(p, &in[off + 2], (u16_t)len); if (nif.input(p, &nif) != ERR_OK) pbuf_free(p); }
        off += 2 + len;
      }
      in.erase(in.begin(), in.begin() + off);
    }
    sys_check_timeouts();
  }
}
