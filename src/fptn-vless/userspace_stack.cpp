#include "fptn-vless/userspace_stack.h"

#include <algorithm>
#include <chrono>
#include <future>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

extern "C" {
#include "lwip/dns.h"
#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
}

extern "C" u32_t sys_now(void) {
  static const auto start = std::chrono::steady_clock::now();
  return static_cast<u32_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - start)
          .count());
}

namespace fptn::vless {

namespace {
constexpr std::size_t kMaxQueuedPackets = 16384;
}

struct LwipGlue {
  struct DnsCtx {
    TcpFlowPtr flow;
    std::uint16_t port;
  };

  static err_t NetifInit(struct netif* nif) {
    nif->name[0] = 'f';
    nif->name[1] = 'p';
    nif->output = &IpOutput;
    nif->linkoutput = nullptr;
    nif->mtu = 1420;
    nif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
  }

  // lwIP -> tunnel
  static err_t IpOutput(
      struct netif* nif, struct pbuf* p, const ip4_addr_t* /*ipaddr*/) {
    auto* stack = static_cast<UserspaceStack*>(nif->state);
    Bytes pkt(p->tot_len);
    pbuf_copy_partial(p, pkt.data(), p->tot_len, 0);
    {
      const std::lock_guard<std::mutex> lock(stack->out_mu_);
      if (stack->out_q_.size() >= kMaxQueuedPackets) {
        ++stack->dropped_out_;
        return ERR_OK;
      }
      stack->out_q_.push_back(std::move(pkt));
    }
    stack->out_cv_.notify_one();
    return ERR_OK;
  }

  // tunnel -> lwIP
  static void Inject(struct netif* nif, const Bytes& data) {
    struct pbuf* p = pbuf_alloc(PBUF_RAW, static_cast<u16_t>(data.size()),
        PBUF_POOL);
    if (p == nullptr) {
      return;
    }
    if (pbuf_take(p, data.data(), static_cast<u16_t>(data.size())) != ERR_OK ||
        nif->input(p, nif) != ERR_OK) {
      pbuf_free(p);
    }
  }

  static void Fail(const TcpFlowPtr& flow) {
    flow->pcb_ = nullptr;
    auto cb = std::move(flow->cb_);
    flow->cb_ = {};
    flow->stack_->flows_.erase(flow);
    if (cb.on_connected) {
      cb.on_connected(false);
    }
  }

  static void BeginConnect(
      const TcpFlowPtr& flow, const ip_addr_t* addr, std::uint16_t port) {
    if (!flow->cb_.on_connected) {  // closed while resolving
      flow->stack_->flows_.erase(flow);
      return;
    }
    tcp_pcb* pcb = tcp_new();
    if (pcb == nullptr) {
      Fail(flow);
      return;
    }
    flow->pcb_ = pcb;
    tcp_arg(pcb, flow.get());
    tcp_recv(pcb, &OnRecv);
    tcp_sent(pcb, &OnSent);
    tcp_err(pcb, &OnErr);
    tcp_nagle_disable(pcb);
    if (tcp_connect(pcb, addr, port, &OnConnected) != ERR_OK) {
      tcp_arg(pcb, nullptr);
      tcp_err(pcb, nullptr);
      tcp_abort(pcb);
      Fail(flow);
    }
  }

  static void StartFlow(UserspaceStack& stack,
      const TcpFlowPtr& flow,
      const Target& target) {
    stack.flows_.insert(flow);
    ip_addr_t addr;
    if (target.is_ipv4) {
      ip_addr_set_ip4_u32(&addr, target.ipv4_be);
      BeginConnect(flow, &addr, target.port);
      return;
    }
    auto* ctx = new DnsCtx{flow, target.port};
    const err_t e = dns_gethostbyname(target.host.c_str(), &addr, &DnsFound, ctx);
    if (e == ERR_OK) {
      std::unique_ptr<DnsCtx> own(ctx);
      BeginConnect(flow, &addr, target.port);
    } else if (e != ERR_INPROGRESS) {
      std::unique_ptr<DnsCtx> own(ctx);
      Fail(flow);
    }
  }

  static void DnsFound(
      const char* /*name*/, const ip_addr_t* addr, void* arg) {
    std::unique_ptr<DnsCtx> ctx(static_cast<DnsCtx*>(arg));
    if (addr == nullptr) {
      Fail(ctx->flow);
      return;
    }
    BeginConnect(ctx->flow, addr, ctx->port);
  }

  static err_t OnConnected(void* arg, tcp_pcb* /*pcb*/, err_t err) {
    auto* f = static_cast<TcpFlow*>(arg);
    if (err != ERR_OK) {
      return err;
    }
    f->connected_ = true;
    if (f->cb_.on_connected) {
      f->cb_.on_connected(true);
    }
    f->Pump();
    return ERR_OK;
  }

  static err_t OnRecv(void* arg, tcp_pcb* /*pcb*/, struct pbuf* p, err_t err) {
    auto* f = static_cast<TcpFlow*>(arg);
    if (p == nullptr) {  // remote FIN
      if (f != nullptr && f->cb_.on_eof) {
        f->cb_.on_eof();
      }
      return ERR_OK;
    }
    if (err != ERR_OK || f == nullptr || !f->cb_.on_data) {
      pbuf_free(p);
      return ERR_OK;
    }
    const u16_t len = p->tot_len;
    Bytes data(len);
    pbuf_copy_partial(p, data.data(), len, 0);
    pbuf_free(p);

    std::weak_ptr<TcpFlow> weak = f->weak_from_this();
    UserspaceStack* stack = f->stack_;
    f->cb_.on_data(std::move(data), [weak, stack, len]() {
      stack->Post([weak, len]() {
        if (auto fl = weak.lock(); fl && fl->pcb_ != nullptr) {
          tcp_recved(fl->pcb_, len);
        }
      });
    });
    return ERR_OK;
  }

  static err_t OnSent(void* arg, tcp_pcb* /*pcb*/, u16_t /*len*/) {
    if (auto* f = static_cast<TcpFlow*>(arg)) {
      f->Pump();
    }
    return ERR_OK;
  }

  // The pcb has already been freed by lwIP when this runs.
  static void OnErr(void* arg, err_t /*err*/) {
    auto* f = static_cast<TcpFlow*>(arg);
    if (f == nullptr) {
      return;
    }
    const TcpFlowPtr self = f->shared_from_this();
    f->pcb_ = nullptr;
    auto cb = std::move(f->cb_);
    f->cb_ = {};
    f->accepted_ = nullptr;
    f->stack_->flows_.erase(self);
    if (!f->connected_) {
      if (cb.on_connected) {
        cb.on_connected(false);
      }
    } else if (cb.on_error) {
      cb.on_error();
    }
  }

  // Drops every flow at once; the tunnel they ran through is gone.
  static void AbortAll(UserspaceStack& stack) {
    const std::vector<TcpFlowPtr> flows(
        stack.flows_.begin(), stack.flows_.end());
    stack.flows_.clear();
    for (const auto& flow : flows) {
      auto cb = std::move(flow->cb_);
      flow->cb_ = {};
      flow->accepted_ = nullptr;
      if (flow->pcb_ != nullptr) {
        tcp_pcb* pcb = flow->pcb_;
        flow->pcb_ = nullptr;
        tcp_arg(pcb, nullptr);
        tcp_recv(pcb, nullptr);
        tcp_sent(pcb, nullptr);
        tcp_err(pcb, nullptr);
        tcp_abort(pcb);
      }
      if (flow->connected_) {
        if (cb.on_error) {
          cb.on_error();
        }
      } else if (cb.on_connected) {
        cb.on_connected(false);
      }
    }
    // Forget everything meant for the old tunnel, including the RST packets
    // that tcp_abort() has just generated.
    {
      const std::lock_guard<std::mutex> lock(stack.out_mu_);
      stack.out_q_.clear();
    }
    {
      const std::lock_guard<std::mutex> lock(stack.mu_);
      stack.in_q_.clear();
    }
  }

  static void CloseFlow(const TcpFlowPtr& flow, bool abort) {
    flow->cb_ = {};
    flow->accepted_ = nullptr;
    if (flow->pcb_ != nullptr) {
      tcp_pcb* pcb = flow->pcb_;
      flow->pcb_ = nullptr;
      tcp_arg(pcb, nullptr);
      tcp_recv(pcb, nullptr);
      tcp_sent(pcb, nullptr);
      tcp_err(pcb, nullptr);
      if (abort || tcp_close(pcb) != ERR_OK) {
        tcp_abort(pcb);
      }
    }
    flow->stack_->flows_.erase(flow);
  }
};

/* ------------------------------ TcpFlow ------------------------------ */

void TcpFlow::Write(Bytes data, std::function<void()> accepted) {
  stack_->Post([self = shared_from_this(), d = std::move(data),
                   a = std::move(accepted)]() mutable {
    if (self->pcb_ == nullptr) {
      return;
    }
    self->pending_ = std::move(d);
    self->pending_off_ = 0;
    self->accepted_ = std::move(a);
    self->Pump();
  });
}

void TcpFlow::ShutdownWrite() {
  stack_->Post([self = shared_from_this()]() {
    self->want_fin_ = true;
    self->Pump();
  });
}

void TcpFlow::Close(bool abort) {
  stack_->Post([self = shared_from_this(), abort]() {
    LwipGlue::CloseFlow(self, abort);
  });
}

void TcpFlow::Pump() {
  if (pcb_ == nullptr || !connected_) {
    return;
  }
  while (pending_off_ < pending_.size()) {
    const u16_t room = tcp_sndbuf(pcb_);
    if (room == 0) {
      break;
    }
    const std::size_t n = std::min<std::size_t>(room, pending_.size() - pending_off_);
    const err_t e = tcp_write(pcb_, pending_.data() + pending_off_,
        static_cast<u16_t>(n), TCP_WRITE_FLAG_COPY);
    if (e == ERR_MEM) {
      break;  // retry from OnSent
    }
    if (e != ERR_OK) {
      LwipGlue::CloseFlow(shared_from_this(), true);
      return;
    }
    pending_off_ += n;
  }
  tcp_output(pcb_);
  if (pending_off_ >= pending_.size()) {
    pending_.clear();
    pending_off_ = 0;
    if (accepted_) {
      auto done = std::move(accepted_);
      accepted_ = nullptr;
      done();
    }
    if (want_fin_ && !fin_sent_ && pcb_ != nullptr) {
      fin_sent_ = true;
      tcp_shutdown(pcb_, 0, 1);
    }
  }
}

/* --------------------------- UserspaceStack --------------------------- */

UserspaceStack& UserspaceStack::Instance() {
  static UserspaceStack instance;
  return instance;
}

bool UserspaceStack::Start(const Config& config) {
  if (running_.exchange(true)) {
    return false;
  }
  auto ready = std::make_shared<std::promise<bool>>();
  auto fut = ready->get_future();
  thread_ = std::thread(&UserspaceStack::Run, this, config, ready);
  if (!fut.get()) {
    running_ = false;
    if (thread_.joinable()) {
      thread_.join();
    }
    return false;
  }
  return true;
}

void UserspaceStack::Stop() {
  if (!running_.exchange(false)) {
    return;
  }
  cv_.notify_all();
  out_cv_.notify_all();
  if (thread_.joinable()) {
    thread_.join();
  }
}

void UserspaceStack::Post(std::function<void()> fn) {
  {
    const std::lock_guard<std::mutex> lock(mu_);
    tasks_.push_back(std::move(fn));
  }
  cv_.notify_one();
}

// Server 0 = the DNS the FPTN server announced, server 1 = a public resolver
// reached THROUGH the tunnel. lwIP alternates between them on retries, so a
// server DNS that does not answer costs one second instead of a failed page.
static void ApplyDnsServers(const std::string& primary) {
  ip_addr_t dns;
  if (!primary.empty()) {
    if (ip4addr_aton(primary.c_str(), ip_2_ip4(&dns))) {
      dns_setserver(0, &dns);
    } else {
      SPDLOG_WARN("userspace stack: bad DNS address '{}'", primary);
    }
  }
  const char* fallback = primary == "1.1.1.1" ? "8.8.8.8" : "1.1.1.1";
  if (ip4addr_aton(fallback, ip_2_ip4(&dns))) {
    dns_setserver(1, &dns);
  }
}

void UserspaceStack::ResetForNewTunnel(const std::string& dns_ipv4) {
  if (!running_) {
    return;
  }
  auto done = std::make_shared<std::promise<void>>();
  auto finished = done->get_future();
  Post([this, dns_ipv4, done]() {
    LwipGlue::AbortAll(*this);
    ApplyDnsServers(dns_ipv4);
    done->set_value();
  });
  finished.wait_for(std::chrono::seconds(3));
}

void UserspaceStack::Input(const std::uint8_t* data, std::size_t size) {
  if (data == nullptr || size == 0 || size > 0xFFFF) {
    return;
  }
  {
    const std::lock_guard<std::mutex> lock(mu_);
    if (in_q_.size() >= kMaxQueuedPackets) {
      ++dropped_in_;
      return;
    }
    in_q_.emplace_back(data, data + size);
    ++in_packets_;
  }
  cv_.notify_one();
}

int UserspaceStack::TakeOutput(
    std::uint8_t* buf, std::size_t cap, int timeout_ms) {
  std::unique_lock<std::mutex> lock(out_mu_);
  if (out_q_.empty()) {
    out_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
        [this]() { return !out_q_.empty() || !running_; });
  }
  if (out_q_.empty()) {
    return 0;
  }
  Bytes pkt = std::move(out_q_.front());
  out_q_.pop_front();
  lock.unlock();
  if (pkt.size() > cap) {
    ++dropped_out_;
    return 0;
  }
  std::copy(pkt.begin(), pkt.end(), buf);
  ++out_packets_;
  return static_cast<int>(pkt.size());
}

TcpFlowPtr UserspaceStack::Connect(Target target, FlowCallbacks callbacks) {
  auto flow = std::make_shared<TcpFlow>(this);
  flow->cb_ = std::move(callbacks);
  Post([this, flow, t = std::move(target)]() {
    LwipGlue::StartFlow(*this, flow, t);
  });
  return flow;
}

void UserspaceStack::Run(
    Config config, std::shared_ptr<std::promise<bool>> ready) {
  lwip_init();

  ip4_addr_t ip;
  ip4_addr_t mask;
  ip4_addr_t gw;
  if (!ip4addr_aton(config.ipv4.c_str(), &ip)) {
    SPDLOG_ERROR("userspace stack: bad IPv4 address '{}'", config.ipv4);
    ready->set_value(false);
    return;
  }
  IP4_ADDR(&mask, 255, 255, 255, 255);
  ip4_addr_set_zero(&gw);

  static struct netif nif;
  netif_add(&nif, &ip, &mask, &gw, this, &LwipGlue::NetifInit, &ip_input);
  nif.mtu = static_cast<u16_t>(config.mtu);
  netif_set_default(&nif);
  netif_set_up(&nif);
  netif_set_link_up(&nif);

  ApplyDnsServers(config.dns_ipv4);
  ready->set_value(true);

  while (running_) {
    std::deque<std::function<void()>> tasks;
    std::deque<Bytes> packets;
    {
      std::unique_lock<std::mutex> lock(mu_);
      if (tasks_.empty() && in_q_.empty()) {
        u32_t sleep_ms = sys_timeouts_sleeptime();
        if (sleep_ms == SYS_TIMEOUTS_SLEEPTIME_INFINITE || sleep_ms > 50) {
          sleep_ms = 50;
        }
        cv_.wait_for(lock, std::chrono::milliseconds(sleep_ms));
      }
      tasks.swap(tasks_);
      packets.swap(in_q_);
    }
    for (const auto& pkt : packets) {
      LwipGlue::Inject(&nif, pkt);
    }
    for (auto& task : tasks) {
      task();
    }
    sys_check_timeouts();
  }

  for (const auto& flow : flows_) {  // drop everything on shutdown
    if (flow->pcb_ != nullptr) {
      tcp_pcb* pcb = flow->pcb_;
      flow->pcb_ = nullptr;
      tcp_arg(pcb, nullptr);
      tcp_err(pcb, nullptr);
      tcp_abort(pcb);
    }
  }
  flows_.clear();
}

}  // namespace fptn::vless
