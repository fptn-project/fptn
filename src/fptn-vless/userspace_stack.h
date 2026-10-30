#pragma once

/*
 * Userspace TCP/IP client stack (lwIP) that stands in for the OS TUN adapter.
 *
 *   TCP flow  --lwIP-->  IP packets  --Device::Read-->  libfptn  -->  FPTN server
 *   TCP flow  <--lwIP--  IP packets  <--Device::Write--  libfptn  <--  FPTN server
 *
 * Nothing here touches the Windows network configuration: no adapter, no
 * routes, no DNS changes.
 *
 * Threading: lwIP (NO_SYS) is single-threaded, so every lwIP call happens on
 * one private "stack thread". Public methods below are thread-safe and only
 * enqueue work for that thread. Callbacks in FlowCallbacks run ON the stack
 * thread and must not block; hand work off to your own executor.
 */

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <future>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

struct tcp_pcb;  // lwIP type, kept opaque

namespace fptn::vless {

using Bytes = std::vector<std::uint8_t>;

class UserspaceStack;
struct LwipGlue;

struct Target {
  bool is_ipv4 = false;
  std::uint32_t ipv4_be = 0;  // network byte order, valid if is_ipv4
  std::string host;           // valid if !is_ipv4 (resolved through the tunnel)
  std::uint16_t port = 0;
};

struct FlowCallbacks {
  // Connect result. After on_connected(false) the flow is dead.
  std::function<void(bool ok)> on_connected;
  // Payload from the remote side. The receive window only reopens once
  // `consumed` has been called (from any thread) -> natural backpressure.
  std::function<void(Bytes data, std::function<void()> consumed)> on_data;
  // Remote sent FIN. We can still write.
  std::function<void()> on_eof;
  // Connection reset / aborted / timed out after it was established.
  std::function<void()> on_error;
};

class TcpFlow : public std::enable_shared_from_this<TcpFlow> {
 public:
  explicit TcpFlow(UserspaceStack* stack) : stack_(stack) {}

  // At most ONE Write may be outstanding. `accepted` is invoked (on the stack
  // thread) once all of `data` has been taken into the lwIP send buffer.
  void Write(Bytes data, std::function<void()> accepted);
  // Send FIN once pending data is flushed.
  void ShutdownWrite();
  // abort=true sends RST, abort=false closes gracefully. No callbacks after.
  void Close(bool abort);

 private:
  friend class UserspaceStack;
  friend struct LwipGlue;
  void Pump();  // stack thread

  UserspaceStack* stack_;
  tcp_pcb* pcb_ = nullptr;
  FlowCallbacks cb_;
  Bytes pending_;
  std::size_t pending_off_ = 0;
  std::function<void()> accepted_;
  bool want_fin_ = false;
  bool fin_sent_ = false;
  bool connected_ = false;
};
using TcpFlowPtr = std::shared_ptr<TcpFlow>;

class UserspaceStack {
 public:
  struct Config {
    std::string ipv4 = "10.0.0.1";  // must equal the client's tun address
    std::string dns_ipv4;           // DNS server announced by the FPTN server
    int mtu = 1420;
  };

  static UserspaceStack& Instance();

  // lwIP keeps global state: Start() may be called once per process.
  bool Start(const Config& config);
  void Stop();
  bool IsRunning() const { return running_; }

  // Tunnel side. Thread-safe.
  void Input(const std::uint8_t* data, std::size_t size);
  // Blocks up to timeout_ms; returns packet size copied to buf, 0 if none.
  int TakeOutput(std::uint8_t* buf, std::size_t cap, int timeout_ms);

  // Application side. Thread-safe, asynchronous.
  TcpFlowPtr Connect(Target target, FlowCallbacks callbacks);

  void Post(std::function<void()> fn);

  // Called when the tunnel is replaced by one to ANOTHER server (the old
  // server knows nothing about our open connections): resets every
  // connection so VLESS clients reconnect at once instead of hanging, forgets
  // packets queued for the old tunnel and switches the DNS server.
  // Blocks until done (a few ms).
  void ResetForNewTunnel(const std::string& dns_ipv4);

  std::uint64_t DroppedIn() const { return dropped_in_; }
  std::uint64_t DroppedOut() const { return dropped_out_; }
  // Packets handed to the tunnel / received from it (for diagnostics).
  std::uint64_t PacketsOut() const { return out_packets_; }
  std::uint64_t PacketsIn() const { return in_packets_; }

 private:
  UserspaceStack() = default;
  ~UserspaceStack() { Stop(); }
  friend struct LwipGlue;
  friend class TcpFlow;

  void Run(Config config, std::shared_ptr<std::promise<bool>> ready);

  std::atomic<bool> running_{false};
  std::thread thread_;

  std::mutex mu_;
  std::condition_variable cv_;
  std::deque<std::function<void()>> tasks_;
  std::deque<Bytes> in_q_;

  std::mutex out_mu_;
  std::condition_variable out_cv_;
  std::deque<Bytes> out_q_;

  std::unordered_set<TcpFlowPtr> flows_;  // stack thread only
  std::atomic<std::uint64_t> dropped_in_{0};
  std::atomic<std::uint64_t> dropped_out_{0};
  std::atomic<std::uint64_t> out_packets_{0};
  std::atomic<std::uint64_t> in_packets_{0};
};

}  // namespace fptn::vless
