/*=============================================================================
Copyright (c) 2024-2026 Pavel Shpilev

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <queue>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/network/ip_packet.h"
#include "common/network/net_interface.h"

// ===== Minimal valid IP packet builders for testing =====

namespace {

// Minimal valid IPv4 header (20 bytes): src=10.0.0.1, dst=10.0.0.2
fptn::common::network::IPPacketData MakeMinimalIPv4Packet() {
  return {
      0x45,
      0x00,
      0x00,
      0x14,  // ver=4, IHL=5, total_len=20
      0x00,
      0x01,
      0x00,
      0x00,  // id=1, flags=0, frag=0
      0x40,
      0x00,
      0xf5,
      0xc2,  // TTL=64, proto=HOPOPT, checksum
      0x0a,
      0x00,
      0x00,
      0x01,  // src: 10.0.0.1
      0x0a,
      0x00,
      0x00,
      0x02,  // dst: 10.0.0.2
  };
}

// Minimal valid IPv6 header (40 bytes): src=fc00:1::1, dst=fc00:1::2
fptn::common::network::IPPacketData MakeMinimalIPv6Packet() {
  return {
      0x60,
      0x00,
      0x00,
      0x00,  // ver=6, traffic class, flow label
      0x00,
      0x00,
      0x3b,
      0x40,  // payload_len=0, next=NoNext(59), hop=64
      // src: fc00:1::1
      0xfc,
      0x00,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x01,
      // dst: fc00:1::2
      0xfc,
      0x00,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x02,
  };
}

}  // namespace

// ===== Mock TUN device with shared state for testing GenericTunInterface =====

namespace {

struct SharedMockState {
  std::mutex mutex;
  std::vector<fptn::common::network::IPPacketData> written_packets;
  std::queue<fptn::common::network::IPPacketData> read_queue;

  void RecordWrite(const void* data, int size) {
    std::scoped_lock lock(mutex);
    written_packets.emplace_back(static_cast<const std::uint8_t*>(data),
        static_cast<const std::uint8_t*>(data) + size);
  }

  int FeedRead(void* buffer, int max_size) {
    std::scoped_lock lock(mutex);
    if (read_queue.empty()) {
      return 0;
    }
    const auto& front = read_queue.front();
    const int sz = std::min(max_size, static_cast<int>(front.size()));
    std::memcpy(buffer, front.data(), sz);
    read_queue.pop();
    return sz;
  }

  void InjectPacket(fptn::common::network::IPPacketData data) {
    std::scoped_lock lock(mutex);
    read_queue.push(std::move(data));
  }

  void Clear() {
    std::scoped_lock lock(mutex);
    written_packets.clear();
    while (!read_queue.empty()) {
      read_queue.pop();
    }
  }
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::shared_ptr<SharedMockState> g_mock_state;

class MockTunDevice {
 public:
  bool Open(const std::string& name) {
    name_ = name;
    return true;
  }
  // cppcheck-suppress functionStatic
  void Close() {}  // NOLINT(readability-convert-member-functions-to-static)
  [[nodiscard]] const std::string& GetName() const { return name_; }
  // cppcheck-suppress functionStatic
  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  bool ConfigureIPv4(const std::string& /*addr*/, int /*mask*/) { return true; }
  // cppcheck-suppress functionStatic
  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  bool ConfigureIPv6(const std::string& /*addr*/, int /*mask*/) { return true; }
  // cppcheck-suppress functionStatic
  // NOLINTNEXTLINE(readability-convert-member-*)
  void SetNonBlocking(bool /*enabled*/) {}
  // cppcheck-suppress functionStatic
  // NOLINTNEXTLINE(readability-convert-member-*)
  void SetMTU(int /*mtu*/) {}
  // cppcheck-suppress functionStatic
  // NOLINTNEXTLINE(readability-convert-member-*)
  void BringUp() {}
  // cppcheck-suppress functionStatic
  // NOLINTNEXTLINE(readability-convert-member-*)
  void SetStopFlag(const std::atomic<bool>* /*running*/) {}

  // cppcheck-suppress functionStatic
  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  int Read(void* buffer, int size) {
    return g_mock_state->FeedRead(buffer, size);
  }

  // cppcheck-suppress functionStatic
  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  int Write(const void* data, int size) {
    g_mock_state->RecordWrite(data, size);
    return size;
  }

 private:
  std::string name_;
};

}  // namespace

namespace fptn::common::network {

template <typename TunDevice>
class GenericTunInterface;

}

using MockTunInterface =
    fptn::common::network::GenericTunInterface<MockTunDevice>;

namespace {

class GenericTunInterfaceTest : public ::testing::Test {
 protected:
  void SetUp() override { g_mock_state = std::make_shared<SharedMockState>(); }

  void TearDown() override {
    g_mock_state->Clear();
    g_mock_state.reset();
  }

  static MockTunInterface::Config MakeConfig() {
    MockTunInterface::Config config;
    config.name = "mock0";
    config.mtu_size = FPTN_DEFAULT_MTU_SIZE;
    config.using_rate_calculator = false;
    config.ipv4_addr = fptn::common::network::IPv4Address("10.0.0.1");
    config.ipv4_netmask = 24;
    config.ipv6_addr = fptn::common::network::IPv6Address("fc00:1::1");
    config.ipv6_netmask = 112;
    return config;
  }
};

}  // namespace

TEST_F(GenericTunInterfaceTest, StartAndStop) {
  MockTunInterface iface(MakeConfig());
  ASSERT_TRUE(iface.Start());
  EXPECT_EQ(iface.Name(), "mock0");
  EXPECT_TRUE(iface.Stop());
}

TEST_F(GenericTunInterfaceTest, SendIPv4Packet) {
  MockTunInterface iface(MakeConfig());
  ASSERT_TRUE(iface.Start());

  auto pkt_data = MakeMinimalIPv4Packet();
  auto packet = fptn::common::network::IPPacket::Parse(pkt_data);
  ASSERT_NE(packet, nullptr);

  EXPECT_TRUE(iface.Send(std::move(packet)));

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  auto written = g_mock_state->written_packets;
  ASSERT_EQ(written.size(), 1U);
  EXPECT_EQ(written[0].size(), pkt_data.size());
  EXPECT_EQ(written[0], pkt_data);

  iface.Stop();
}

TEST_F(GenericTunInterfaceTest, SendIPv6Packet) {
  MockTunInterface iface(MakeConfig());
  ASSERT_TRUE(iface.Start());

  auto pkt_data = MakeMinimalIPv6Packet();
  auto packet = fptn::common::network::IPPacket::Parse(pkt_data);
  ASSERT_NE(packet, nullptr);

  EXPECT_TRUE(iface.Send(std::move(packet)));

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  auto written = g_mock_state->written_packets;
  ASSERT_EQ(written.size(), 1U);
  EXPECT_EQ(written[0].size(), pkt_data.size());
  EXPECT_EQ(written[0], pkt_data);

  iface.Stop();
}

TEST_F(GenericTunInterfaceTest, ReceiveIPv4Packet) {
  MockTunInterface iface(MakeConfig());

  std::mutex callback_mutex;
  std::vector<fptn::common::network::IPPacketData> received;

  iface.SetRecvIPPacketCallback([&](fptn::common::network::IPPacketPtr packet) {
    if (packet) {
      std::scoped_lock lock(callback_mutex);

      const auto& data = packet->Data();
      received.emplace_back(data.data(), data.data() + data.size());
    }
  });

  ASSERT_TRUE(iface.Start());

  g_mock_state->InjectPacket(MakeMinimalIPv4Packet());

  for (int i = 0; i < 100; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    std::scoped_lock lock(callback_mutex);
    if (!received.empty()) {
      break;
    }
  }

  iface.Stop();

  std::scoped_lock lock(callback_mutex);
  ASSERT_FALSE(received.empty());
  ASSERT_EQ(received.size(), 1U);
  // cppcheck-suppress containerOutOfBounds
  EXPECT_EQ(received[0], MakeMinimalIPv4Packet());
}

TEST_F(GenericTunInterfaceTest, ReceiveIPv6Packet) {
  MockTunInterface iface(MakeConfig());

  std::mutex callback_mutex;
  std::vector<fptn::common::network::IPPacketData> received;

  iface.SetRecvIPPacketCallback([&](fptn::common::network::IPPacketPtr packet) {
    if (packet) {
      std::scoped_lock lock(callback_mutex);

      const auto& data = packet->Data();
      received.emplace_back(data.data(), data.data() + data.size());
    }
  });

  ASSERT_TRUE(iface.Start());

  g_mock_state->InjectPacket(MakeMinimalIPv6Packet());

  for (int i = 0; i < 100; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    std::scoped_lock lock(callback_mutex);
    if (!received.empty()) {
      break;
    }
  }

  iface.Stop();

  std::scoped_lock lock(callback_mutex);
  // cppcheck-suppress
  ASSERT_FALSE(received.empty());
  ASSERT_EQ(received.size(), 1U);
  // cppcheck-suppress containerOutOfBounds
  EXPECT_EQ(received[0], MakeMinimalIPv6Packet());
}

TEST_F(GenericTunInterfaceTest, SendMultipleMixedPackets) {
  MockTunInterface iface(MakeConfig());
  ASSERT_TRUE(iface.Start());

  auto ipv4_data = MakeMinimalIPv4Packet();
  auto ipv6_data = MakeMinimalIPv6Packet();

  auto pkt4 = fptn::common::network::IPPacket::Parse(ipv4_data);
  auto pkt6 = fptn::common::network::IPPacket::Parse(ipv6_data);
  ASSERT_NE(pkt4, nullptr);
  ASSERT_NE(pkt6, nullptr);

  EXPECT_TRUE(iface.Send(std::move(pkt4)));
  EXPECT_TRUE(iface.Send(std::move(pkt6)));

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  auto written = g_mock_state->written_packets;
  ASSERT_EQ(written.size(), 2U);
  EXPECT_EQ(written[0], ipv4_data);
  EXPECT_EQ(written[1], ipv6_data);

  iface.Stop();
}

TEST_F(GenericTunInterfaceTest, DeviceNameUpdatedAfterStart) {
  MockTunInterface iface(MakeConfig());
  EXPECT_EQ(iface.Name(), "mock0");
  ASSERT_TRUE(iface.Start());
  EXPECT_EQ(iface.Name(), "mock0");
  iface.Stop();
}

#ifdef __APPLE__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/network/tun/darwin_tun_device.h"

class DarwinAfHeaderTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM, 0, fds_), 0);
  }

  void TearDown() override {
    close(fds_[0]);
    close(fds_[1]);
  }

  int fds_[2] = {-1, -1};
};

TEST_F(DarwinAfHeaderTest, WriteIPv4PrependsCorrectAfHeader) {
  fptn::common::network::DarwinTunDevice device;
  ASSERT_TRUE(device.OpenWithFd(fds_[0], "test0"));

  auto ipv4_pkt = MakeMinimalIPv4Packet();
  const int written = device.Write(ipv4_pkt.data(), ipv4_pkt.size());
  EXPECT_EQ(written, static_cast<int>(ipv4_pkt.size()));

  std::uint8_t raw_buf[256] = {};
  const ssize_t n = recv(fds_[1], raw_buf, sizeof(raw_buf), 0);
  ASSERT_GT(n, 4);

  std::uint32_t af_header = 0;
  std::memcpy(&af_header, raw_buf, 4);
  EXPECT_EQ(af_header, htonl(AF_INET));

  const auto payload_size = static_cast<std::size_t>(n) - 4;
  EXPECT_EQ(payload_size, ipv4_pkt.size());
  EXPECT_EQ(std::memcmp(raw_buf + 4, ipv4_pkt.data(), ipv4_pkt.size()), 0);

  device.OpenWithFd(-1, "");
}

TEST_F(DarwinAfHeaderTest, WriteIPv6PrependsCorrectAfHeader) {
  fptn::common::network::DarwinTunDevice device;
  ASSERT_TRUE(device.OpenWithFd(fds_[0], "test0"));

  auto ipv6_pkt = MakeMinimalIPv6Packet();
  const int written = device.Write(ipv6_pkt.data(), ipv6_pkt.size());
  EXPECT_EQ(written, static_cast<int>(ipv6_pkt.size()));

  std::uint8_t raw_buf[256] = {};
  const ssize_t n = recv(fds_[1], raw_buf, sizeof(raw_buf), 0);
  ASSERT_GT(n, 4);

  std::uint32_t af_header = 0;
  std::memcpy(&af_header, raw_buf, 4);
  EXPECT_EQ(af_header, htonl(AF_INET6));

  const auto payload_size = static_cast<std::size_t>(n) - 4;
  EXPECT_EQ(payload_size, ipv6_pkt.size());
  EXPECT_EQ(std::memcmp(raw_buf + 4, ipv6_pkt.data(), ipv6_pkt.size()), 0);

  device.OpenWithFd(-1, "");
}

TEST_F(DarwinAfHeaderTest, ReadStripsAfHeaderIPv4) {
  fptn::common::network::DarwinTunDevice device;
  ASSERT_TRUE(device.OpenWithFd(fds_[0], "test0"));
  device.SetNonBlocking(true);

  auto ipv4_pkt = MakeMinimalIPv4Packet();

  std::vector<std::uint8_t> raw(4 + ipv4_pkt.size());
  std::uint32_t af = htonl(AF_INET);
  std::memcpy(raw.data(), &af, 4);
  std::memcpy(raw.data() + 4, ipv4_pkt.data(), ipv4_pkt.size());
  ASSERT_EQ(send(fds_[1], raw.data(), raw.size(), 0),
      static_cast<ssize_t>(raw.size()));

  std::uint8_t read_buf[256] = {};
  const int bytes_read = device.Read(read_buf, sizeof(read_buf));
  EXPECT_EQ(bytes_read, static_cast<int>(ipv4_pkt.size()));
  EXPECT_EQ(std::memcmp(read_buf, ipv4_pkt.data(), ipv4_pkt.size()), 0);

  device.OpenWithFd(-1, "");
}

TEST_F(DarwinAfHeaderTest, ReadStripsAfHeaderIPv6) {
  fptn::common::network::DarwinTunDevice device;
  ASSERT_TRUE(device.OpenWithFd(fds_[0], "test0"));
  device.SetNonBlocking(true);

  auto ipv6_pkt = MakeMinimalIPv6Packet();

  std::vector<std::uint8_t> raw(4 + ipv6_pkt.size());
  std::uint32_t af = htonl(AF_INET6);
  std::memcpy(raw.data(), &af, 4);
  std::memcpy(raw.data() + 4, ipv6_pkt.data(), ipv6_pkt.size());
  ASSERT_EQ(send(fds_[1], raw.data(), raw.size(), 0),
      static_cast<ssize_t>(raw.size()));

  std::uint8_t read_buf[256] = {};
  const int bytes_read = device.Read(read_buf, sizeof(read_buf));
  EXPECT_EQ(bytes_read, static_cast<int>(ipv6_pkt.size()));
  EXPECT_EQ(std::memcmp(read_buf, ipv6_pkt.data(), ipv6_pkt.size()), 0);

  device.OpenWithFd(-1, "");
}

TEST_F(DarwinAfHeaderTest, RoundTripIPv6Preserved) {
  fptn::common::network::DarwinTunDevice writer;
  fptn::common::network::DarwinTunDevice reader;
  ASSERT_TRUE(writer.OpenWithFd(fds_[0], "writer0"));
  ASSERT_TRUE(reader.OpenWithFd(fds_[1], "reader0"));
  reader.SetNonBlocking(true);

  auto original = MakeMinimalIPv6Packet();
  const int written = writer.Write(original.data(), original.size());
  EXPECT_EQ(written, static_cast<int>(original.size()));

  std::uint8_t read_buf[256] = {};
  const int bytes_read = reader.Read(read_buf, sizeof(read_buf));
  ASSERT_EQ(bytes_read, static_cast<int>(original.size()));

  fptn::common::network::IPPacketData result(read_buf, read_buf + bytes_read);
  EXPECT_EQ(result, original);

  writer.OpenWithFd(-1, "");
  reader.OpenWithFd(-1, "");
}

#endif  // __APPLE__
