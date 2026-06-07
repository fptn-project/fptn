/*=============================================================================
Copyright (c) 2024-2025 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <memory>
#include <utility>

#include <gtest/gtest.h>  // NOLINT(build/include_order)

#include "common/data/channel.h"
#include "common/network/ip_packet.h"

TEST(ChannelTest, PushAndWaitForPacket) {
  fptn::common::data::Channel channel("test_name", 10);

  fptn::common::network::IPPacketData packet_data;
  const char* test_data = "packet-data";
  packet_data.insert(
      packet_data.end(), test_data, test_data + strlen(test_data));

  auto packet =
      std::make_unique<fptn::common::network::IPPacket>(std::move(packet_data),
          static_cast<fptn::ClientID>(1));  // Cast to proper ClientID type

  channel.Push(std::move(packet));
  EXPECT_NE(channel.WaitForPacket(std::chrono::milliseconds(100)), nullptr);
}

TEST(ChannelTest, WaitForPacketTimeout) {
  fptn::common::data::Channel channel("test_name", 10);
  EXPECT_EQ(channel.WaitForPacket(std::chrono::milliseconds(100)), nullptr);
}
