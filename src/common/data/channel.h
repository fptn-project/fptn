/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

#include <queue>

#include "common/network/ip_packet.h"

namespace fptn::common::data {

class Channel {
 public:
  explicit Channel(std::string name, std::size_t max_capacity = 1024 * 8)
      : name_(std::move(name)), max_capacity_(max_capacity) {}

  bool Push(network::IPPacketPtr pkt) noexcept {
    {
      const std::lock_guard<std::mutex> lock(mutex_);  // mutex

      if (queue_.size() <= max_capacity_) {
        if (is_full_) {
          is_full_ = false;
          SPDLOG_WARN("Channel '{}' is no longer full, dropped {} packets",
              name_, dropped_);
          dropped_ = 0;
        }
        queue_.push(std::move(pkt));
      } else {
        ++dropped_;
        if (!is_full_) {
          is_full_ = true;
          SPDLOG_WARN("Channel '{}' is full, dropping packets", name_);
        }
        return false;
      }
    }
    cv_.notify_one();
    return true;
  }

  bool PushBatch(network::BatchIPPacketPtr packets) {
    {
      const std::lock_guard<std::mutex> lock(mutex_);  // mutex

      if (queue_.size() >= max_capacity_) {
        dropped_ += packets.size();
        if (!is_full_) {
          is_full_ = true;
          SPDLOG_WARN("Channel '{}' is full, dropping packets", name_);
        }
        return false;
      }
      if (is_full_) {
        is_full_ = false;
        SPDLOG_WARN("Channel '{}' is no longer full, dropped {} packets", name_,
            dropped_);
        dropped_ = 0;
      }
      for (auto& packet : packets) {
        queue_.push(std::move(packet));
      }
    }
    cv_.notify_one();
    return true;
  }

  network::IPPacketPtr WaitForPacket(
      const std::chrono::milliseconds& duration) noexcept {
    std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (queue_.empty()) {
      cv_.wait_for(lock, duration, [this] { return !queue_.empty(); });
    }

    if (queue_.empty()) {
      return nullptr;
    }

    auto packet = std::move(queue_.front());
    queue_.pop();
    return packet;
  }

  network::BatchIPPacketPtr WaitForPackets(
      const std::chrono::milliseconds& duration,
      const std::size_t max_batch_size = 256) noexcept {
    network::BatchIPPacketPtr batch;

    std::unique_lock<std::mutex> lock(mutex_);  // mutex

    if (queue_.empty()) {
      cv_.wait_for(lock, duration, [this] { return !queue_.empty(); });
    }

    if (!queue_.empty()) {
      batch.reserve(std::min(max_batch_size, queue_.size()));
      while (!queue_.empty() && batch.size() < max_batch_size) {
        batch.push_back(std::move(queue_.front()));
        queue_.pop();
      }
    }
    return batch;
  }

 private:
  const std::string name_;
  const std::size_t max_capacity_;

  std::queue<network::IPPacketPtr> queue_;
  bool is_full_ = false;
  std::size_t dropped_ = 0;
  std::mutex mutex_;
  std::condition_variable cv_;
};

using ChannelPtr = std::unique_ptr<Channel>;

}  // namespace fptn::common::data
