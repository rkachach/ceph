// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2025 Clyso GmbH
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

// This implements hygienic storage for secrets, for use by KMSCache.

#pragma once

#include <memory>
#include <map>
#include <mutex>
#include <ostream>
#include <shared_mutex>
#include <system_error>
#include <utility>

#include "fmt/ostream.h"
#include "include/expected.hpp"

namespace ceph {
class KeyringSecret {
 public:
  virtual ~KeyringSecret() noexcept = default;
  [[nodiscard]] virtual std::error_code read(std::string& out) const = 0;
  [[nodiscard]] virtual std::error_code remove() const = 0;
  [[nodiscard]] virtual bool initialized() const = 0;
  friend std::ostream& operator<<(
      std::ostream& os, const KeyringSecret& secret) {
    return os;
  }
};

class Keyring {
 public:
  virtual ~Keyring() noexcept = default;
  virtual tl::expected<std::unique_ptr<KeyringSecret>, std::error_code> add(
      const std::string& key, const std::string& secret) noexcept = 0;
  virtual bool supported(std::error_code* ec) noexcept = 0;
// describe is only for test logic, serial parm here is bogus
  [[nodiscard]] virtual std::error_code describe(int, std::string& out) const noexcept = 0;
  [[nodiscard]] virtual std::string_view name() const noexcept = 0;

  static std::unique_ptr<Keyring> get_best();
};

class UnsupportedKeyringSecret : public KeyringSecret {
 public:
  ~UnsupportedKeyringSecret() noexcept override = default;
  [[nodiscard]] std::error_code read(std::string& out) const override;
  [[nodiscard]] std::error_code remove() const override;
  [[nodiscard]] bool initialized() const override;
  friend std::ostream& operator<<(
      std::ostream& os, const UnsupportedKeyringSecret& secret) {
    os << "UnsupportedKeyringSecret{}";
    return os;
  }
};

class UnsupportedKeyring : public Keyring {
 public:
  ~UnsupportedKeyring() noexcept override = default;
  tl::expected<std::unique_ptr<KeyringSecret>, std::error_code> add(
      const std::string& key, const std::string& secret) noexcept override;
  bool supported(std::error_code* ec) noexcept override;
  [[nodiscard]] std::error_code describe(int, std::string& out) const noexcept override;
  [[nodiscard]] std::string_view name() const noexcept override {
    return "Unsupported";
  }
};

/// RAII style wrapper around a secret stored in the Memory Key
/// Retention Service.
/// Based on an earlier version that used keyctl functions.
/// this version is all in-core.

class MemoryKeyring;

class MemoryKeyringSecret : public KeyringSecret {
  MemoryKeyring *_ring;
  size_t _len;
  int _serial;

  explicit MemoryKeyringSecret(int serial, size_t len, MemoryKeyring*) noexcept;

 public:
  MemoryKeyringSecret() = delete;
  MemoryKeyringSecret(const MemoryKeyringSecret&) = delete;
  MemoryKeyringSecret& operator=(const MemoryKeyringSecret&) = delete;
  MemoryKeyringSecret(MemoryKeyringSecret&& other) noexcept
      : _ring(std::exchange(other._ring, nullptr)),
        _len(std::exchange(other._len, 0)),
        _serial(std::exchange(other._serial, -1)) {};

  MemoryKeyringSecret& operator=(MemoryKeyringSecret&& other) noexcept {
    if (this != &other) {
      if (this->initialized()) {
        this->reset();
      }
      _len = std::exchange(other._len, 0);
      _serial = std::exchange(other._serial, -1);
    }
    return *this;
  };

  ~MemoryKeyringSecret() noexcept override;

  // Initialize the process keyring. Do this before starting any
  // threads that want to share possession of keys in the process
  // keyring
  static void initialize_process_keyring() noexcept;

  [[nodiscard]] std::error_code read(std::string& out) const override;
  [[nodiscard]] std::error_code remove() const override;
  [[nodiscard]] bool initialized() const override;

 private:
  std::error_code reset();

  friend std::ostream& operator<<(
      std::ostream& os, const MemoryKeyringSecret& secret) {
    if (secret._serial == -1) {
      return os << "MemoryKeyringSecret{}";
    }
    return os << "MemoryKeyringSecret{" << secret._serial << "}";
  }
  friend class MemoryKeyringTest_LifecycleMoveAssignResetsDestination_Test;
  friend class MemoryKeyringTest_ResetClearsState_Test;
  friend class MemoryKeyring;
};

struct MemoryKeyringEntry {
  MemoryKeyring *_ring;
  std::string _keyname;
  unsigned char *_data;
  int _serial;
  int _len;
  MemoryKeyringEntry(MemoryKeyring *ring, std::string key)
   : _ring(ring), _keyname(key) {
  }
  ~MemoryKeyringEntry() noexcept;
  void reset();
};

class MemoryKeyring : public Keyring {
 private:
  mutable std::shared_mutex mutex;
  int nextserial;
  std::map <std::string, MemoryKeyringEntry *> _byname;
  std::map <int, MemoryKeyringEntry *> _byserial;
 public:
  // Add a secret to the in process keystore. Beware: calling this
  // with with an existing key _updates_ the value and causes multiple
  // instances to refer to the same key.
  tl::expected<std::unique_ptr<KeyringSecret>, std::error_code> add(
      const std::string& key, const std::string& secret) noexcept override;
  bool supported(std::error_code* ec) noexcept override;
  [[nodiscard]] std::error_code describe(int, std::string& out) const noexcept override;
  [[nodiscard]] std::string_view name() const noexcept override {
    return "Key Cache Retention Service";
  };

  MemoryKeyring() noexcept;
  ~MemoryKeyring() noexcept override;
  friend MemoryKeyringSecret;
  friend MemoryKeyringEntry;
};
}  // namespace ceph

#if FMT_VERSION >= 90000
template <typename T>
struct fmt::formatter<
    T, std::enable_if_t<std::is_base_of_v<ceph::KeyringSecret, T>, char>>
    : fmt::ostream_formatter {};
#endif
