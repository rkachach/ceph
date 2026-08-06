
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

#include "keyring.h"
#include "common/ceph_crypto.h"

#include <memory>
#include <sstream>

#if defined(__linux__)
extern "C" {
#include <unistd.h>
#include <keyutils.h>
}
#endif

namespace ceph {

std::unique_ptr<Keyring> Keyring::get_best() {
#if defined(__linux__)
  return std::make_unique<MemoryKeyring>();
#else
  return std::make_unique<UnsupportedKeyring>();
#endif
}

tl::expected<std::unique_ptr<KeyringSecret>, std::error_code>
UnsupportedKeyring::add(
    const std::string& key, const std::string& secret) noexcept {
  return tl::unexpected(std::error_code(ENOSYS, std::system_category()));
}

bool UnsupportedKeyring::supported(std::error_code* ec) noexcept {
  if (ec != nullptr) {
    *ec = {ENOSYS, std::system_category()};
  }
  return false;
}

[[nodiscard]] std::error_code UnsupportedKeyringSecret::read(
    std::string& out) const {
  return {ENOSYS, std::system_category()};
}

[[nodiscard]] std::error_code UnsupportedKeyringSecret::remove() const {
  return {ENOSYS, std::system_category()};
}

[[nodiscard]] bool UnsupportedKeyringSecret::initialized() const {
  return false;
}

[[nodiscard]] std::error_code UnsupportedKeyring::describe(
    int serial, std::string& out) const noexcept {
  return {ENOSYS, std::system_category()};
}

#if defined(__linux__)

MemoryKeyringSecret::MemoryKeyringSecret(key_serial_t serial, size_t len, MemoryKeyring* ring) noexcept
    : _ring(ring), _len(len), _serial(serial) {}

MemoryKeyringSecret::~MemoryKeyringSecret() noexcept {
  reset();
}

void MemoryKeyringEntry::reset() {
  if (_data) ::ceph::crypto::zeroize_for_security(_data, _len);
  free(_data);
  _data = nullptr;
  _len = -1;
}

MemoryKeyringEntry::~MemoryKeyringEntry() {
  reset();
}

MemoryKeyring::MemoryKeyring() noexcept {
  nextserial = 1;
}

MemoryKeyring::~MemoryKeyring() noexcept {
}

tl::expected<std::unique_ptr<KeyringSecret>, std::error_code> MemoryKeyring::add(
    const std::string& key, const std::string& secret) noexcept {
  std::unique_lock l(mutex);
  MemoryKeyringEntry *entry;
  auto k = _byname.find(key);
  if (k != _byname.end()) {
    entry = k->second;
    entry->reset();
  } else {
    entry = new MemoryKeyringEntry(this, key);
    entry->_serial = nextserial++;
    _byname.insert({entry->_keyname, entry});
    _byserial.insert({entry->_serial, entry});
  }
  // XXX someday, should try to use non-swappable ram here.
  entry->_data = (unsigned char *) malloc(entry->_len = secret.size());
  memcpy(entry->_data, secret.c_str(), entry->_len);
  return std::unique_ptr<KeyringSecret>(
      new MemoryKeyringSecret(entry->_serial, secret.size(), this));
}

bool MemoryKeyring::supported(std::error_code* ec) noexcept {
  return true;
}

//
// this is highly bogus; the LinuxKeyring code used keyctl_describe,
// and serial shouldn't even be in the base class.
//

[[nodiscard]] std::error_code MemoryKeyring::describe(int serial, std::string& out) const noexcept {
  std::unique_lock l(mutex);
  std::stringstream ss;
  auto k = _byserial.find(serial);
  if (k == _byserial.end()) {
    return {ENOKEY, std::generic_category()};
  }
  ss << "user;" << getuid() << ';' << getgid() << ";00000000;" << "desc";
  out = ss.str();
  return {};
}

void MemoryKeyringSecret::initialize_process_keyring() noexcept {
}

[[nodiscard]] std::error_code MemoryKeyringSecret::read(std::string& out) const {
  std::unique_lock l(_ring->mutex);
  out.clear();
  out.resize(_len);
  auto k = _ring->_byserial.find(_serial);
  if (k == _ring->_byserial.end()) {
    return {ENOKEY, std::generic_category()};
  }
  if (k->second->_len != _len) {
    return {EINVAL, std::generic_category()};
  }
  memcpy(out.data(), k->second->_data, k->second->_len);
  return {};
}

[[nodiscard]] std::error_code MemoryKeyringSecret::remove() const {
  std::unique_lock l(_ring->mutex);
  auto k = _ring->_byserial.find(_serial);
  if (k == _ring->_byserial.end()) {
    return {ENOKEY, std::system_category()};
  }
  auto *entry = k->second;
  _ring->_byname.erase(entry->_keyname);
  _ring->_byserial.erase(k);
  delete(entry);
  return {};
}

[[nodiscard]] std::error_code MemoryKeyringSecret::reset() {
  if (_serial == -1) {
    return {EINVAL, std::generic_category()};
  }
  if (const auto ret = remove(); ret) {
    return ret;
  }
  _serial = -1;
  _len = 0;
  return {};
}
[[nodiscard]] bool MemoryKeyringSecret::initialized() const {
  return _len > 0 && _serial != -1;
}

#endif

}  // namespace ceph
