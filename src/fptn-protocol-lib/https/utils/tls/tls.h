/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <openssl/ssl.h>  // NOLINT(build/include_order)

namespace fptn::protocol::https::utils {

std::string GetSHA1Hash(std::uint32_t number);
std::string GenerateFptnKey(std::uint32_t timestamp);

// Keyed marker: HMAC-SHA256(secret, be32(timestamp))[0:kFptnKeyLength].
// `secret` is the deployment-wide shared session key S, distributed to clients
// in the connection token and configured on the server. Unlike the legacy
// GenerateFptnKey (which is only SHA1(time) and therefore computable by anyone,
// incl. a censor), a keyed marker cannot be produced or recognised without S.
std::string GenerateFptnKeyKeyed(
    std::uint32_t timestamp, const std::string& secret);

// Client-side marker setters. When `secret` is empty they fall back to the
// legacy (unkeyed, time-only) marker for backward compatibility.
bool SetDecoyHandshakeSessionID(SSL* ssl, const std::string& secret = "");

// Server-side validators. `secrets` = the configured shared session key(s) S;
// more than one may be supplied so a new key can be rolled out before the old
// one is retired (rotation). accept_legacy=true keeps accepting old unkeyed
// clients during the migration window; set to false once all clients are
// upgraded to close the time-based fingerprint.
// DEPRECATED
bool IsDecoyHandshakeSessionID(const std::uint8_t* session,
    std::size_t session_len,
    const std::vector<std::string>& secrets = {},
    bool accept_legacy = true);

bool IsDecoyHandshakeSessionID2(const std::uint8_t* session,
    std::size_t session_len,
    const std::vector<std::string>& secrets = {},
    bool accept_legacy = true);

bool SetHandshakeSessionID(SSL* ssl, const std::string& secret = "");

bool IsFptnClientSessionID(const std::uint8_t* session,
    std::size_t session_len,
    const std::vector<std::string>& secrets = {},
    bool accept_legacy = true);

bool SetHandshakeSni(SSL* ssl, const std::string& sni);

SSL_CTX* CreateNewSslCtx();

std::string ChromeCiphers();

std::string GetCertificateMD5Fingerprint(const X509* cert);

// `secret` (the shared session key S) keys the embedded session-id marker;
// empty keeps the legacy time-only marker.
std::vector<std::uint8_t> GenerateDecoyTlsHandshake(
    const std::string& sni, const std::string& secret = "");

// DEPRECATED
std::optional<std::array<std::uint8_t, 32>> GenerateDecoyTlsSessionId();

std::optional<std::array<std::uint8_t, 32>> GenerateDecoyTlsSessionId2(
    const std::string& secret = "");

// Callbacks
using CertificateVerificationCallback = std::function<bool(const std::string&)>;
void AttachCertificateVerificationCallback(
    SSL* ssl, const CertificateVerificationCallback& callback);

void AttachCertificateVerificationCallbackDelete(SSL* ssl);

}  // namespace fptn::protocol::https::utils
