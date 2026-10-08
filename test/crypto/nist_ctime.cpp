/**
 * Copyright (c) 2011-2026 libbitcoin developers
 *
 * This file is part of libbitcoin.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "../test.hpp"

BOOST_AUTO_TEST_SUITE(nist_ctime_tests)

// Under valgrind a secret is undefined, so a branch or memory address that
// depends on it is reported as an error, and each output is defined before it
// is compared to the same computation on the defined secret.

// datatracker.ietf.org/doc/html/rfc6979 (A.2.5, A.2.6)
const secp256r1::secret_t p256_secret = base16_array("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
const secp384r1::secret_t p384_secret = base16_array("6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5");
const hash_digest message = base16_hash("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf");

// p-256

BOOST_AUTO_TEST_CASE(nist_ctime__secp256r1_public_key__undefined_secret__expected)
{
    secp256r1::point_t expected{};
    BOOST_REQUIRE(secp256r1::public_key(expected, p256_secret));

    auto secret = p256_secret;
    classify(secret);
    secp256r1::point_t point{};
    auto result = secp256r1::public_key(point, secret);
    declassify(result);
    declassify(point);
    BOOST_REQUIRE(result);
    BOOST_REQUIRE_EQUAL(point, expected);
}

BOOST_AUTO_TEST_CASE(nist_ctime__secp256r1_sign__undefined_secret__expected)
{
    secp256r1::signature_t expected{};
    BOOST_REQUIRE(secp256r1::sign(expected, p256_secret, message));

    auto secret = p256_secret;
    classify(secret);
    secp256r1::signature_t signature{};
    auto result = secp256r1::sign(signature, secret, message);
    declassify(result);
    declassify(signature);
    BOOST_REQUIRE(result);
    BOOST_REQUIRE_EQUAL(signature, expected);
}

BOOST_AUTO_TEST_CASE(nist_ctime__secp256r1_agree__undefined_secret__expected)
{
    secp256r1::point_t point{};
    BOOST_REQUIRE(secp256r1::public_key(point, p256_secret));
    secp256r1::shared_t expected{};
    BOOST_REQUIRE(secp256r1::agree(expected, p256_secret, point));

    auto secret = p256_secret;
    classify(secret);
    secp256r1::shared_t shared{};
    auto result = secp256r1::agree(shared, secret, point);
    declassify(result);
    declassify(shared);
    BOOST_REQUIRE(result);
    BOOST_REQUIRE_EQUAL(shared, expected);
}

// p-384

BOOST_AUTO_TEST_CASE(nist_ctime__secp384r1_public_key__undefined_secret__expected)
{
    secp384r1::point_t expected{};
    BOOST_REQUIRE(secp384r1::public_key(expected, p384_secret));

    auto secret = p384_secret;
    classify(secret);
    secp384r1::point_t point{};
    auto result = secp384r1::public_key(point, secret);
    declassify(result);
    declassify(point);
    BOOST_REQUIRE(result);
    BOOST_REQUIRE_EQUAL(point, expected);
}

BOOST_AUTO_TEST_CASE(nist_ctime__secp384r1_sign__undefined_secret__expected)
{
    secp384r1::signature_t expected{};
    BOOST_REQUIRE(secp384r1::sign(expected, p384_secret, message));

    auto secret = p384_secret;
    classify(secret);
    secp384r1::signature_t signature{};
    auto result = secp384r1::sign(signature, secret, message);
    declassify(result);
    declassify(signature);
    BOOST_REQUIRE(result);
    BOOST_REQUIRE_EQUAL(signature, expected);
}

BOOST_AUTO_TEST_CASE(nist_ctime__secp384r1_agree__undefined_secret__expected)
{
    secp384r1::point_t point{};
    BOOST_REQUIRE(secp384r1::public_key(point, p384_secret));
    secp384r1::shared_t expected{};
    BOOST_REQUIRE(secp384r1::agree(expected, p384_secret, point));

    auto secret = p384_secret;
    classify(secret);
    secp384r1::shared_t shared{};
    auto result = secp384r1::agree(shared, secret, point);
    declassify(result);
    declassify(shared);
    BOOST_REQUIRE(result);
    BOOST_REQUIRE_EQUAL(shared, expected);
}

BOOST_AUTO_TEST_SUITE_END()
