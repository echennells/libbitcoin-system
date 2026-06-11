/**
 * Copyright (c) 2011-2026 libbitcoin developers (see AUTHORS)
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
#include "../../test.hpp"

using namespace boost;
using namespace bc::system::chain;

BOOST_AUTO_TEST_SUITE(output_tests)

BOOST_AUTO_TEST_CASE(output__json__conversions__expected)
{
    const std::string_view text
    {
        "{"
            R"("value":24,)"
            R"("script":"pick roll return")"
        "}"
    };

    const output instance
    {
        24,
        script
        {
            operations
            {
                { opcode::pick },
                { opcode::roll },
                { opcode::op_return }
            }
        }
    };

    const auto value = json::value_from(instance);

    BOOST_REQUIRE_EQUAL(json::serialize(value), text);
    BOOST_REQUIRE(json::parse(text) == value);

    BOOST_REQUIRE(json::value_from(instance) == value);
    BOOST_REQUIRE(json::value_to<output>(value) == instance);
}

// bitcoind output script rendering (type/address/asm). The helper builds an
// output from a script hex literal (templated so the literal forwards to
// base16_chunk, which only accepts a compile-time char array).
template <size_t Size>
static output to_output(uint64_t value, const char (&script_hex)[Size])
{
    return output{ value, script{ base16_chunk(script_hex), false } };
}

BOOST_AUTO_TEST_CASE(output__bitcoind__pay_key_hash__type_address_asm)
{
    const auto out = to_output(4075061499ull,
        "76a914536ffa992491508dca0354e52f32a3a7a679a53a88ac");
    const auto value = json::value_from(bitcoind(out));
    const auto& output_script = value.as_object().at("scriptPubKey").as_object();
    BOOST_REQUIRE_EQUAL(output_script.at("type").as_string(), "pubkeyhash");
    BOOST_REQUIRE_EQUAL(output_script.at("asm").as_string(),
        "OP_DUP OP_HASH160 536ffa992491508dca0354e52f32a3a7a679a53a"
        " OP_EQUALVERIFY OP_CHECKSIG");
    BOOST_REQUIRE_EQUAL(output_script.at("address").as_string(),
        "18cBEMRxXHqzWWCxZNtU91F5sbUNKhL5PX");
}

BOOST_AUTO_TEST_CASE(output__bitcoind__pay_script_hash__type_address)
{
    const auto out = to_output(100000ull,
        "a914748284390f9e263a4b766a75d0633c50426eb87587");
    const auto value = json::value_from(bitcoind(out));
    const auto& output_script = value.as_object().at("scriptPubKey").as_object();
    BOOST_REQUIRE_EQUAL(output_script.at("type").as_string(), "scripthash");
    BOOST_REQUIRE_EQUAL(output_script.at("asm").as_string(),
        "OP_HASH160 748284390f9e263a4b766a75d0633c50426eb875 OP_EQUAL");
    BOOST_REQUIRE_EQUAL(output_script.at("address").as_string(),
        "3CK4fEwbMP7heJarmU4eqA3sMbVJyEnU3V");
}

BOOST_AUTO_TEST_CASE(output__bitcoind__witness_key_hash__type_bech32_address)
{
    const auto out = to_output(100000ull,
        "0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const auto value = json::value_from(bitcoind(out));
    const auto& output_script = value.as_object().at("scriptPubKey").as_object();
    BOOST_REQUIRE_EQUAL(output_script.at("type").as_string(), "witness_v0_keyhash");

    // bitcoind renders OP_0 as '0' and the program as bare hex.
    BOOST_REQUIRE_EQUAL(output_script.at("asm").as_string(),
        "0 751e76e8199196d454941c45d1b3a323f1433bd6");
    BOOST_REQUIRE_EQUAL(output_script.at("address").as_string(),
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
}

BOOST_AUTO_TEST_CASE(output__bitcoind__taproot__type_bech32m_address)
{
    const auto out = to_output(100000ull,
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const auto value = json::value_from(bitcoind(out));
    const auto& output_script = value.as_object().at("scriptPubKey").as_object();
    BOOST_REQUIRE_EQUAL(output_script.at("type").as_string(), "witness_v1_taproot");
    BOOST_REQUIRE_EQUAL(output_script.at("asm").as_string(),
        "1 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

    // bech32m (bip350) for witness version 1.
    BOOST_REQUIRE_EQUAL(output_script.at("address").as_string(),
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0");
}

BOOST_AUTO_TEST_CASE(output__bitcoind__op_return__nulldata_no_address)
{
    const auto out = to_output(0ull, "6a04deadbeef");
    const auto value = json::value_from(bitcoind(out));
    const auto& output_script = value.as_object().at("scriptPubKey").as_object();
    BOOST_REQUIRE_EQUAL(output_script.at("type").as_string(), "nulldata");
    BOOST_REQUIRE_EQUAL(output_script.at("asm").as_string(), "OP_RETURN deadbeef");
    BOOST_REQUIRE(!output_script.contains("address"));
    BOOST_REQUIRE(!output_script.contains("addresses"));
}

BOOST_AUTO_TEST_CASE(output__bitcoind__multisig__type_no_address)
{
    // OP_1 <key> <key> OP_2 OP_CHECKMULTISIG.
    const auto out = to_output(100000ull,
        "5121"
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "21"
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        "52ae");
    const auto value = json::value_from(bitcoind(out));
    const auto& output_script = value.as_object().at("scriptPubKey").as_object();
    BOOST_REQUIRE_EQUAL(output_script.at("type").as_string(), "multisig");
    BOOST_REQUIRE(!output_script.contains("address"));
    BOOST_REQUIRE(!output_script.contains("addresses"));
}

// Address context (network selection) determines base58 versions and the
// bech32 prefix. The key-hash script/address pair is Fulcrum/electrs verified.
BOOST_AUTO_TEST_CASE(output__bitcoind__pay_key_hash_testnet3__testnet_address)
{
    const auto out = to_output(312500000ull,
        "76a914d427a9318bc60db2766f9b02b7bbd470b78fa7a488ac");
    const auto context = to_address_context(selection::testnet3);
    const auto value = json::value_from(bitcoind(out, context));
    const auto& output_script = value.as_object().at("scriptPubKey").as_object();
    BOOST_REQUIRE_EQUAL(output_script.at("type").as_string(), "pubkeyhash");
    BOOST_REQUIRE_EQUAL(output_script.at("address").as_string(),
        "mzrj4QmPhk98vc2yQw42uCsgwfBjVzPPLM");
}

BOOST_AUTO_TEST_CASE(output__bitcoind__witness_key_hash_regtest__bcrt_address)
{
    const auto out = to_output(100000ull,
        "0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const auto context = to_address_context(selection::regtest);
    const auto value = json::value_from(bitcoind(out, context));
    const auto& output_script = value.as_object().at("scriptPubKey").as_object();
    BOOST_REQUIRE_EQUAL(output_script.at("type").as_string(), "witness_v0_keyhash");
    BOOST_REQUIRE_EQUAL(output_script.at("address").as_string(),
        "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080");
}

BOOST_AUTO_TEST_CASE(output__bitcoind__taproot_testnet3__tb_address)
{
    const auto out = to_output(100000ull,
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const auto context = to_address_context(selection::testnet3);
    const auto value = json::value_from(bitcoind(out, context));
    const auto& output_script = value.as_object().at("scriptPubKey").as_object();
    BOOST_REQUIRE_EQUAL(output_script.at("type").as_string(), "witness_v1_taproot");
    BOOST_REQUIRE_EQUAL(output_script.at("address").as_string(),
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47zagq");
}

BOOST_AUTO_TEST_SUITE_END()
