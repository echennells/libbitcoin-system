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

BOOST_AUTO_TEST_SUITE(script_tests)

BOOST_AUTO_TEST_CASE(script__json__conversions__expected)
{
    const std::string_view text
    {
        R"("pick roll return")"
    };

    const script instance
    {
        operations
        {
            { opcode::pick },
            { opcode::roll },
            { opcode::op_return }
        }
    };

    const auto value = json::value_from(instance);

    BOOST_REQUIRE_EQUAL(json::serialize(value), text);
    BOOST_REQUIRE(json::parse(text) == value);

    BOOST_REQUIRE(json::value_from(instance) == value);
    BOOST_REQUIRE(json::value_to<script>(value) == instance);
}

// The bitcoind tag emits uppercase OP_ asm tokens with bare push-data hex
// (native emits lowercase mnemonics and bracketed pushes).
BOOST_AUTO_TEST_CASE(script__bitcoind__pay_key_hash__expected_asm)
{
    const script instance{
        base16_chunk("76a914536ffa992491508dca0354e52f32a3a7a679a53a88ac"),
        false };
    const auto value = json::value_from(bitcoind(instance));
    const auto& object = value.as_object();
    BOOST_REQUIRE_EQUAL(object.at("asm").as_string(),
        "OP_DUP OP_HASH160 536ffa992491508dca0354e52f32a3a7a679a53a"
        " OP_EQUALVERIFY OP_CHECKSIG");
    BOOST_REQUIRE_EQUAL(object.at("hex").as_string(),
        "76a914536ffa992491508dca0354e52f32a3a7a679a53a88ac");
}

// OP_0 renders as '0' (native 'zero'); OP_RETURN as 'OP_RETURN' (native
// 'return'); push data as bare hex.
BOOST_AUTO_TEST_CASE(script__bitcoind__small_opcodes__expected_tokens)
{
    const script witness_key_hash{
        base16_chunk("0014751e76e8199196d454941c45d1b3a323f1433bd6"), false };
    const auto witness_value = json::value_from(bitcoind(witness_key_hash));
    BOOST_REQUIRE_EQUAL(witness_value.as_object().at("asm").as_string(),
        "0 751e76e8199196d454941c45d1b3a323f1433bd6");

    const script null_data{ base16_chunk("6a04deadbeef"), false };
    const auto null_data_value = json::value_from(bitcoind(null_data));
    BOOST_REQUIRE_EQUAL(null_data_value.as_object().at("asm").as_string(),
        "OP_RETURN deadbeef");
}

BOOST_AUTO_TEST_SUITE_END()
