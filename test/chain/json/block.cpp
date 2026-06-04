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
#include "../../mocks/blocks.hpp"

using namespace boost;
using namespace bc::system::chain;

BOOST_AUTO_TEST_SUITE(block_tests)

BOOST_AUTO_TEST_CASE(block__json__native__expected)
{
    const std::string_view text
    {
        "{"
            R"("header":)"
            "{"
                R"("hash":"d5b1048b2dcb443dd79a15e54de994fa18620d1d99250f2a4123660c68dea664",)"
                R"("version":42,)"
                R"("previous":"0000000000000000000000000000000000000000000000000000000000000000",)"
                R"("merkle_root":"0000000000000000000000000000000000000000000000000000000000000001",)"
                R"("timestamp":43,)"
                R"("bits":44,)"
                R"("nonce":45)"
            "},"
            R"("transactions":)"
            "["
                "{"
                    R"("hash":"6d74f0162f9c7a3be99cb60cca0c658f3e19fb3462f4c9731d5a0b7495183335",)"
                    R"("version":42,)"
                    R"("inputs":)"
                    "["
                        "{"
                            R"("point":)"
                            "{"
                                R"("hash":"0000000000000000000000000000000000000000000000000000000000000000",)"
                                R"("index":24)"
                            "},"
                            R"("script":"return pick",)"
                            R"("witness":"[242424]",)"
                            R"("sequence":42)"
                        "},"
                        "{"
                            R"("point":)"
                            "{"
                                R"("hash":"0000000000000000000000000000000000000000000000000000000000000001",)"
                                R"("index":42)"
                            "},"
                            R"("script":"return roll",)"
                            R"("witness":"[424242]",)"
                            R"("sequence":24)"
                        "}"
                    "],"
                    R"("outputs":)"
                    "["
                        "{"
                            R"("value":24,)"
                            R"("script":"pick")"
                        "},"
                        "{"
                            R"("value":42,)"
                            R"("script":"roll")"
                        "}"
                    "],"
                    R"("locktime":24)"
                "}"
            "]"
        "}"
    };

    const auto& instance = test::mock_block_json;
    const auto value = json::value_from(instance);

    BOOST_REQUIRE_EQUAL(json::serialize(value), text);
    BOOST_REQUIRE(json::parse(text) == value);

    BOOST_REQUIRE(json::value_from(instance) == value);
    BOOST_REQUIRE(json::value_to<block>(value) == instance);
}

BOOST_AUTO_TEST_CASE(block__json__bitcoind__expected)
{
    const std::string_view text
    {
        "{"
            R"("hash":"d5b1048b2dcb443dd79a15e54de994fa18620d1d99250f2a4123660c68dea664",)"
            R"("size":209,)"
            R"("strippedsize":197,)"
            R"("weight":800,)"
            R"("version":42,)"
            R"("versionHex":"0000002a",)"
            R"("merkleroot":"0000000000000000000000000000000000000000000000000000000000000001",)"
            R"("time":43,)"
            R"("nonce":45,)"
            R"("bits":"0000002c",)"
            R"("difficulty":1.0279680609929991E73,)"
            R"("nTx":1)"
        "}"
    };

    const auto& instance = test::mock_block_json;
    const auto value = json::value_from(bitcoind(instance));
    BOOST_REQUIRE_EQUAL(json::serialize(value), text);
}

BOOST_AUTO_TEST_CASE(block__json__bitcoind_hashed__expected)
{
    const std::string_view text
    {
        "{"
            R"("hash":"d5b1048b2dcb443dd79a15e54de994fa18620d1d99250f2a4123660c68dea664",)"
            R"("size":209,)"
            R"("strippedsize":197,)"
            R"("weight":800,)"
            R"("version":42,)"
            R"("versionHex":"0000002a",)"
            R"("merkleroot":"0000000000000000000000000000000000000000000000000000000000000001",)"
            R"("time":43,)"
            R"("nonce":45,)"
            R"("bits":"0000002c",)"
            R"("difficulty":1.0279680609929991E73,)"
            R"("nTx":1,)"
            R"("tx":["6d74f0162f9c7a3be99cb60cca0c658f3e19fb3462f4c9731d5a0b7495183335"])"
        "}"
    };

    const auto& instance = test::mock_block_json;
    const auto value = json::value_from(bitcoind_hashed(instance));
    BOOST_REQUIRE_EQUAL(json::serialize(value), text);
}

BOOST_AUTO_TEST_CASE(block__json__bitcoind_embedded__expected)
{
    const std::string_view text
    {
        "{"
            R"("hash":"d5b1048b2dcb443dd79a15e54de994fa18620d1d99250f2a4123660c68dea664",)"
            R"("size":209,)"
            R"("strippedsize":197,)"
            R"("weight":800,)"
            R"("version":42,)"
            R"("versionHex":"0000002a",)"
            R"("merkleroot":"0000000000000000000000000000000000000000000000000000000000000001",)"
            R"("time":43,)"
            R"("nonce":45,)"
            R"("bits":"0000002c",)"
            R"("difficulty":1.0279680609929991E73,)"
            R"("nTx":1,)"
            R"("tx":["2a000000000102000000000000000000000000000000000000000000000000000000000000000018000000026a792a00000001000000000000000000000000000000000000000000000000000000000000002a000000026a7a1800000002180000000000000001792a00000000000000017a0103242424010342424218000000"])"
        "}"
    };

    const auto& instance = test::mock_block_json;
    const auto value = json::value_from(bitcoind_embedded(instance));
    BOOST_REQUIRE_EQUAL(json::serialize(value), text);
}

BOOST_AUTO_TEST_CASE(block__json__bitcoind_verbose__expected)
{
    const std::string_view text
    {
        // Core-parity (#778): tx size is total (128), scriptSig/scriptPubKey
        // asm is Core-formatted, nonstandard outputs emit no address.
        R"json({"hash":"d5b1048b2dcb443dd79a15e54de994fa18620d1d99250f2a4123660c68dea664","size":209,"strippedsize":197,"weight":800,"version":42,"versionHex":"0000002a","merkleroot":"0000000000000000000000000000000000000000000000000000000000000001","time":43,"nonce":45,"bits":"0000002c","difficulty":1.0279680609929991E73,"nTx":1,"tx":[{"hex":"2a000000000102000000000000000000000000000000000000000000000000000000000000000018000000026a792a00000001000000000000000000000000000000000000000000000000000000000000002a000000026a7a1800000002180000000000000001792a00000000000000017a0103242424010342424218000000","txid":"6d74f0162f9c7a3be99cb60cca0c658f3e19fb3462f4c9731d5a0b7495183335","hash":"d6650355f9f42540f512cfe6c55829636e7a1b92a8893a4d48e1dec362ad62ff","size":128,"vsize":119,"weight":476,"version":42,"locktime":24,"vin":[{"txid":"0000000000000000000000000000000000000000000000000000000000000000","vout":24,"scriptSig":{"asm":"OP_RETURN OP_PICK","hex":"6a79"},"sequence":42,"txinwitness":["242424"]},{"txid":"0000000000000000000000000000000000000000000000000000000000000001","vout":42,"scriptSig":{"asm":"OP_RETURN OP_ROLL","hex":"6a7a"},"sequence":24,"txinwitness":["424242"]}],"vout":[{"value":2.4E-7,"scriptPubKey":{"asm":"OP_PICK","hex":"79","type":"nonstandard"},"n":0},{"value":4.2E-7,"scriptPubKey":{"asm":"OP_ROLL","hex":"7a","type":"nonstandard"},"n":1}]}]})json"
    };

    const auto& instance = test::mock_block_json;
    const auto value = json::value_from(bitcoind_verbose(instance));
    BOOST_REQUIRE_EQUAL(json::serialize(value), text);
}

BOOST_AUTO_TEST_SUITE_END()
