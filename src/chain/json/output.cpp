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
#include <bitcoin/system/chain/json/json.hpp>

#include <bitcoin/system/chain/enums/magic_numbers.hpp>
#include <bitcoin/system/chain/enums/script_pattern.hpp>
#include <bitcoin/system/chain/output.hpp>
#include <bitcoin/system/chain/script.hpp>
#include <bitcoin/system/define.hpp>
#include <bitcoin/system/math/math.hpp>
#include <bitcoin/system/wallet/addresses/payment_address.hpp>
#include <bitcoin/system/wallet/addresses/witness_address.hpp>

namespace libbitcoin {
namespace system {
namespace chain {

DEFINE_JSON_TO_TAG(output)
{
    return
    {
        value.at("value").as_uint64(),
        value_to<script>(value.at("script"))
    };
}

DEFINE_JSON_FROM_TAG(output)
{
    value =
    {
        { "value", instance.value() },
        { "script", value_from(instance.script()) }
    };
}

DEFINE_JSON_TO_TAG(output::cptr)
{
    return to_shared(tag_invoke(to_tag<output>{}, value));
}

DEFINE_JSON_FROM_TAG(output::cptr)
{
    tag_invoke(from_tag{}, value, *instance);
}

// bitcoind
// ----------------------------------------------------------------------------

// Maps a libbitcoin output script template to the Bitcoin Core
// GetTxnOutputType() string (src/script/solver.cpp), as emitted by
// ScriptPubKeyToUniv / TxToUniv. Core dropped the plural "addresses" and
// "reqSigs" fields in v22 and emits a singular "address" only when exactly one
// address is extractable.
static std::string core_output_type(script_pattern pattern) NOEXCEPT
{
    switch (pattern)
    {
        case script_pattern::pay_public_key:
            return "pubkey";
        case script_pattern::pay_key_hash:
            return "pubkeyhash";
        case script_pattern::pay_script_hash:
            return "scripthash";
        case script_pattern::pay_multisig:
            return "multisig";
        case script_pattern::pay_null_data:
            return "nulldata";
        case script_pattern::pay_witness_key_hash:
            return "witness_v0_keyhash";
        case script_pattern::pay_witness_script_hash:
            return "witness_v0_scripthash";
        case script_pattern::pay_witness_v1_taproot:
            return "witness_v1_taproot";
        default:
            return "nonstandard";
    }
}

// Returns the single Core-style address for an output script, or empty if Core
// would not emit an "address" field for this template. Core emits an address
// for: pubkey (the P2PKH address of the key), pubkeyhash, scripthash, and the
// v0/v1 witness programs. It emits none for multisig, nulldata, nonstandard, or
// unknown/future witness versions.
//
// NOTE (network): this builder receives only a chain::output (the
// wrapped<bitcoind_tag, output> instance) and has no network context, so the
// base58 prefixes and the bech32 human-readable prefix default to mainnet
// (matching prior implicit-mainnet behavior). If a network is ever threaded
// into the JSON tag, pass the per-network payment_address prefixes and
// witness_address::testnet here.
static std::string core_output_address(const script& script) NOEXCEPT
{
    using namespace wallet;

    switch (script.output_pattern())
    {
        // P2PKH / P2SH: extract_output produces the base58check address.
        case script_pattern::pay_key_hash:
        case script_pattern::pay_script_hash:
        {
            const auto address = payment_address::extract_output(script);
            return address ? address.encoded() : std::string{};
        }

        // P2PK: extract_output yields nothing for a bare pubkey, but Core emits
        // the P2PKH address of the embedded public key. ops().front() is the
        // pubkey push (validated by is_pay_public_key_pattern via is_public_key).
        case script_pattern::pay_public_key:
        {
            const payment_address address{
                ec_public{ script.ops().front().data() } };
            return address ? address.encoded() : std::string{};
        }

        // Witness v0 keyhash/scripthash: bech32 (BIP173) over the program.
        case script_pattern::pay_witness_key_hash:
        case script_pattern::pay_witness_script_hash:
        {
            const witness_address address{ script.ops().back().data(), 0u };
            return address ? address.encoded() : std::string{};
        }

        // Witness v1 taproot: bech32m (BIP350) is selected automatically for
        // non-zero versions by witness_address (bech32_constant).
        case script_pattern::pay_witness_v1_taproot:
        {
            const witness_address address{ script.ops().back().data(), 1u };
            return address ? address.encoded() : std::string{};
        }

        // No address: bare multisig, nulldata, nonstandard, unknown witness.
        default:
            return {};
    }
}

DEFINE_JSON_FROM_TAGGED(bitcoind_tag, output)
{
    using namespace boost::json;
    const auto& out = instance.value;
    const auto satoshis = out.value() / to_floating(satoshi_per_bitcoin);
    auto script = value_from(bitcoind(out.script())).as_object();

    // Removed in bitcoind v22.0 (because not useful).
    ////script["reqSigs"] = 1;
    // Removed in bitcoind v22.0 (replaced by the singular "address" below).
    ////script["addresses"] = array{ ... };

    // ECH-37/ECH-43: Core-compatible output classification and a singular
    // "address", derived from the script template (no more hard-coded
    // "nonstandard" / scripthash-as-address).
    script["type"] = core_output_type(out.script().output_pattern());

    // Core emits a singular "address" only when exactly one is extractable.
    const auto address = core_output_address(out.script());
    if (!address.empty())
        script["address"] = address;

    value =
    {
        { "value", satoshis},
        { "scriptPubKey", std::move(script) }

        // In what parallel universe does serializing position make sense?
        ////{ "n", injected from loop }
    };
}

DEFINE_JSON_FROM_TAGGED(bitcoind_tag, output_cptrs)
{
    const auto& outs = instance.value;
    value = boost::json::array(outs.size());
    auto& values = value.as_array();
    for (size_t n{}; n < outs.size(); ++n)
    {
        values.at(n) = value_from(bitcoind(*outs.at(n)));
        values.at(n).as_object()["n"] = n;
    }
}

} // namespace chain
} // namespace system
} // namespace libbitcoin
