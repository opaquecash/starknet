// Custody properties of the stealth account class.
//
// The security of OZ's EthAccountComponent signature validation is covered by
// its own audited suite; these tests pin the CSAP-specific property the SDK
// depends on: the stealth address is a deterministic, precalculable function
// of (class_hash, salt, [pk.x, pk.y]) — so a sender or watch-only scanner
// derives it from the announcement — and it varies per payment with the salt.
//
// The signing key is CSAP canonical vector 1's `one_time_private_key`
// (spec/CSAP.md Test Vectors): `P_stealth = one_time_private_key · G` is the
// account's sole owner, exactly the one-time key a real recipient reconstructs.

use snforge_std::signature::KeyPairTrait;
use snforge_std::signature::secp256k1_curve::Secp256k1CurveKeyPairImpl;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::secp256k1::Secp256k1Point;

/// CSAP canonical vector 1 `one_time_private_key`.
const ONE_TIME_PRIVATE_KEY: u256 =
    0x9d1fcbe17267729a88091556cadd19b3c11e33029883163d1d7118bc21a61e2e;

fn stealth_pubkey_calldata() -> Array<felt252> {
    let key_pair = KeyPairTrait::<u256, Secp256k1Point>::from_secret_key(
        ONE_TIME_PRIVATE_KEY,
    );
    let mut calldata: Array<felt252> = array![];
    key_pair.public_key.serialize(ref calldata);
    calldata
}

#[test]
fn test_stealth_address_is_precalculable_and_deterministic() {
    let contract = declare("StealthAccount").unwrap().contract_class();
    let calldata = stealth_pubkey_calldata();

    // The sender/scanner precalculates the address from public data only.
    let predicted = contract.precalculate_address(@calldata);
    let (deployed, _) = contract.deploy_at(@calldata, predicted).unwrap();
    assert(predicted == deployed, 'address not precalculable');
}

#[test]
fn test_salt_changes_the_stealth_address() {
    let contract = declare("StealthAccount").unwrap().contract_class();
    let calldata = stealth_pubkey_calldata();

    // Two payments to the same recipient key must land at different addresses;
    // precalculate_address folds in a fresh salt per call so unlinkability
    // comes from the per-payment ephemeral key that produced this P_stealth.
    let first = contract.precalculate_address(@calldata);
    let (deployed_first, _) = contract.deploy_at(@calldata, first).unwrap();
    let second = contract.precalculate_address(@calldata);
    assert(deployed_first != second, 'salt did not change address');
}

#[test]
fn test_account_reports_its_stealth_public_key() {
    let contract = declare("StealthAccount").unwrap().contract_class();
    let calldata = stealth_pubkey_calldata();
    let (address, _) = contract.deploy(@calldata).unwrap();

    // The stored owner must be the one-time key we constructed it with;
    // compare the serialised point (the constructor-calldata encoding).
    let dispatcher = IEthPublicKeyDispatcher { contract_address: address };
    let mut got: Array<felt252> = array![];
    dispatcher.get_public_key().serialize(ref got);
    assert(got == calldata, 'wrong stored public key');
}

#[starknet::interface]
trait IEthPublicKey<TState> {
    fn get_public_key(self: @TState) -> Secp256k1Point;
}
