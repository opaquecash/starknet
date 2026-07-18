// End-to-end tests for the OpaqueReputationVerifierV2 wrapper against the
// real V2 proof fixture (circuits/test/fixtures/v2, encoded by `garaga
// calldata` into tests/proof_calldata.txt). Fork testing is required because
// the generated Groth16 verifier library-calls Garaga's ECIP ops class, which
// is declared on Sepolia but not in a pristine test state.

use opaque_reputation_verifier::{
    IOpaqueReputationVerifierV2Dispatcher, IOpaqueReputationVerifierV2DispatcherTrait,
};
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_caller_address, stop_cheat_caller_address,
};
use starknet::ContractAddress;

// Public signals of the committed V2 fixture proof.
const MERKLE_ROOT: u256 = 0xd7809eb6f273f2f7b2da04ac0028f53c1cb14f63ce153a004ed08b728e70edb;
const NULLIFIER_HASH: u256 = 0x12b010b6f66b40387e5dc720325f79a6978756d15b8dba232d38789098a21376;

const REGISTERED_AT: u64 = 1000;
const ROOT_EXPIRY_SECS: u64 = 3600;

fn admin() -> ContractAddress {
    'admin'.try_into().unwrap()
}

fn deploy_stack() -> IOpaqueReputationVerifierV2Dispatcher {
    let verifier_class = declare("Groth16VerifierBN254").unwrap().contract_class();
    let (verifier_address, _) = verifier_class.deploy(@array![]).unwrap();

    let wrapper_class = declare("OpaqueReputationVerifierV2").unwrap().contract_class();
    let mut constructor_calldata: Array<felt252> = array![];
    admin().serialize(ref constructor_calldata);
    verifier_address.serialize(ref constructor_calldata);
    let (wrapper_address, _) = wrapper_class.deploy(@constructor_calldata).unwrap();

    IOpaqueReputationVerifierV2Dispatcher { contract_address: wrapper_address }
}

fn register_fixture_root(wrapper: IOpaqueReputationVerifierV2Dispatcher) {
    start_cheat_block_timestamp(wrapper.contract_address, REGISTERED_AT);
    start_cheat_caller_address(wrapper.contract_address, admin());
    wrapper.update_merkle_root(MERKLE_ROOT);
    stop_cheat_caller_address(wrapper.contract_address);
}

fn fixture_calldata() -> Span<felt252> {
    read_txt(@FileTrait::new("tests/proof_calldata.txt")).span()
}

#[test]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 12155600)]
fn test_verify_reputation_consumes_nullifier() {
    let wrapper = deploy_stack();
    register_fixture_root(wrapper);
    let calldata = fixture_calldata();

    assert(wrapper.is_root_active(MERKLE_ROOT), 'root should be active');
    assert(!wrapper.is_nullifier_used(NULLIFIER_HASH), 'nullifier fresh');
    assert(wrapper.verify_reputation_view(calldata), 'view should pass');

    wrapper.verify_reputation(calldata);

    assert(wrapper.is_nullifier_used(NULLIFIER_HASH), 'nullifier consumed');
    assert(!wrapper.verify_reputation_view(calldata), 'view false after consume');
}

#[test]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 12155600)]
#[should_panic(expected: 'nullifier already used')]
fn test_replay_is_rejected() {
    let wrapper = deploy_stack();
    register_fixture_root(wrapper);
    let calldata = fixture_calldata();

    wrapper.verify_reputation(calldata);
    wrapper.verify_reputation(calldata);
}

#[test]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 12155600)]
#[should_panic(expected: 'unknown or expired root')]
fn test_expired_root_is_rejected() {
    let wrapper = deploy_stack();
    register_fixture_root(wrapper);

    start_cheat_block_timestamp(
        wrapper.contract_address, REGISTERED_AT + ROOT_EXPIRY_SECS + 1,
    );
    wrapper.verify_reputation(fixture_calldata());
}

#[test]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 12155600)]
#[should_panic(expected: 'unknown or expired root')]
fn test_unregistered_root_is_rejected() {
    let wrapper = deploy_stack();
    wrapper.verify_reputation(fixture_calldata());
}

#[test]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 12155600)]
#[should_panic(expected: 'only admin')]
fn test_root_update_is_admin_only() {
    let wrapper = deploy_stack();
    wrapper.update_merkle_root(MERKLE_ROOT);
}
