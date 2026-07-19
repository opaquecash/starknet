// PsrGate end-to-end against the real V2 fixture proof.
//
// Deploys the full stack (Groth16 verifier -> reputation wrapper -> gate),
// registers the fixture root, and drives entry with the committed proof.
// Fork testing is required: the generated Groth16 verifier library-calls
// Garaga's ECIP ops class, declared on Sepolia but not in a pristine VM.

use opaque_reputation_verifier::{
    IOpaqueReputationVerifierV2Dispatcher, IOpaqueReputationVerifierV2DispatcherTrait,
};
use psr_gate::{IPsrGateDispatcher, IPsrGateDispatcherTrait};
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_caller_address,
};
use starknet::ContractAddress;

const MERKLE_ROOT: u256 = 0xd7809eb6f273f2f7b2da04ac0028f53c1cb14f63ce153a004ed08b728e70edb;
// attestation_id (schema) committed by the fixture proof.
const FIXTURE_SCHEMA: u256 = 0x2c2ad974da749;
const EXTERNAL_NULLIFIER: u256 = 0xdeadbeef;
const REGISTERED_AT: u64 = 1000;

fn admin() -> ContractAddress {
    'admin'.try_into().unwrap()
}

fn fixture_calldata() -> Span<felt252> {
    read_txt(@FileTrait::new("tests/proof_calldata.txt")).span()
}

/// Deploy Groth16 verifier + wrapper + gate; register the fixture root.
fn deploy_stack(required_schema: u256) -> (IOpaqueReputationVerifierV2Dispatcher, IPsrGateDispatcher) {
    let verifier_class = declare("Groth16VerifierBN254").unwrap().contract_class();
    let (verifier_addr, _) = verifier_class.deploy(@array![]).unwrap();

    let wrapper_class = declare("OpaqueReputationVerifierV2").unwrap().contract_class();
    let mut wc: Array<felt252> = array![];
    admin().serialize(ref wc);
    verifier_addr.serialize(ref wc);
    let (wrapper_addr, _) = wrapper_class.deploy(@wc).unwrap();
    let wrapper = IOpaqueReputationVerifierV2Dispatcher { contract_address: wrapper_addr };

    let gate_class = declare("PsrGate").unwrap().contract_class();
    let mut gc: Array<felt252> = array![];
    wrapper_addr.serialize(ref gc);
    required_schema.serialize(ref gc);
    let (gate_addr, _) = gate_class.deploy(@gc).unwrap();
    let gate = IPsrGateDispatcher { contract_address: gate_addr };

    start_cheat_block_timestamp(wrapper_addr, REGISTERED_AT);
    start_cheat_caller_address(wrapper_addr, admin());
    wrapper.update_merkle_root(MERKLE_ROOT);
    // Reset caller so gate calls come from a normal account.
    start_cheat_caller_address(wrapper_addr, 'relayer'.try_into().unwrap());
    (wrapper, gate)
}

#[test]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 12155600)]
fn test_valid_credential_enters_the_gate() {
    let (_wrapper, gate) = deploy_stack(FIXTURE_SCHEMA);
    assert(!gate.has_entered(EXTERNAL_NULLIFIER), 'not entered yet');

    let scope = gate.enter(fixture_calldata());

    assert(scope == EXTERNAL_NULLIFIER, 'wrong scope returned');
    assert(gate.has_entered(EXTERNAL_NULLIFIER), 'should be entered');
    assert(gate.entry_count() == 1, 'entry not counted');
}

#[test]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 12155600)]
#[should_panic(expected: 'nullifier already used')]
fn test_same_credential_cannot_re_enter() {
    let (_wrapper, gate) = deploy_stack(FIXTURE_SCHEMA);
    gate.enter(fixture_calldata());
    // Replay: the verifier's nullifier is spent, so re-entry is rejected.
    gate.enter(fixture_calldata());
}

#[test]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 12155600)]
#[should_panic(expected: 'wrong schema')]
fn test_credential_under_wrong_schema_is_rejected() {
    // The gate requires a different schema than the fixture proves.
    let (_wrapper, gate) = deploy_stack(FIXTURE_SCHEMA + 1);
    gate.enter(fixture_calldata());
}

#[test]
#[fork(url: "https://api.zan.top/public/starknet-sepolia/rpc/v0_10", block_number: 12155600)]
#[should_panic(expected: 'unknown or expired root')]
fn test_entry_without_a_fresh_root_is_rejected() {
    let (wrapper, gate) = deploy_stack(FIXTURE_SCHEMA);
    // Advance past the root TTL so the proof's root is no longer active.
    start_cheat_block_timestamp(wrapper.contract_address, REGISTERED_AT + 3601);
    gate.enter(fixture_calldata());
}
