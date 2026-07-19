// OpaqueNameMirror: L1->L2 mirror delivery + invariants (spec/ONS.md §3).
//
// snforge's L1HandlerTrait simulates the sequencer delivering an L1->L2 message: it
// forges `from_address` (so the emitter allowlist is exercised) and Serde-encodes the
// payload the Ethereum registry would send.

use ons_mirror::{
    ACTION_REVOKE, ACTION_UPSERT, IOpaqueNameMirrorDispatcher, IOpaqueNameMirrorDispatcherTrait,
    MetaKey,
};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, L1HandlerTrait, declare,
    start_cheat_caller_address,
};
use starknet::ContractAddress;

// The allowlisted L1 emitter (the Ethereum OpaqueNameRegistry / mirror-sender), as a felt.
const L1_EMITTER: felt252 = 0x00000000000000000000000000000000deadbeef;
const NAME_HASH: u256 = 0xa11ce0000000000000000000000000000000000000000000000000000000001;

fn admin() -> ContractAddress {
    'admin'.try_into().unwrap()
}

fn deploy() -> IOpaqueNameMirrorDispatcher {
    let class = declare("OpaqueNameMirror").unwrap().contract_class();
    let mut calldata: Array<felt252> = array![];
    admin().serialize(ref calldata);
    L1_EMITTER.serialize(ref calldata);
    let (address, _) = class.deploy(@calldata).unwrap();
    IOpaqueNameMirrorDispatcher { contract_address: address }
}

/// Serde-encode the mirror payload the way the L1 message carries it.
fn mirror_payload(
    sequence: u64, action: u8, name_hash: u256, spend: MetaKey, view: MetaKey, eth_owner: felt252,
) -> Array<felt252> {
    let mut payload: Array<felt252> = array![];
    sequence.serialize(ref payload);
    action.serialize(ref payload);
    name_hash.serialize(ref payload);
    spend.serialize(ref payload);
    view.serialize(ref payload);
    eth_owner.serialize(ref payload);
    payload
}

fn spend_key() -> MetaKey {
    MetaKey { prefix: 0x02, x: 0x1111111111111111111111111111111111111111111111111111111111111111 }
}

fn view_key() -> MetaKey {
    MetaKey { prefix: 0x03, x: 0x2222222222222222222222222222222222222222222222222222222222222222 }
}

/// Deliver a payload from `from_address` via the simulated sequencer, expecting success.
fn deliver(
    mirror: IOpaqueNameMirrorDispatcher, from_address: felt252, payload: Array<felt252>,
) {
    try_deliver(mirror, from_address, payload).unwrap();
}

/// Deliver a payload and return the raw result; a panicking `#[l1_handler]` surfaces as
/// `Err(panic_data)` (snforge does not re-raise it), so negative tests assert on the error.
fn try_deliver(
    mirror: IOpaqueNameMirrorDispatcher, from_address: felt252, payload: Array<felt252>,
) -> starknet::SyscallResult<()> {
    let handler = L1HandlerTrait::new(mirror.contract_address, selector!("handle_mirror"));
    handler.execute(from_address, payload.span())
}

fn assert_delivery_reverts(
    mirror: IOpaqueNameMirrorDispatcher,
    from_address: felt252,
    payload: Array<felt252>,
    expected: felt252,
) {
    match try_deliver(mirror, from_address, payload) {
        Result::Ok(()) => core::panic_with_felt252('expected revert'),
        Result::Err(data) => assert(*data.at(0) == expected, 'wrong revert reason'),
    }
}

#[test]
fn test_upsert_mirrors_the_record() {
    let mirror = deploy();
    deliver(
        mirror,
        L1_EMITTER,
        mirror_payload(1, ACTION_UPSERT, NAME_HASH, spend_key(), view_key(), 0xabcd),
    );

    let (spend, view) = mirror.resolve_meta(NAME_HASH);
    assert(spend == spend_key(), 'spend mismatch');
    assert(view == view_key(), 'view mismatch');
    assert(mirror.sequence_of(NAME_HASH) == 1, 'seq not set');
    assert(!mirror.is_revoked(NAME_HASH), 'should not be revoked');
}

#[test]
fn test_later_sequence_updates_in_place() {
    let mirror = deploy();
    deliver(mirror, L1_EMITTER, mirror_payload(1, ACTION_UPSERT, NAME_HASH, spend_key(), view_key(), 0xabcd));
    // A new upsert at a higher sequence with different keys.
    let new_spend = MetaKey { prefix: 0x02, x: 0x9999 };
    deliver(mirror, L1_EMITTER, mirror_payload(5, ACTION_UPSERT, NAME_HASH, new_spend, view_key(), 0xffff));

    let (spend, _) = mirror.resolve_meta(NAME_HASH);
    assert(spend == new_spend, 'not updated');
    assert(mirror.sequence_of(NAME_HASH) == 5, 'seq not advanced');
}

#[test]
fn test_stale_sequence_is_rejected() {
    let mirror = deploy();
    deliver(mirror, L1_EMITTER, mirror_payload(5, ACTION_UPSERT, NAME_HASH, spend_key(), view_key(), 0xabcd));
    // Lower sequence must be rejected (replay / out-of-order delivery).
    assert_delivery_reverts(
        mirror,
        L1_EMITTER,
        mirror_payload(4, ACTION_UPSERT, NAME_HASH, spend_key(), view_key(), 0xabcd),
        'stale sequence',
    );
}

#[test]
fn test_equal_sequence_is_rejected() {
    let mirror = deploy();
    deliver(mirror, L1_EMITTER, mirror_payload(5, ACTION_UPSERT, NAME_HASH, spend_key(), view_key(), 0xabcd));
    assert_delivery_reverts(
        mirror,
        L1_EMITTER,
        mirror_payload(5, ACTION_UPSERT, NAME_HASH, spend_key(), view_key(), 0xabcd),
        'stale sequence',
    );
}

#[test]
fn test_revoke_tombstones_and_keeps_the_floor() {
    let mirror = deploy();
    deliver(mirror, L1_EMITTER, mirror_payload(3, ACTION_UPSERT, NAME_HASH, spend_key(), view_key(), 0xabcd));
    deliver(mirror, L1_EMITTER, mirror_payload(4, ACTION_REVOKE, NAME_HASH, spend_key(), view_key(), 0xabcd));

    assert(mirror.is_revoked(NAME_HASH), 'not revoked');
    // Floor survives the revoke so a stale upsert cannot resurrect the name.
    assert(mirror.sequence_of(NAME_HASH) == 4, 'floor lost');
    let record = mirror.resolve(NAME_HASH);
    assert(record.exists, 'record should persist');
    assert(record.spend_pubkey.x == 0, 'keys not zeroed');
}

#[test]
#[should_panic(expected: 'unresolved name')]
fn test_revoked_name_does_not_resolve() {
    let mirror = deploy();
    deliver(mirror, L1_EMITTER, mirror_payload(3, ACTION_UPSERT, NAME_HASH, spend_key(), view_key(), 0xabcd));
    deliver(mirror, L1_EMITTER, mirror_payload(4, ACTION_REVOKE, NAME_HASH, spend_key(), view_key(), 0xabcd));
    mirror.resolve_meta(NAME_HASH); // must panic: revoked == unresolved
}

#[test]
fn test_revoke_blocks_lower_sequence_upsert_resurrection() {
    let mirror = deploy();
    // Upsert at 3, revoke at 5, then a delayed upsert at 4 arrives — must be rejected,
    // so the name cannot be resurrected at stale keys (OPQ-004).
    deliver(mirror, L1_EMITTER, mirror_payload(3, ACTION_UPSERT, NAME_HASH, spend_key(), view_key(), 0xabcd));
    deliver(mirror, L1_EMITTER, mirror_payload(5, ACTION_REVOKE, NAME_HASH, spend_key(), view_key(), 0xabcd));
    assert_delivery_reverts(
        mirror,
        L1_EMITTER,
        mirror_payload(4, ACTION_UPSERT, NAME_HASH, spend_key(), view_key(), 0xabcd),
        'stale sequence',
    );
    assert(mirror.is_revoked(NAME_HASH), 'still revoked');
}

#[test]
fn test_unauthorized_l1_sender_is_rejected() {
    let mirror = deploy();
    let attacker: felt252 = 0x00000000000000000000000000000000badc0de;
    assert_delivery_reverts(
        mirror,
        attacker,
        mirror_payload(1, ACTION_UPSERT, NAME_HASH, spend_key(), view_key(), 0xabcd),
        'unauthorized emitter',
    );
}

#[test]
fn test_admin_can_rotate_emitter() {
    let mirror = deploy();
    let new_emitter: felt252 = 0x00000000000000000000000000000000cafe;
    start_cheat_caller_address(mirror.contract_address, admin());
    mirror.set_l1_emitter(new_emitter);
    assert(mirror.l1_emitter() == new_emitter, 'emitter not rotated');
    // The new emitter can now write; the old one cannot (covered by the negative test).
    deliver(mirror, new_emitter, mirror_payload(1, ACTION_UPSERT, NAME_HASH, spend_key(), view_key(), 0xabcd));
    assert(mirror.sequence_of(NAME_HASH) == 1, 'new emitter write failed');
}

#[test]
#[should_panic(expected: 'only admin')]
fn test_emitter_rotation_is_admin_only() {
    let mirror = deploy();
    mirror.set_l1_emitter(0xcafe);
}
