// OpaqueNameMirror — Starknet read-only ONS mirror.
//
// Mirrors the canonical Ethereum ONS registry (OpaqueNameRegistry) to Starknet so a
// Starknet client can resolve `name -> CSAP meta-address` from one local read, with no
// Ethereum RPC. The Solana mirror (spec/ONS.md §3) is fed by Wormhole VAAs; Starknet has
// no Wormhole endpoint, so this mirror is fed by NATIVE L1->L2 messaging: the Ethereum
// registry (or an L1 mirror-sender) calls `sendMessageToL2` on the Starknet core
// contract, and the sequencer delivers the payload to `handle_mirror` (an `#[l1_handler]`).
//
// The mirror invariants of spec/ONS.md §3 are preserved:
//   - Emitter allowlist: only the configured L1 sender may write (the sequencer injects
//     the true L1 sender as `from_address`, replacing the Wormhole `(chainId, emitter)`
//     pair).
//   - Monotonic sequence: a payload with `sequence <= stored` is rejected (stale/replayed).
//     The floor is skipped only for a genuinely new name (first delivery).
//   - Revoke tombstones, never deletes (OPQ-004): a revoke keeps the name, zeroes the
//     keys, advances the sequence, and sets `revoked = true`, so a later-delivered but
//     lower-sequence upsert cannot resurrect the name at stale keys.
//
// There is no direct-write path; the mirror is read-only from Starknet's perspective.

use starknet::ContractAddress;

pub const ACTION_UPSERT: u8 = 1;
pub const ACTION_REVOKE: u8 = 2;

/// A compressed secp256k1 point: `prefix` (0x02/0x03) and the 32-byte x-coordinate.
#[derive(Copy, Drop, Serde, PartialEq, starknet::Store)]
pub struct MetaKey {
    pub prefix: u8,
    pub x: u256,
}

/// A mirrored ONS record. `name_hash` is the map key, not stored in the struct.
#[derive(Copy, Drop, Serde, PartialEq, starknet::Store)]
pub struct OnsRecord {
    pub spend_pubkey: MetaKey,
    pub view_pubkey: MetaKey,
    /// Ethereum registrant, a 20-byte address in the low bytes of the felt.
    pub eth_owner: felt252,
    /// Last applied sequence (monotonic floor).
    pub sequence: u64,
    pub updated_at: u64,
    pub revoked: bool,
    /// Distinguishes a genuinely new name from an absent one (floor bypass).
    pub exists: bool,
}

#[starknet::interface]
pub trait IOpaqueNameMirror<TContractState> {
    /// The mirrored record for `name_hash` (`exists = false` if never delivered).
    fn resolve(self: @TContractState, name_hash: u256) -> OnsRecord;
    /// Resolver view: `(spend, view)` meta-address, or panic if unresolved/revoked.
    fn resolve_meta(self: @TContractState, name_hash: u256) -> (MetaKey, MetaKey);
    fn is_revoked(self: @TContractState, name_hash: u256) -> bool;
    fn sequence_of(self: @TContractState, name_hash: u256) -> u64;
    /// The allowlisted L1 sender (as a felt) that may feed this mirror.
    fn l1_emitter(self: @TContractState) -> felt252;
    /// Admin-only: rotate the allowlisted L1 emitter.
    fn set_l1_emitter(ref self: TContractState, emitter: felt252);
    fn transfer_admin(ref self: TContractState, new_admin: ContractAddress);
}

#[starknet::contract]
pub mod OpaqueNameMirror {
    use core::num::traits::Zero;
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess,
        StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
    use super::{ACTION_REVOKE, ACTION_UPSERT, MetaKey, OnsRecord};

    #[storage]
    struct Storage {
        admin: ContractAddress,
        /// The L1 sender allowed to write, as a felt252 (Ethereum address).
        l1_emitter: felt252,
        records: Map<u256, OnsRecord>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        RecordUpserted: RecordUpserted,
        RecordRevoked: RecordRevoked,
        EmitterUpdated: EmitterUpdated,
    }

    #[derive(Drop, starknet::Event)]
    struct RecordUpserted {
        #[key]
        name_hash: u256,
        sequence: u64,
        eth_owner: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct RecordRevoked {
        #[key]
        name_hash: u256,
        sequence: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct EmitterUpdated {
        emitter: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress, l1_emitter: felt252) {
        assert(!admin.is_zero(), 'zero admin');
        assert(l1_emitter != 0, 'zero emitter');
        self.admin.write(admin);
        self.l1_emitter.write(l1_emitter);
    }

    /// Consume a mirror payload delivered by the sequencer from L1. `from_address` is the
    /// true L1 sender injected by the protocol; the payload is Serde-deserialized into the
    /// remaining parameters (`sequence, action, name_hash, spend, view, eth_owner`).
    #[l1_handler]
    fn handle_mirror(
        ref self: ContractState,
        from_address: felt252,
        sequence: u64,
        action: u8,
        name_hash: u256,
        spend_pubkey: MetaKey,
        view_pubkey: MetaKey,
        eth_owner: felt252,
    ) {
        // Emitter allowlist: only the configured L1 registry/mirror-sender may write.
        assert(from_address == self.l1_emitter.read(), 'unauthorized emitter');

        let existing = self.records.read(name_hash);
        // Monotonic floor — skipped only for a genuinely new name (first delivery).
        if existing.exists {
            assert(sequence > existing.sequence, 'stale sequence');
        }

        let now = get_block_timestamp();
        if action == ACTION_UPSERT {
            self
                .records
                .write(
                    name_hash,
                    OnsRecord {
                        spend_pubkey,
                        view_pubkey,
                        eth_owner,
                        sequence,
                        updated_at: now,
                        revoked: false,
                        exists: true,
                    },
                );
            self.emit(RecordUpserted { name_hash, sequence, eth_owner });
        } else if action == ACTION_REVOKE {
            // Tombstone (OPQ-004): keep the name, zero the keys, advance the floor.
            let zero_key = MetaKey { prefix: 0, x: 0 };
            self
                .records
                .write(
                    name_hash,
                    OnsRecord {
                        spend_pubkey: zero_key,
                        view_pubkey: zero_key,
                        eth_owner: 0,
                        sequence,
                        updated_at: now,
                        revoked: true,
                        exists: true,
                    },
                );
            self.emit(RecordRevoked { name_hash, sequence });
        } else {
            core::panic_with_felt252('bad action');
        }
    }

    #[abi(embed_v0)]
    impl OpaqueNameMirrorImpl of super::IOpaqueNameMirror<ContractState> {
        fn resolve(self: @ContractState, name_hash: u256) -> OnsRecord {
            self.records.read(name_hash)
        }

        fn resolve_meta(self: @ContractState, name_hash: u256) -> (MetaKey, MetaKey) {
            let record = self.records.read(name_hash);
            assert(record.exists && !record.revoked, 'unresolved name');
            (record.spend_pubkey, record.view_pubkey)
        }

        fn is_revoked(self: @ContractState, name_hash: u256) -> bool {
            self.records.read(name_hash).revoked
        }

        fn sequence_of(self: @ContractState, name_hash: u256) -> u64 {
            self.records.read(name_hash).sequence
        }

        fn l1_emitter(self: @ContractState) -> felt252 {
            self.l1_emitter.read()
        }

        fn set_l1_emitter(ref self: ContractState, emitter: felt252) {
            self.assert_only_admin();
            assert(emitter != 0, 'zero emitter');
            self.l1_emitter.write(emitter);
            self.emit(EmitterUpdated { emitter });
        }

        fn transfer_admin(ref self: ContractState, new_admin: ContractAddress) {
            self.assert_only_admin();
            assert(!new_admin.is_zero(), 'zero admin');
            self.admin.write(new_admin);
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn assert_only_admin(self: @ContractState) {
            assert(get_caller_address() == self.admin.read(), 'only admin');
        }
    }
}
