// PsrGate — the Tier-1 PSR consumer: credential-gated entry.
//
// Demonstrates the integration thesis (spec/starknet-integration.md §5): STRK20
// has viewing keys but no way to require "is this actor eligible?" before an
// action. PsrGate is the minimal general form of that gate — an allowlist an
// actor may enter ONLY by proving, in zero knowledge, possession of a valid
// attestation under a specific schema, with the proof's nullifier consumed
// once so the same credential cannot enter the same scope twice (Sybil
// resistance). A real deployment points a STRK20 anonymizer / DeFi action at
// `has_entered` (or gates the action inline), so only credentialed stealth
// identities transact — without ever revealing who they are.

use starknet::ContractAddress;

#[starknet::interface]
pub trait IReputationVerifier<TContractState> {
    fn verify_and_consume(
        ref self: TContractState, full_proof_with_hints: Span<felt252>,
    ) -> (u256, u256, u256, u256);
}

#[starknet::interface]
pub trait IPsrGate<TContractState> {
    /// Enter the gate with a PSR proof. Verifies + consumes the nullifier via
    /// the verifier, requires the proof's schema to equal `required_schema`,
    /// records the entry, and returns the action scope (`external_nullifier`).
    fn enter(ref self: TContractState, full_proof_with_hints: Span<felt252>) -> u256;
    /// Whether `scope` (an `external_nullifier`) has been entered.
    fn has_entered(self: @TContractState, scope: u256) -> bool;
    fn entry_count(self: @TContractState) -> u64;
    fn required_schema(self: @TContractState) -> u256;
    fn verifier(self: @TContractState) -> ContractAddress;
}

#[starknet::contract]
pub mod PsrGate {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};
    use super::{IReputationVerifierDispatcher, IReputationVerifierDispatcherTrait};

    #[storage]
    struct Storage {
        verifier: ContractAddress,
        required_schema: u256,
        entered: Map<u256, bool>,
        entry_count: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        Entered: Entered,
    }

    /// `entrant` is the submitting account (a relayer or the user); it is NOT
    /// the stealth identity, which stays private. `scope` is the action's
    /// `external_nullifier`; `attestation_id` is the proven schema.
    #[derive(Drop, starknet::Event)]
    pub struct Entered {
        #[key]
        pub scope: u256,
        #[key]
        pub attestation_id: u256,
        pub entrant: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, verifier: ContractAddress, required_schema: u256,
    ) {
        self.verifier.write(verifier);
        self.required_schema.write(required_schema);
    }

    #[abi(embed_v0)]
    impl PsrGateImpl of super::IPsrGate<ContractState> {
        fn enter(ref self: ContractState, full_proof_with_hints: Span<felt252>) -> u256 {
            // The verifier checks Groth16 validity, root freshness, schema
            // liveness, and consumes the nullifier (one-time use). It panics on
            // any failure or a replayed nullifier, so a successful return means
            // the proof was valid and fresh.
            let (_root, attestation_id, external_nullifier, _nullifier) =
                IReputationVerifierDispatcher { contract_address: self.verifier.read() }
                .verify_and_consume(full_proof_with_hints);

            // Gate policy: the credential must be under THIS gate's schema.
            assert(attestation_id == self.required_schema.read(), 'wrong schema');

            // The nullifier is already spent in the verifier, so this is belt
            // and suspenders — but it keeps the gate's own view consistent.
            assert(!self.entered.read(external_nullifier), 'scope already entered');
            self.entered.write(external_nullifier, true);
            self.entry_count.write(self.entry_count.read() + 1);

            self
                .emit(
                    Entered {
                        scope: external_nullifier,
                        attestation_id,
                        entrant: get_caller_address(),
                    },
                );
            external_nullifier
        }

        fn has_entered(self: @ContractState, scope: u256) -> bool {
            self.entered.read(scope)
        }

        fn entry_count(self: @ContractState) -> u64 {
            self.entry_count.read()
        }

        fn required_schema(self: @ContractState) -> u256 {
            self.required_schema.read()
        }

        fn verifier(self: @ContractState) -> ContractAddress {
            self.verifier.read()
        }
    }
}
