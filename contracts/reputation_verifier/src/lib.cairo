// OpaqueReputationVerifierV2 — Starknet port.
//
// Mirrors the Ethereum wrapper (OpaqueReputationVerifierV2.sol): admin-published
// Merkle roots with a 1h TTL and delete-on-evict history, a consume-once
// nullifier set, and the OPQ-006 schema-liveness binding ahead of the pairing
// check. Proof verification is delegated to the Garaga-generated
// psr_groth16_verifier contract, which returns the four V2 public signals
// [merkle_root, attestation_id, external_nullifier, nullifier_hash] on success.
//
// All public signals are BN254 scalar-field elements carried as u256 (BN254 r
// exceeds felt252) and MUST be reduced into [0, r); out-of-field values are
// rejected here even though the prover-side encoding already enforces this.

use starknet::ContractAddress;

#[starknet::interface]
pub trait IGroth16VerifierBN254<TContractState> {
    fn verify_groth16_proof_bn254(
        self: @TContractState, full_proof_with_hints: Span<felt252>,
    ) -> Result<Span<u256>, felt252>;
}

/// OPQ-006 seam: the Cairo schema registry (P1) exposes liveness so a proof
/// cannot assert reputation under a never-registered or deprecated schema.
#[starknet::interface]
pub trait ISchemaLiveness<TContractState> {
    fn is_schema_live(self: @TContractState, schema_id: u256) -> bool;
}

#[starknet::interface]
pub trait IOpaqueReputationVerifierV2<TContractState> {
    fn update_merkle_root(ref self: TContractState, root: u256);
    fn verify_reputation(ref self: TContractState, full_proof_with_hints: Span<felt252>);
    fn verify_reputation_view(
        self: @TContractState, full_proof_with_hints: Span<felt252>,
    ) -> bool;
    fn is_nullifier_used(self: @TContractState, nullifier_hash: u256) -> bool;
    fn is_root_active(self: @TContractState, root: u256) -> bool;
    fn set_schema_registry(ref self: TContractState, registry: ContractAddress);
    fn transfer_admin(ref self: TContractState, new_admin: ContractAddress);
}

#[starknet::contract]
mod OpaqueReputationVerifierV2 {
    use core::num::traits::Zero;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_block_timestamp, get_caller_address};
    use super::{
        IGroth16VerifierBN254Dispatcher, IGroth16VerifierBN254DispatcherTrait,
        ISchemaLivenessDispatcher, ISchemaLivenessDispatcherTrait,
    };

    /// BN254 scalar-field order r; every public signal must lie in [0, r).
    const BN254_R: u256 = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    const ROOT_EXPIRY_SECS: u64 = 3600;
    const MAX_ROOT_HISTORY: u64 = 100;
    const N_PUBLIC_INPUTS: u32 = 4;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        groth16_verifier: ContractAddress,
        /// Zero address = binding disabled (P0; enable when the registry lands).
        schema_registry: ContractAddress,
        /// root -> registration timestamp; 0 = absent (delete-on-evict).
        root_timestamps: Map<u256, u64>,
        /// Ring buffer of the last MAX_ROOT_HISTORY roots.
        root_ring: Map<u64, u256>,
        /// Total roots ever registered (next ring position = head % MAX).
        root_head: u64,
        nullifiers: Map<u256, bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        MerkleRootUpdated: MerkleRootUpdated,
        ReputationVerified: ReputationVerified,
        AdminTransferred: AdminTransferred,
    }

    #[derive(Drop, starknet::Event)]
    struct MerkleRootUpdated {
        root: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ReputationVerified {
        #[key]
        nullifier_hash: u256,
        #[key]
        attestation_id: u256,
        external_nullifier: u256,
        merkle_root: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct AdminTransferred {
        previous_admin: ContractAddress,
        new_admin: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, admin: ContractAddress, groth16_verifier: ContractAddress,
    ) {
        assert(!admin.is_zero(), 'zero admin');
        assert(!groth16_verifier.is_zero(), 'zero verifier');
        self.admin.write(admin);
        self.groth16_verifier.write(groth16_verifier);
    }

    #[abi(embed_v0)]
    impl OpaqueReputationVerifierV2Impl of super::IOpaqueReputationVerifierV2<ContractState> {
        fn update_merkle_root(ref self: ContractState, root: u256) {
            self.assert_only_admin();
            assert(root < BN254_R, 'root out of field');
            let now = get_block_timestamp();
            if self.root_timestamps.read(root) != 0 {
                // Re-registration refreshes the TTL without a new ring slot.
                self.root_timestamps.write(root, now);
                self.emit(MerkleRootUpdated { root, timestamp: now });
                return;
            }
            let head = self.root_head.read();
            if head >= MAX_ROOT_HISTORY {
                // Delete-on-evict (EVM semantics): the evicted root becomes
                // unknown, not merely expired.
                let evicted = self.root_ring.read(head % MAX_ROOT_HISTORY);
                self.root_timestamps.write(evicted, 0);
            }
            self.root_ring.write(head % MAX_ROOT_HISTORY, root);
            self.root_timestamps.write(root, now);
            self.root_head.write(head + 1);
            self.emit(MerkleRootUpdated { root, timestamp: now });
        }

        fn verify_reputation(ref self: ContractState, full_proof_with_hints: Span<felt252>) {
            let (merkle_root, attestation_id, external_nullifier, nullifier_hash) = self
                .verify_and_extract(full_proof_with_hints);
            assert(!self.nullifiers.read(nullifier_hash), 'nullifier already used');
            self.nullifiers.write(nullifier_hash, true);
            self
                .emit(
                    ReputationVerified {
                        nullifier_hash, attestation_id, external_nullifier, merkle_root,
                    },
                );
        }

        fn verify_reputation_view(
            self: @ContractState, full_proof_with_hints: Span<felt252>,
        ) -> bool {
            let verifier = IGroth16VerifierBN254Dispatcher {
                contract_address: self.groth16_verifier.read(),
            };
            let public_inputs = match verifier.verify_groth16_proof_bn254(full_proof_with_hints) {
                Result::Ok(pi) => pi,
                Result::Err(_) => { return false; },
            };
            if public_inputs.len() != N_PUBLIC_INPUTS {
                return false;
            }
            let merkle_root = *public_inputs.at(0);
            let attestation_id = *public_inputs.at(1);
            let external_nullifier = *public_inputs.at(2);
            let nullifier_hash = *public_inputs.at(3);
            if merkle_root >= BN254_R
                || attestation_id >= BN254_R
                || external_nullifier >= BN254_R
                || nullifier_hash >= BN254_R {
                return false;
            }
            if !self.root_is_active(merkle_root) {
                return false;
            }
            if !self.schema_is_live(attestation_id) {
                return false;
            }
            !self.nullifiers.read(nullifier_hash)
        }

        fn is_nullifier_used(self: @ContractState, nullifier_hash: u256) -> bool {
            self.nullifiers.read(nullifier_hash)
        }

        fn is_root_active(self: @ContractState, root: u256) -> bool {
            self.root_is_active(root)
        }

        fn set_schema_registry(ref self: ContractState, registry: ContractAddress) {
            self.assert_only_admin();
            // Zero disables the binding; setting it live is one-way in spirit
            // (OPQ-006) but admin-reversible while the registry port matures.
            self.schema_registry.write(registry);
        }

        fn transfer_admin(ref self: ContractState, new_admin: ContractAddress) {
            self.assert_only_admin();
            assert(!new_admin.is_zero(), 'zero admin');
            let previous_admin = self.admin.read();
            self.admin.write(new_admin);
            self.emit(AdminTransferred { previous_admin, new_admin });
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn assert_only_admin(self: @ContractState) {
            assert(get_caller_address() == self.admin.read(), 'only admin');
        }

        fn root_is_active(self: @ContractState, root: u256) -> bool {
            let ts = self.root_timestamps.read(root);
            if ts == 0 {
                return false;
            }
            get_block_timestamp() - ts <= ROOT_EXPIRY_SECS
        }

        fn schema_is_live(self: @ContractState, attestation_id: u256) -> bool {
            let registry = self.schema_registry.read();
            if registry.is_zero() {
                return true;
            }
            ISchemaLivenessDispatcher { contract_address: registry }.is_schema_live(attestation_id)
        }

        fn verify_and_extract(
            ref self: ContractState, full_proof_with_hints: Span<felt252>,
        ) -> (u256, u256, u256, u256) {
            let verifier = IGroth16VerifierBN254Dispatcher {
                contract_address: self.groth16_verifier.read(),
            };
            let public_inputs = match verifier.verify_groth16_proof_bn254(full_proof_with_hints) {
                Result::Ok(pi) => pi,
                Result::Err(e) => core::panic_with_felt252(e),
            };
            assert(public_inputs.len() == N_PUBLIC_INPUTS, 'bad public input count');
            let merkle_root = *public_inputs.at(0);
            let attestation_id = *public_inputs.at(1);
            let external_nullifier = *public_inputs.at(2);
            let nullifier_hash = *public_inputs.at(3);
            assert(merkle_root < BN254_R, 'root out of field');
            assert(attestation_id < BN254_R, 'schema out of field');
            assert(external_nullifier < BN254_R, 'scope out of field');
            assert(nullifier_hash < BN254_R, 'nullifier out of field');
            assert(self.root_is_active(merkle_root), 'unknown or expired root');
            assert(self.schema_is_live(attestation_id), 'schema not live');
            (merkle_root, attestation_id, external_nullifier, nullifier_hash)
        }
    }
}
