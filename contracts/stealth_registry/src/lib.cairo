// CSAP stealth meta-address registry — Starknet port.
//
// Mirrors ERC-6538 storage (`registrant -> (scheme_id -> meta bytes)`) and the
// Solana `stealth_registry` semantics. Registration is self-service: the
// registrant is the caller. The stored bytes use the CSAP §2.1 ordering
// (viewing key first): 66 bytes (`V ‖ S`, legacy Ethereum-only form) or
// 98 bytes (`V ‖ S ‖ S_ed`, the full cross-chain form). Both work on
// Starknet — its stealth path uses the secp256k1 halves.
//
// On-behalf registration replaces the EIP-712 (EVM) / Ed25519-SigVerify
// (Solana) flows with SNIP-12 typed data validated through the registrant
// account's SRC-6 `is_valid_signature` — on Starknet every registrant is a
// contract account, so the EIP-1271-style path is primary. The registrant
// signs the message hash off-chain; any payer submits it; the current nonce
// is bound into the hash and consumed on success, so a signature authorises
// exactly one registration.

use core::hash::{HashStateExTrait, HashStateTrait};
use core::poseidon::{PoseidonTrait, poseidon_hash_span};
use openzeppelin_utils::cryptography::snip12::{
    StarknetDomain, StructHash, StructHashStarknetDomainImpl,
};
use starknet::{ContractAddress, get_tx_info};

/// SNIP-12 (rev 1) type hash of the on-behalf registration message.
/// `meta_address_hash` is `poseidon_hash_span(Serde(stealth_meta_address))`.
pub const REGISTER_KEYS_TYPE_HASH: felt252 = selector!(
    "\"RegisterKeys\"(\"scheme_id\":\"felt\",\"meta_address_hash\":\"felt\",\"nonce\":\"felt\")",
);

pub const SNIP12_NAME: felt252 = 'Opaque Stealth Registry';
pub const SNIP12_VERSION: felt252 = '1';

#[derive(Copy, Drop, Hash)]
pub struct RegisterKeys {
    pub scheme_id: felt252,
    pub meta_address_hash: felt252,
    pub nonce: felt252,
}

pub impl RegisterKeysStructHash of StructHash<RegisterKeys> {
    fn hash_struct(self: @RegisterKeys) -> felt252 {
        PoseidonTrait::new().update_with(REGISTER_KEYS_TYPE_HASH).update_with(*self).finalize()
    }
}

/// Poseidon commitment to the meta-address bytes (over its Serde felts).
pub fn meta_address_hash(meta: @ByteArray) -> felt252 {
    let mut serialized: Array<felt252> = array![];
    meta.serialize(ref serialized);
    poseidon_hash_span(serialized.span())
}

/// The full SNIP-12 off-chain message hash the registrant account signs:
/// `poseidon('StarkNet Message', domain_hash, registrant, struct_hash)`.
pub fn register_keys_message_hash(
    registrant: ContractAddress, scheme_id: felt252, meta_hash: felt252, nonce: felt252,
) -> felt252 {
    let domain = StarknetDomain {
        name: SNIP12_NAME,
        version: SNIP12_VERSION,
        chain_id: get_tx_info().unbox().chain_id,
        revision: 1,
    };
    let message = RegisterKeys { scheme_id, meta_address_hash: meta_hash, nonce };
    PoseidonTrait::new()
        .update_with('StarkNet Message')
        .update_with(domain.hash_struct())
        .update_with(registrant)
        .update_with(message.hash_struct())
        .finalize()
}

/// Minimal SRC-6 surface used to validate the registrant's signature.
#[starknet::interface]
pub trait ISRC6Account<TContractState> {
    fn is_valid_signature(
        self: @TContractState, hash: felt252, signature: Array<felt252>,
    ) -> felt252;
}

#[starknet::interface]
pub trait IStealthRegistry<TContractState> {
    fn register_keys(
        ref self: TContractState, scheme_id: u256, stealth_meta_address: ByteArray,
    );
    fn register_keys_on_behalf(
        ref self: TContractState,
        registrant: ContractAddress,
        scheme_id: u256,
        stealth_meta_address: ByteArray,
        signature: Array<felt252>,
    );
    fn get_register_keys_message_hash(
        self: @TContractState,
        registrant: ContractAddress,
        scheme_id: u256,
        stealth_meta_address: ByteArray,
    ) -> felt252;
    fn stealth_meta_address_of(
        self: @TContractState, registrant: ContractAddress, scheme_id: u256,
    ) -> ByteArray;
    fn nonce_of(self: @TContractState, registrant: ContractAddress) -> u64;
    fn increment_nonce(ref self: TContractState);
}

#[starknet::contract]
pub mod StealthMetaAddressRegistry {
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};

    #[storage]
    struct Storage {
        /// (registrant, scheme_id) -> CSAP meta-address bytes (empty = unset).
        records: Map<(ContractAddress, u256), ByteArray>,
        /// Consumed by the SNIP-12 on-behalf flow; incrementable to revoke
        /// outstanding signatures (ERC-6538 `incrementNonce` parity).
        nonces: Map<ContractAddress, u64>,
    }

    #[event]
    #[derive(Drop, PartialEq, starknet::Event)]
    pub enum Event {
        StealthMetaAddressSet: StealthMetaAddressSet,
        NonceIncremented: NonceIncremented,
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    pub struct StealthMetaAddressSet {
        #[key]
        pub registrant: ContractAddress,
        #[key]
        pub scheme_id: u256,
        pub stealth_meta_address: ByteArray,
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    pub struct NonceIncremented {
        #[key]
        pub registrant: ContractAddress,
        pub new_nonce: u64,
    }

    #[abi(embed_v0)]
    impl StealthRegistryImpl of super::IStealthRegistry<ContractState> {
        fn register_keys(
            ref self: ContractState, scheme_id: u256, stealth_meta_address: ByteArray,
        ) {
            let registrant = get_caller_address();
            self.store_record(registrant, scheme_id, stealth_meta_address);
        }

        fn register_keys_on_behalf(
            ref self: ContractState,
            registrant: ContractAddress,
            scheme_id: u256,
            stealth_meta_address: ByteArray,
            signature: Array<felt252>,
        ) {
            let nonce = self.nonces.entry(registrant).read();
            let hash = self.message_hash_for(registrant, scheme_id, @stealth_meta_address, nonce);
            let valid = super::ISRC6AccountDispatcherTrait::is_valid_signature(
                super::ISRC6AccountDispatcher { contract_address: registrant }, hash, signature,
            );
            assert(valid == starknet::VALIDATED, 'invalid signature');
            // Consume the nonce so the signature authorises exactly one write.
            self.nonces.entry(registrant).write(nonce + 1);
            self.store_record(registrant, scheme_id, stealth_meta_address);
        }

        fn get_register_keys_message_hash(
            self: @ContractState,
            registrant: ContractAddress,
            scheme_id: u256,
            stealth_meta_address: ByteArray,
        ) -> felt252 {
            let nonce = self.nonces.entry(registrant).read();
            self.message_hash_for(registrant, scheme_id, @stealth_meta_address, nonce)
        }

        fn stealth_meta_address_of(
            self: @ContractState, registrant: ContractAddress, scheme_id: u256,
        ) -> ByteArray {
            self.records.entry((registrant, scheme_id)).read()
        }

        fn nonce_of(self: @ContractState, registrant: ContractAddress) -> u64 {
            self.nonces.entry(registrant).read()
        }

        fn increment_nonce(ref self: ContractState) {
            let registrant = get_caller_address();
            let new_nonce = self.nonces.entry(registrant).read() + 1;
            self.nonces.entry(registrant).write(new_nonce);
            self.emit(NonceIncremented { registrant, new_nonce });
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn store_record(
            ref self: ContractState,
            registrant: ContractAddress,
            scheme_id: u256,
            stealth_meta_address: ByteArray,
        ) {
            let len = stealth_meta_address.len();
            assert(len == 66 || len == 98, 'bad meta-address length');
            self.records.entry((registrant, scheme_id)).write(stealth_meta_address.clone());
            self.emit(StealthMetaAddressSet { registrant, scheme_id, stealth_meta_address });
        }

        fn message_hash_for(
            self: @ContractState,
            registrant: ContractAddress,
            scheme_id: u256,
            stealth_meta_address: @ByteArray,
            nonce: u64,
        ) -> felt252 {
            // scheme ids are small integers (CSAP scheme 1); the SNIP-12
            // message carries the value as a single felt.
            assert(scheme_id.high == 0, 'scheme id too large');
            super::register_keys_message_hash(
                registrant,
                scheme_id.low.into(),
                super::meta_address_hash(stealth_meta_address),
                nonce.into(),
            )
        }
    }
}
