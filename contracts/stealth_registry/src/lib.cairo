// CSAP stealth meta-address registry — Starknet port.
//
// Mirrors ERC-6538 storage (`registrant -> (scheme_id -> meta bytes)`) and the
// Solana `stealth_registry` semantics. Registration is self-service: the
// registrant is the caller. The stored bytes use the CSAP §2.1 ordering
// (viewing key first): 66 bytes (`V ‖ S`, legacy Ethereum-only form) or
// 98 bytes (`V ‖ S ‖ S_ed`, the full cross-chain form). Both work on
// Starknet — its stealth path uses the secp256k1 halves.
//
// On-behalf registration (SNIP-12 typed data through the registrant account's
// SRC-6 `is_valid_signature`, replacing the EIP-712 / Ed25519-SigVerify flows
// of the other chains) is specified in spec/starknet-integration.md §7.2 and
// lands as a follow-up; the nonce storage it consumes is already declared so
// the layout does not change underneath deployed instances.

use starknet::ContractAddress;

#[starknet::interface]
pub trait IStealthRegistry<TContractState> {
    fn register_keys(
        ref self: TContractState, scheme_id: u256, stealth_meta_address: ByteArray,
    );
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
            let len = stealth_meta_address.len();
            assert(len == 66 || len == 98, 'bad meta-address length');
            let registrant = get_caller_address();
            self.records.entry((registrant, scheme_id)).write(stealth_meta_address.clone());
            self.emit(StealthMetaAddressSet { registrant, scheme_id, stealth_meta_address });
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
}
