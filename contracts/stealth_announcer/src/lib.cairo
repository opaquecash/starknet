// CSAP stealth announcer — Starknet port.
//
// Stateless event contract mirroring the EIP-5564 `Announcement` shape used on
// Ethereum (exact match) and Solana (event fields): scheme id, the 20-byte
// EVM-style stealth identifier CSAP uses as the universal scanner-matching key
// (custody is chain-specific, CSAP.md §2.3), the calling account, a 33-byte
// compressed secp256k1 ephemeral public key, and metadata whose first byte is
// the view tag. The Solana implementation's input bounds are enforced
// on-chain; Cairo's `ByteArray` carries the variable-length fields.

use starknet::EthAddress;

#[starknet::interface]
pub trait IStealthAnnouncer<TContractState> {
    fn announce(
        ref self: TContractState,
        scheme_id: u256,
        stealth_address: EthAddress,
        ephemeral_pub_key: ByteArray,
        metadata: ByteArray,
    );
}

#[starknet::contract]
pub mod StealthAnnouncer {
    use starknet::{ContractAddress, EthAddress, get_caller_address};

    #[storage]
    struct Storage {}

    #[event]
    #[derive(Drop, PartialEq, starknet::Event)]
    pub enum Event {
        Announcement: Announcement,
    }

    #[derive(Drop, PartialEq, starknet::Event)]
    pub struct Announcement {
        #[key]
        pub scheme_id: u256,
        #[key]
        pub stealth_address: EthAddress,
        #[key]
        pub caller: ContractAddress,
        pub ephemeral_pub_key: ByteArray,
        pub metadata: ByteArray,
    }

    #[abi(embed_v0)]
    impl StealthAnnouncerImpl of super::IStealthAnnouncer<ContractState> {
        fn announce(
            ref self: ContractState,
            scheme_id: u256,
            stealth_address: EthAddress,
            ephemeral_pub_key: ByteArray,
            metadata: ByteArray,
        ) {
            assert(ephemeral_pub_key.len() == 33, 'bad ephemeral key length');
            assert(metadata.len() >= 1, 'empty metadata');
            self
                .emit(
                    Announcement {
                        scheme_id,
                        stealth_address,
                        caller: get_caller_address(),
                        ephemeral_pub_key,
                        metadata,
                    },
                );
        }
    }
}
