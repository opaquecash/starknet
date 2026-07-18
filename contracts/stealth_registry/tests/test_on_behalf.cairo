// On-behalf registration: SNIP-12 message hash validated through the
// registrant account's SRC-6 `is_valid_signature`, nonce consumed on success.
//
// The registrant here is a mock account that approves exactly one hash — the
// registry's flow (hash construction, SRC-6 dispatch, nonce consumption,
// replay rejection) is what is under test; real secp256k1 signature
// validation is the stealth_account class's (OZ-audited) concern.

use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
};
use starknet::ContractAddress;
use stealth_registry::{
    IStealthRegistryDispatcher, IStealthRegistryDispatcherTrait,
};

#[starknet::interface]
trait IMockAccount<TContractState> {
    fn approve_hash(ref self: TContractState, hash: felt252);
    fn is_valid_signature(
        self: @TContractState, hash: felt252, signature: Array<felt252>,
    ) -> felt252;
}

#[starknet::contract]
mod MockSrc6Account {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        approved: felt252,
    }

    #[abi(embed_v0)]
    impl MockAccountImpl of super::IMockAccount<ContractState> {
        fn approve_hash(ref self: ContractState, hash: felt252) {
            self.approved.write(hash);
        }

        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            if hash == self.approved.read() && signature.len() != 0 {
                starknet::VALIDATED
            } else {
                0
            }
        }
    }
}

fn filled(len: u32, byte: u8) -> ByteArray {
    let mut out: ByteArray = Default::default();
    let mut i = 0;
    while i != len {
        out.append_byte(byte);
        i += 1;
    }
    out
}

fn setup() -> (IStealthRegistryDispatcher, IMockAccountDispatcher, ContractAddress) {
    let registry_class = declare("StealthMetaAddressRegistry").unwrap().contract_class();
    let (registry_address, _) = registry_class.deploy(@array![]).unwrap();
    let account_class = declare("MockSrc6Account").unwrap().contract_class();
    let (account_address, _) = account_class.deploy(@array![]).unwrap();

    let registry = IStealthRegistryDispatcher { contract_address: registry_address };
    let account = IMockAccountDispatcher { contract_address: account_address };
    // The submitter is an unrelated payer, never the registrant.
    let payer: ContractAddress = 'payer'.try_into().unwrap();
    start_cheat_caller_address(registry_address, payer);
    (registry, account, account_address)
}

#[test]
fn test_on_behalf_registers_and_consumes_nonce() {
    let (registry, account, registrant) = setup();
    let meta = filled(98, 0xab);

    let hash = registry.get_register_keys_message_hash(registrant, 1, meta.clone());
    account.approve_hash(hash);

    registry.register_keys_on_behalf(registrant, 1, meta.clone(), array![0x1]);

    assert(registry.stealth_meta_address_of(registrant, 1) == meta, 'record not written');
    assert(registry.nonce_of(registrant) == 1, 'nonce not consumed');
}

#[test]
#[should_panic(expected: 'invalid signature')]
fn test_on_behalf_signature_cannot_replay() {
    let (registry, account, registrant) = setup();
    let meta = filled(98, 0xab);

    let hash = registry.get_register_keys_message_hash(registrant, 1, meta.clone());
    account.approve_hash(hash);
    registry.register_keys_on_behalf(registrant, 1, meta.clone(), array![0x1]);

    // The nonce moved, so the previously-approved hash no longer matches.
    registry.register_keys_on_behalf(registrant, 1, meta, array![0x1]);
}

#[test]
#[should_panic(expected: 'invalid signature')]
fn test_on_behalf_rejects_unapproved_hash() {
    let (registry, _, registrant) = setup();
    registry.register_keys_on_behalf(registrant, 1, filled(98, 0xab), array![0x1]);
}

#[test]
#[should_panic(expected: 'invalid signature')]
fn test_on_behalf_binds_the_meta_bytes() {
    let (registry, account, registrant) = setup();

    // Signature over one meta-address must not authorise a different one.
    let hash = registry.get_register_keys_message_hash(registrant, 1, filled(98, 0xab));
    account.approve_hash(hash);
    registry.register_keys_on_behalf(registrant, 1, filled(98, 0xcd), array![0x1]);
}

#[test]
#[should_panic(expected: 'invalid signature')]
fn test_increment_nonce_revokes_outstanding_signature() {
    let (registry, account, registrant) = setup();
    let meta = filled(98, 0xab);

    let hash = registry.get_register_keys_message_hash(registrant, 1, meta.clone());
    account.approve_hash(hash);

    // The registrant invalidates the signature before the payer submits it.
    start_cheat_caller_address(registry.contract_address, registrant);
    registry.increment_nonce();
    let payer: ContractAddress = 'payer'.try_into().unwrap();
    start_cheat_caller_address(registry.contract_address, payer);

    registry.register_keys_on_behalf(registrant, 1, meta, array![0x1]);
}

#[test]
#[should_panic(expected: 'bad meta-address length')]
fn test_on_behalf_enforces_meta_length() {
    let (registry, account, registrant) = setup();
    let meta = filled(97, 0xab);
    let hash = registry.get_register_keys_message_hash(registrant, 1, meta.clone());
    account.approve_hash(hash);
    registry.register_keys_on_behalf(registrant, 1, meta, array![0x1]);
}