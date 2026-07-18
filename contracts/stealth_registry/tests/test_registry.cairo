use snforge_std::{
    ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait, declare, spy_events,
    start_cheat_caller_address,
};
use starknet::ContractAddress;
use stealth_registry::{
    IStealthRegistryDispatcher, IStealthRegistryDispatcherTrait, StealthMetaAddressRegistry,
};

fn filled(len: u32, byte: u8) -> ByteArray {
    let mut out: ByteArray = Default::default();
    let mut i = 0;
    while i != len {
        out.append_byte(byte);
        i += 1;
    }
    out
}

fn deploy() -> IStealthRegistryDispatcher {
    let class = declare("StealthMetaAddressRegistry").unwrap().contract_class();
    let (address, _) = class.deploy(@array![]).unwrap();
    IStealthRegistryDispatcher { contract_address: address }
}

fn as_caller(
    registry: IStealthRegistryDispatcher, who: felt252,
) -> ContractAddress {
    let address: ContractAddress = who.try_into().unwrap();
    start_cheat_caller_address(registry.contract_address, address);
    address
}

#[test]
fn test_register_and_resolve_98_byte_meta() {
    let registry = deploy();
    let registrant = as_caller(registry, 'alice');
    let meta = filled(98, 0xab);

    let mut spy = spy_events();
    registry.register_keys(1, meta.clone());

    assert(registry.stealth_meta_address_of(registrant, 1) == meta, 'roundtrip mismatch');
    spy
        .assert_emitted(
            @array![
                (
                    registry.contract_address,
                    StealthMetaAddressRegistry::Event::StealthMetaAddressSet(
                        StealthMetaAddressRegistry::StealthMetaAddressSet {
                            registrant, scheme_id: 1, stealth_meta_address: meta,
                        },
                    ),
                ),
            ],
        );
}

#[test]
fn test_register_accepts_legacy_66_byte_meta() {
    let registry = deploy();
    let registrant = as_caller(registry, 'alice');
    let meta = filled(66, 0xcd);
    registry.register_keys(1, meta.clone());
    assert(registry.stealth_meta_address_of(registrant, 1) == meta, 'legacy roundtrip');
}

#[test]
fn test_reregistration_overwrites() {
    let registry = deploy();
    let registrant = as_caller(registry, 'alice');
    registry.register_keys(1, filled(98, 0x11));
    let updated = filled(98, 0x22);
    registry.register_keys(1, updated.clone());
    assert(registry.stealth_meta_address_of(registrant, 1) == updated, 'overwrite failed');
}

#[test]
fn test_records_are_scoped_by_registrant_and_scheme() {
    let registry = deploy();
    let alice = as_caller(registry, 'alice');
    registry.register_keys(1, filled(98, 0xab));

    let empty: ByteArray = Default::default();
    assert(registry.stealth_meta_address_of(alice, 2) == empty, 'scheme not scoped');
    let bob: ContractAddress = 'bob'.try_into().unwrap();
    assert(registry.stealth_meta_address_of(bob, 1) == empty, 'registrant not scoped');
}

#[test]
#[should_panic(expected: 'bad meta-address length')]
fn test_wrong_length_is_rejected() {
    let registry = deploy();
    as_caller(registry, 'alice');
    registry.register_keys(1, filled(97, 0xab));
}

#[test]
fn test_nonce_increments() {
    let registry = deploy();
    let registrant = as_caller(registry, 'alice');
    assert(registry.nonce_of(registrant) == 0, 'fresh nonce');
    registry.increment_nonce();
    assert(registry.nonce_of(registrant) == 1, 'nonce after increment');
}
