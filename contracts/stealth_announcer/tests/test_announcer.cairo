// Announcement emission + input bounds, using CSAP canonical vector 1
// (spec/CSAP.md Test Vectors): the ephemeral public key, view tag 225, and
// the 20-byte stealth identifier all come from the cross-validated fixture.

use snforge_std::{
    ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait, declare, spy_events,
    start_cheat_caller_address,
};
use starknet::{ContractAddress, EthAddress};
use stealth_announcer::{
    IStealthAnnouncerDispatcher, IStealthAnnouncerDispatcherTrait, StealthAnnouncer,
};

fn bytes(vals: Span<u8>) -> ByteArray {
    let mut out: ByteArray = Default::default();
    for v in vals {
        out.append_byte(*v);
    }
    out
}

/// CSAP canonical vector 1 `ephemeral_public_key` (33-byte compressed secp256k1).
fn canonical_ephemeral() -> ByteArray {
    bytes(
        array![
            0x02, 0xb9, 0x5c, 0x24, 0x9d, 0x84, 0xf4, 0x17, 0xe3, 0xe3, 0x95, 0xa1, 0x27, 0x42,
            0x54, 0x28, 0xb5, 0x40, 0x67, 0x1c, 0xc1, 0x58, 0x81, 0xeb, 0x82, 0x8c, 0x17, 0xb7,
            0x22, 0xa5, 0x3f, 0xc5, 0x99,
        ]
            .span(),
    )
}

/// CSAP canonical vector 1 `stealth_address` (the scanner-matching identifier).
fn canonical_stealth_address() -> EthAddress {
    0xa5847a467208cbcd5d238369865a90716310183a.try_into().unwrap()
}

fn deploy() -> IStealthAnnouncerDispatcher {
    let class = declare("StealthAnnouncer").unwrap().contract_class();
    let (address, _) = class.deploy(@array![]).unwrap();
    IStealthAnnouncerDispatcher { contract_address: address }
}

#[test]
fn test_announce_emits_eip5564_shaped_event() {
    let announcer = deploy();
    let caller: ContractAddress = 'sender'.try_into().unwrap();
    start_cheat_caller_address(announcer.contract_address, caller);

    let mut spy = spy_events();
    // metadata[0] = view tag 225 (0xe1) from the canonical vector.
    announcer.announce(1, canonical_stealth_address(), canonical_ephemeral(), bytes(array![0xe1].span()));

    spy
        .assert_emitted(
            @array![
                (
                    announcer.contract_address,
                    StealthAnnouncer::Event::Announcement(
                        StealthAnnouncer::Announcement {
                            scheme_id: 1,
                            stealth_address: canonical_stealth_address(),
                            caller,
                            ephemeral_pub_key: canonical_ephemeral(),
                            metadata: bytes(array![0xe1].span()),
                        },
                    ),
                ),
            ],
        );
}

#[test]
#[should_panic(expected: 'bad ephemeral key length')]
fn test_short_ephemeral_key_is_rejected() {
    let announcer = deploy();
    let mut short: ByteArray = Default::default();
    let mut i = 0_u32;
    while i != 32 {
        short.append_byte(0x02);
        i += 1;
    }
    announcer.announce(1, canonical_stealth_address(), short, bytes(array![0xe1].span()));
}

#[test]
#[should_panic(expected: 'empty metadata')]
fn test_empty_metadata_is_rejected() {
    let announcer = deploy();
    announcer.announce(1, canonical_stealth_address(), canonical_ephemeral(), Default::default());
}
