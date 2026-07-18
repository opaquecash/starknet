// CSAP stealth account — Starknet custody for a one-time stealth payment.
//
// A Starknet stealth address is the counterfactual deployment address of THIS
// class, salted per payment, whose sole signer is the one-time secp256k1
// stealth public key `P_stealth = S + (s_h mod n)·G` (CSAP.md §2.3). The
// sender and any watch-only scanner compute the address from public
// announcement material via `compute_address(class_hash, salt, [pk.x, pk.y])`;
// only the recipient can reconstruct the matching private scalar
// `p_stealth = (s + s_h) mod n` and therefore spend — never the payer (the
// OPQ-002 failure mode is excluded by construction).
//
// The class embeds OpenZeppelin's audited `EthAccountComponent` unchanged:
// secp256k1 signature validation, SRC-6 `is_valid_signature` (the primary
// on-behalf-registration path on Starknet), and the deploy-account validator.
// It is intentionally NON-upgradeable and adds no storage of its own, so the
// `class_hash` is stable; per spec/starknet-integration.md §7.1 that hash and
// the `[x, y]` constructor-calldata layout are consensus-critical CSAP
// constants — changing the class changes every future stealth address.

#[starknet::contract(account)]
pub mod StealthAccount {
    use openzeppelin_account::EthAccountComponent;
    use openzeppelin_account::interface::EthPublicKey;
    use openzeppelin_introspection::src5::SRC5Component;

    component!(path: EthAccountComponent, storage: eth_account, event: EthAccountEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    // SRC-6 account ABI: __execute__ / __validate__ / is_valid_signature,
    // the deploy-account validator, and public-key views.
    #[abi(embed_v0)]
    impl EthAccountMixinImpl =
        EthAccountComponent::EthAccountMixinImpl<ContractState>;
    impl EthAccountInternalImpl = EthAccountComponent::InternalImpl<ContractState>;
    impl SRC5InternalImpl = SRC5Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        eth_account: EthAccountComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        EthAccountEvent: EthAccountComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
    }

    /// `public_key` is the one-time `P_stealth`. It is the only constructor
    /// argument, so the counterfactual address is a pure function of
    /// (class_hash, salt, [x, y]) and is derivable from the announcement. The
    /// parameter name and position MUST match OZ's `__validate_deploy__` so a
    /// real `deploy_account` transaction validates against the same argument.
    #[constructor]
    fn constructor(ref self: ContractState, public_key: EthPublicKey) {
        self.eth_account.initializer(public_key);
    }
}
