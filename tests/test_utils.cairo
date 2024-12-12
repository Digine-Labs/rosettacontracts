use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, start_cheat_caller_address, stop_cheat_caller_address};
use starknet::{ClassHash, ContractAddress, EthAddress};
use core::pedersen::PedersenTrait;
use core::hash::{HashStateExTrait, HashStateTrait};
use rosettacontracts::rosettanet::{
    IRosettanetDispatcher, IRosettanetDispatcherTrait
};
use rosettacontracts::accounts::base::{IRosettaAccountDispatcher};
use rosettacontracts::mocks::erc20::{IMockERC20Dispatcher, IMockERC20DispatcherTrait};

fn compute_hash_on_elements(data: Span<felt252>) -> felt252 {
    let mut state = PedersenTrait::new(0);
    for elem in data {
        state = state.update_with(*elem);
    };

    state.update_with(data.len()).finalize()
}

pub fn declare_erc20() -> ClassHash {
    let class = declare("MockERC20").unwrap().contract_class();
    *class.class_hash
}

pub fn declare_account() -> ClassHash {
    let class = declare("RosettaAccount").unwrap().contract_class();
    *class.class_hash
}

pub fn deploy_and_set_account() -> IRosettanetDispatcher {
    let contract = declare("Rosettanet").unwrap().contract_class();
    let native_currency = deploy_erc20();
    let (contract_address, _) = contract.deploy(@array![developer().into(), native_currency.contract_address.into()]).unwrap();
    let dispatcher = IRosettanetDispatcher { contract_address };
    let account_class = declare_account();

    start_cheat_caller_address(dispatcher.contract_address, developer());
    dispatcher.set_account_class(account_class);
    stop_cheat_caller_address(dispatcher.contract_address);

    dispatcher
}

pub fn developer() -> ContractAddress { 
    starknet::contract_address_const::<1>()
}

pub fn eth_account() -> EthAddress {
    0x12345678.try_into().unwrap()
}

pub fn deploy_erc20() -> IMockERC20Dispatcher {
    let class = declare("MockERC20").unwrap().contract_class();
    let (contract_address, _) = class.deploy(@array![]).unwrap();
    IMockERC20Dispatcher { contract_address }
}

pub fn deploy_rosettanet() -> IRosettanetDispatcher {
    let contract = declare("Rosettanet").unwrap().contract_class();
    let native_currency = deploy_erc20();
    let (contract_address, _) = contract.deploy(@array![developer().into(), native_currency.contract_address.into()]).unwrap();
    IRosettanetDispatcher { contract_address }
}

pub fn deploy_account_from_rosettanet(eth_address: EthAddress) -> (IRosettanetDispatcher, IRosettaAccountDispatcher) {
    let account_class = declare_account();

    let rosettanet = deploy_rosettanet();

    start_cheat_caller_address(rosettanet.contract_address, developer());
    rosettanet.set_account_class(account_class);
    stop_cheat_caller_address(rosettanet.contract_address);

    let account = rosettanet.deploy_account(eth_address);

    (rosettanet, IRosettaAccountDispatcher { contract_address: account })
}

pub fn deploy_account_from_existing_rosettanet(eth_address: EthAddress, rosettanet_contract: ContractAddress) -> IRosettaAccountDispatcher {
    let rosettanet = IRosettanetDispatcher { contract_address: rosettanet_contract };

    let account = rosettanet.deploy_account(eth_address);
    IRosettaAccountDispatcher { contract_address: account }
}

pub fn deploy_funded_account_from_rosettanet(eth_address: EthAddress) -> (IRosettanetDispatcher, IRosettaAccountDispatcher, IMockERC20Dispatcher) {
    let (rosettanet, account) = deploy_account_from_rosettanet(eth_address);

    let native_currency_address = rosettanet.native_currency();

    let strk = IMockERC20Dispatcher { contract_address: native_currency_address};

    strk.mint(account.contract_address, 1000000);

    assert_eq!(strk.balance_of(account.contract_address), 1000000);

    (rosettanet, account, strk)
}

// Forcely matches these addresses
pub fn manipulate_rosettanet_registry(rosettanet_contract: ContractAddress, sn_address: ContractAddress, eth_address: EthAddress) {
    // Currently we use function in registry
    // After alpha version, we have to remove that function. So this function also needs to be rewritten with store function in foundry
    start_cheat_caller_address(rosettanet_contract, developer());
    IRosettanetDispatcher { contract_address: rosettanet_contract }.register_matched_addresses(sn_address, eth_address);
    stop_cheat_caller_address(rosettanet_contract);

}

#[test]
fn test_storage_manipulation() {
    let rosettanet = deploy_rosettanet();

    let eth_address: EthAddress = 0x123.try_into().unwrap();
    let sn_address: ContractAddress = 0xFFF.try_into().unwrap();

    manipulate_rosettanet_registry(rosettanet.contract_address, sn_address, eth_address);

    assert_eq!(rosettanet.get_starknet_address(eth_address), sn_address);
    assert_eq!(rosettanet.get_ethereum_address(sn_address), eth_address);
}