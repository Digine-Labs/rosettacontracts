use snforge_std::{start_cheat_caller_address, stop_cheat_caller_address};

use rosettacontracts::rosettanet::{IRosettanetDispatcherTrait};
use starknet::EthAddress;

use crate::test_utils::{
    developer, eth_account, deploy_rosettanet, deploy_and_set_account, deploy_weth,
    deploy_account_from_rosettanet,
};


#[test]
fn rosettanet_deploy_initial_dev() {
    let rosettanet = deploy_rosettanet();

    assert_eq!(rosettanet.developer(), starknet::contract_address_const::<1>());
}

#[test]
#[should_panic(expected: 'only dev')]
fn rosettanet_non_dev_set_class() {
    let rosettanet = deploy_rosettanet();

    rosettanet.set_account_class(1.try_into().unwrap());
}

#[test]
fn rosettanet_set_class() {
    let rosettanet = deploy_rosettanet();

    start_cheat_caller_address(rosettanet.contract_address, developer());
    rosettanet.set_account_class(1.try_into().unwrap());
    stop_cheat_caller_address(rosettanet.contract_address);

    assert_eq!(rosettanet.latest_class(), 1.try_into().unwrap());
}

#[test]
fn rosettanet_check_precalculated_address() {
    let rosettanet = deploy_and_set_account();

    let precalculated_address = rosettanet.precalculate_starknet_account(eth_account());

    let deployed_account = rosettanet.deploy_account(eth_account());

    assert_eq!(precalculated_address, deployed_account);
}

#[test]
#[should_panic]
#[ignore] // Fail cannot be handled??
fn rosettanet_redeploy_same_account() {
    let rosettanet = deploy_and_set_account();

    let precalculated_address = rosettanet.precalculate_starknet_account(eth_account());

    let deployed_account = rosettanet.deploy_account(eth_account());

    assert_eq!(precalculated_address, deployed_account);
    rosettanet.deploy_account(eth_account());
}

#[test]
fn rosettanet_register_contract() {
    let rosettanet = deploy_rosettanet();

    start_cheat_caller_address(
        rosettanet.contract_address, starknet::contract_address_const::<1>(),
    );
    let weth = deploy_weth();
    rosettanet.register_contract(weth.contract_address);
    stop_cheat_caller_address(rosettanet.contract_address);

    let eth_address = rosettanet.get_ethereum_address(weth.contract_address);

    assert_ne!(rosettanet.get_starknet_address(eth_address), 0.try_into().unwrap());
}

#[test]
#[should_panic(expected: 'Contract already registered')]
fn rosettanet_register_existing_contract() {
    let rosettanet = deploy_rosettanet();

    start_cheat_caller_address(
        rosettanet.contract_address, starknet::contract_address_const::<1>(),
    );
    let weth = deploy_weth();
    rosettanet.register_contract(weth.contract_address);
    rosettanet.register_contract(weth.contract_address);
    stop_cheat_caller_address(rosettanet.contract_address);
}

#[test]
#[should_panic(expected: 'Contract is not deployed')]
fn rosettanet_register_non_deployed_contract() {
    let rosettanet = deploy_rosettanet();

    start_cheat_caller_address(
        rosettanet.contract_address, starknet::contract_address_const::<1>(),
    );

    rosettanet.register_contract(1.try_into().unwrap());
    stop_cheat_caller_address(rosettanet.contract_address);
}

#[test]
#[should_panic(expected: 'Class is account')]
fn rosettanet_register_account_class_as_contract() {
    let eth_address: EthAddress = 123.try_into().unwrap();
    let (rosettanet, account) = deploy_account_from_rosettanet(eth_address);

    start_cheat_caller_address(
        rosettanet.contract_address, starknet::contract_address_const::<1>(),
    );

    rosettanet.register_contract(account.contract_address);
    stop_cheat_caller_address(rosettanet.contract_address);
}
