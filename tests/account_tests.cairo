use starknet::{EthAddress};
use snforge_std::{
    start_cheat_signature_global, stop_cheat_signature_global, start_cheat_nonce_global,
    stop_cheat_nonce_global, start_cheat_caller_address, stop_cheat_caller_address,
    start_cheat_resource_bounds_global, stop_cheat_resource_bounds_global,
    start_cheat_transaction_version_global, stop_cheat_transaction_version_global,
};

use rosettacontracts::accounts::base::{IRosettaAccountDispatcherTrait};
use rosettacontracts::accounts::utils::{generate_tx_hash};
use rosettacontracts::rosettanet::{IRosettanetDispatcherTrait};
use rosettacontracts::accounts::types::{RosettanetCall};
use rosettacontracts::utils::decoder::{EVMTypes};
use crate::test_utils::{
    deploy_account_from_rosettanet, register_function, deploy_funded_account_from_rosettanet,
    deploy_account_from_existing_rosettanet, manipulate_rosettanet_registry, deploy_erc20,
    deploy_specificly_funded_account_from_rosettanet, deploy_weth, create_resource_bounds,
};
use rosettacontracts::mocks::erc20::{IMockERC20DispatcherTrait};
use rosettacontracts::mocks::weth::{IMockWETHDispatcherTrait};

use rosettacontracts::accounts::errors::AccountErrors::*;

#[test]
fn test_signature_validation_eip1559() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0xfea45e666ba85f417463f9c7bd9c0ab532c3a9bf29bb09c73fed760364f6c405;
    let signature = array![
        0x1d9fb6b7ce01fda249f0f0a3ac00d3a2,
        0x15bd08d62685c22d30a57d611a643c76,
        0x290a42b030be68a236a837dff15a77c3,
        0x57f669dd35be2b984cd4ab48c0a0c588,
        0x1c,
        0x1,
        0x0,
    ];

    let (_, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
fn test_signature_validation_legacy() {
    // Legacy tx hash
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0x04af5100efeb883338fbc81c2c167f0907889760af4002d45b378ee093a882ac;
    let signature = array![
        0x34e45bcf8ecf1ca3bd52ea7a93ef7d31,
        0x74d09bfb0301645262106184fee00493,
        0xd43382bdf45a8c272bcf101e9fcfa716,
        0x55296d9471410304362b0e4fd0ab7e06,
        0x1b,
        0x0,
        0x0,
    ];
    let (_, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'Invalid signature')]
fn test_signature_validation_legacy_invalid() {
    // Legacy tx hash
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0x04af5100efeb883338fbc81c2c167f0907889760af4002d45b378ee093a882ac;
    let signature = array![
        0x34e44bcf8ecf1ca3bd52ea7a93ef7d31,
        0x74d09bfb0301645262106184fee00493,
        0xd43382bdf45a8c272bcf101e9fcfa716,
        0x55296d9471410304362b0e4fd0ab7e06,
        0x1b,
        0x0,
        0x0,
    ];
    let (_, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'Invalid signature')]
fn test_signature_validation_eip1559_invalid() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let unsigned_tx_hash: u256 = 0x105d7b8d7c9fe830c123f2d99c01e09bfa7d902cb3b5afee409cf3dca533f52b;
    let signature: Array<felt252> = array![
        0x3188ef10bf8469101d372e6b0960ed2b,
        0x02bb74ffa5465b3dda0e353bbc3b6be3,
        0x436c4cd167829819ce46024300e24d6d,
        0x0739cb3999ae6842528ce5d8ec01a7fc,
        0x1b,
        0x0,
        0x0,
    ]; // r.low, r.high, s.low, s.high, v

    let (_, account) = deploy_account_from_rosettanet(eth_address);

    assert_eq!(account.is_valid_signature(unsigned_tx_hash, signature), starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'ACC: nonsupported tx type')]
fn test_transaction_validation_unsupported_tx_type() {
    let eth_address: EthAddress = 0x30ffDf2c33b929F749afE49D7aBf3f4B8D399B40.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 1,
        to: 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee.try_into().unwrap(),
        nonce: 4,
        max_priority_fee_per_gas: 158129478,
        max_fee_per_gas: 50742206232,
        gas_price: 0,
        gas_limit: 21000,
        value: 1000000000000000000,
        calldata: array![].span(),
    };

    let signature = array![
        0x8bba859d5730ac5dc9363a3c4cb101dd,
        0xb688a37cc78e902c27509be951232f94,
        0xb0e9624f16c50a779023870d75cad640,
        0x5c7bf7e431e816e08e9329edcc014fe4,
        0x1c,
        0xde0b6b3a7640000,
        0x0,
    ];
    let unsigned_tx_hash: u256 = 0xbf4c65f85c5317b99259cedee5a69aacae0551f5a265d4df53714c9deb5add55;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    account.__validate__(tx);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
fn test_eip1559_transaction_validation_value_transfer_only() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 2,
        to: 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee.try_into().unwrap(),
        nonce: 0,
        max_priority_fee_per_gas: 158129478,
        max_fee_per_gas: 50742206232,
        gas_price: 0,
        gas_limit: 21000,
        value: 1000000000000000000,
        calldata: array![].span(),
    };

    let signature = array![
        0x6f7a6066f3627f849b8a375c13e4f3e2,
        0x3067d2d98a667ba070f5ea280b217dbd,
        0xd92f9c8cb6427767d42612e94464c01b,
        0x63fcefda762f5f2c3c4396756dd585d9,
        0x1b,
        0xde0b6b3a7640000,
        0x0,
    ];
    let unsigned_tx_hash: u256 = 0x939bef480a462e4cc5a8cf57801237a54a4b306c1bac8da102dbec5ecb1ee1c6;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_resource_bounds_global(create_resource_bounds(21000, 50742206232));
    let validation = account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_legacy_transaction_validation_value_transfer_only() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 0,
        to: 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee.try_into().unwrap(),
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_price: 152345,
        gas_limit: 21000,
        value: 1000000000000000000,
        calldata: array![].span(),
    };

    let signature = array![
        0x81616b7dba2a4db9c40cb8c5adb8520c,
        0xda3125b81fe3548011c59cc2cc45159e,
        0xc93773a0f51c0405ec10d8970945cd90,
        0x4bee80dfddbb70fb94aab57cda65a754,
        0x1b,
        0xde0b6b3a7640000,
        0x0,
    ];

    let unsigned_tx_hash: u256 = 0x010f366b2188db8818f41583d22301a0499636470ec8ae21f8353543256d0924;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_resource_bounds_global(create_resource_bounds(21000, 152345));
    let validation = account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'ACC: invalid nonce')]
fn test_legacy_transaction_wrong_nonce() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 0,
        to: 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
            .try_into()
            .unwrap(), // we dont need to deploy account, we only check validation here
        nonce: 77,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_price: 45235,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0xa9059cbb,
            0x000000000000000000000000b756b1bc,
            0x042fa70d85ee84eab646a3b438a285ee,
            0x00000000000000000000000000000000,
            0x000000000000000000000000000f4240,
        ]
            .span(),
    };

    let signature = array![
        0xa242563ffb0771ea806fc160e0665583,
        0x6279ab9f3ee976a5a0a47538ca5383be,
        0xc8cfbaab64f80111d375dce2c52e896c,
        0x419770f60d92f921b9d5434941b3891a,
        0x1c,
        0x0,
        0x0,
    ];
    let unsigned_tx_hash: u256 = 0xb2e837d9ee9c8d6e9bb40a9cf18eac862c6b4f9b0bbe5d2437abb9dcade6bab2;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(234234);
    start_cheat_signature_global(signature.span());
    start_cheat_resource_bounds_global(create_resource_bounds(21000, 45235));
    start_cheat_transaction_version_global(3);
    let validation = account.__validate__(tx);
    stop_cheat_transaction_version_global();
    stop_cheat_resource_bounds_global();
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'ACC: invalid tx version')]
fn test_legacy_transaction_wrong_tx_version() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 0,
        to: 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
            .try_into()
            .unwrap(), // we dont need to deploy account, we only check validation here
        nonce: 77,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_price: 45235,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0xa9059cbb,
            0x000000000000000000000000b756b1bc,
            0x042fa70d85ee84eab646a3b438a285ee,
            0x00000000000000000000000000000000,
            0x000000000000000000000000000f4240,
        ]
            .span(),
    };

    let signature = array![
        0xa242563ffb0771ea806fc160e0665583,
        0x6279ab9f3ee976a5a0a47538ca5383be,
        0xc8cfbaab64f80111d375dce2c52e896c,
        0x419770f60d92f921b9d5434941b3891a,
        0x1c,
        0x0,
        0x0,
    ];
    let unsigned_tx_hash: u256 = 0xb2e837d9ee9c8d6e9bb40a9cf18eac862c6b4f9b0bbe5d2437abb9dcade6bab2;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_resource_bounds_global(create_resource_bounds(21000, 400000));
    start_cheat_transaction_version_global(2);
    let validation = account.__validate__(tx);
    stop_cheat_transaction_version_global();
    stop_cheat_resource_bounds_global();
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'ACC: max price unit wrong')]
fn test_legacy_transaction_wrong_gas() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 0,
        to: 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
            .try_into()
            .unwrap(), // we dont need to deploy account, we only check validation here
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_price: 45235,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0xa9059cbb,
            0x000000000000000000000000b756b1bc,
            0x042fa70d85ee84eab646a3b438a285ee,
            0x00000000000000000000000000000000,
            0x000000000000000000000000000f4240,
        ]
            .span(),
    };

    let signature = array![
        0xe37dc7f258742f6e867ee4ea8abc0e0a,
        0xea457961c92ad1a94e731eaf3d83d22,
        0x503edc6c37b1c8eb30dc6af0ab0ab41e,
        0x37b5691bc537a800ba90d70316e5a456,
        0x1b,
        0x0,
        0x0,
    ];
    let unsigned_tx_hash: u256 = 0x5b0ec3543f28c8d0929929446718b191fdf68a87ee42da6ac9e8849fa817b6f1;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_resource_bounds_global(create_resource_bounds(21000, 400000));
    let validation = account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_legacy_transaction_validation_calldata() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 0,
        to: 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
            .try_into()
            .unwrap(), // we dont need to deploy account, we only check validation here
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_price: 45235,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0xa9059cbb,
            0x000000000000000000000000b756b1bc,
            0x042fa70d85ee84eab646a3b438a285ee,
            0x00000000000000000000000000000000,
            0x000000000000000000000000000f4240,
        ]
            .span(),
    };

    let signature = array![
        0xe37dc7f258742f6e867ee4ea8abc0e0a,
        0xea457961c92ad1a94e731eaf3d83d22,
        0x503edc6c37b1c8eb30dc6af0ab0ab41e,
        0x37b5691bc537a800ba90d70316e5a456,
        0x1b,
        0x0,
        0x0,
    ];
    let unsigned_tx_hash: u256 = 0x5b0ec3543f28c8d0929929446718b191fdf68a87ee42da6ac9e8849fa817b6f1;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_resource_bounds_global(create_resource_bounds(21000, 45235));
    let validation = account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_eip1559_transaction_validation_calldata() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 2,
        to: 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
            .try_into()
            .unwrap(), // we dont need to deploy account, we only check validation here
        nonce: 0,
        max_priority_fee_per_gas: 1638611,
        max_fee_per_gas: 18610805637,
        gas_price: 0,
        gas_limit: 45439,
        value: 0,
        calldata: array![
            0xa9059cbb,
            0x000000000000000000000000b756b1bc,
            0x042fa70d85ee84eab646a3b438a285ee,
            0x00000000000000000000000000000000,
            0x000000000000000000000000000f4240,
        ]
            .span(),
    };

    let signature = array![
        0x2d346079783f0657d3fe825ee4cc951d,
        0x542ea2752ad4f97508932ac7a577b3ab,
        0x682c824cc19339131c2e6191cfb90f45,
        0x78dcaab615b5451f2594a2d3acf75bf1,
        0x1b,
        0x0,
        0x0,
    ];
    let unsigned_tx_hash: u256 = 0xd4cf95b8d1f68b8393e78b5bd95c1abcea1afd063628cef7dc2066af962a799a;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(1);
    start_cheat_signature_global(signature.span());
    start_cheat_resource_bounds_global(create_resource_bounds(45439, 18610805637));
    let validation = account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_transaction_validation_calldata_and_value_transfer() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let target: EthAddress = 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 2,
        to: target, // we dont need to deploy account, we only check validation here
        nonce: 0,
        max_priority_fee_per_gas: 13620452,
        max_fee_per_gas: 46700970384,
        gas_price: 0,
        gas_limit: 28156,
        value: 10000000000000000,
        calldata: array![0xd0e30db0].span(),
    };

    let signature = array![
        0xf2f3fcbf0a9bb12e444f8d63e99a00bb,
        0xbdb69810975e2dfd3bc79631916885a2,
        0xafd200e43de6d5d01a9d0ed49a5c0da6,
        0x369fc72b369c0ca44488608b2dd20e8a,
        0x1c,
        0x2386f26fc10000,
        0x0,
    ];
    let unsigned_tx_hash: u256 = 0xc8d78654ba51d1f9889df81bbed149391209ba71e787a5291a71a2438180ac39;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_resource_bounds_global(create_resource_bounds(28156, 46700970384));
    let validation = account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'Invalid signature')]
fn test_legacy_transaction_validation_calldata_invalid_signature() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 0,
        to: 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238
            .try_into()
            .unwrap(), // we dont need to deploy account, we only check validation here
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_price: 45235,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0xa9059cbb,
            0x000000000000000000000000b756b1bc,
            0x042fa70d85ee84eab646a3b438a285ee,
            0x00000000000000000000000000000000,
            0x000000000000000000000000000f4240,
        ]
            .span(),
    };

    let signature = array![
        0xa242563ffb0771ea806fc160e0665584,
        0x6279ab9f3ee976a5a0a47538ca5383be,
        0xc8cfbaab64f80111d375dce2c52e896c,
        0x419770f60d92f921b9d5434941b3891a,
        0x1c,
        0x0,
        0x0,
    ];
    //let unsigned_tx_hash: u256 =
    //0xb2e837d9ee9c8d6e9bb40a9cf18eac862c6b4f9b0bbe5d2437abb9dcade6bab2;

    //let generated_tx_hash: u256 = generate_tx_hash(tx);
    //assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_resource_bounds_global(create_resource_bounds(21000, 45235));
    account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
#[should_panic(expected: 'ACC: value on sign mismatch')]
fn test_execute_value_transfer_wrong_value_on_sig() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let receiver_address: EthAddress = 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee
        .try_into()
        .unwrap();
    let tx = RosettanetCall {
        to: receiver_address,
        tx_type: 2,
        nonce: 59,
        max_priority_fee_per_gas: 158129478,
        max_fee_per_gas: 50742206232,
        gas_price: 0,
        gas_limit: 21000,
        value: 1,
        calldata: array![].span(),
    };

    let signature = array![
        0x1d9fb6b7ce01fda249f0f0a3ac00d3a2,
        0x15bd08d62685c22d30a57d611a643c76,
        0x290a42b030be68a236a837dff15a77c3,
        0x57f669dd35be2b984cd4ab48c0a0c588,
        0x1c,
        0x1FFF,
        0x1FFF,
    ];

    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);

    let _ = deploy_account_from_existing_rosettanet(receiver_address, rosettanet.contract_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(execution, array![array![].span()]);
}

#[test]
#[should_panic(expected: 'ERC20: insufficient balance')]
fn test_execute_value_transfer_not_enough_balance() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let receiver_address: EthAddress = 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee
        .try_into()
        .unwrap();
    let tx = RosettanetCall {
        to: receiver_address,
        tx_type: 2,
        nonce: 59,
        max_priority_fee_per_gas: 158129478,
        max_fee_per_gas: 50742206232,
        gas_price: 0,
        gas_limit: 21000,
        value: 1,
        calldata: array![].span(),
    };

    let signature = array![
        0x1d9fb6b7ce01fda249f0f0a3ac00d3a2,
        0x15bd08d62685c22d30a57d611a643c76,
        0x290a42b030be68a236a837dff15a77c3,
        0x57f669dd35be2b984cd4ab48c0a0c588,
        0x1c,
        0x1,
        0x0,
    ];

    let (rosettanet, account) = deploy_account_from_rosettanet(eth_address);

    let _ = deploy_account_from_existing_rosettanet(receiver_address, rosettanet.contract_address);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(execution, array![array![].span()]);
}

#[test]
fn test_execute_value_transfer() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let receiver_address: EthAddress = 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee
        .try_into()
        .unwrap();
    let tx = RosettanetCall {
        to: receiver_address,
        tx_type: 2,
        nonce: 59,
        max_priority_fee_per_gas: 158129478,
        max_fee_per_gas: 50742206232,
        gas_price: 0,
        gas_limit: 21000,
        value: 1,
        calldata: array![].span(),
    };

    let signature = array![
        0x1d9fb6b7ce01fda249f0f0a3ac00d3a2,
        0x15bd08d62685c22d30a57d611a643c76,
        0x290a42b030be68a236a837dff15a77c3,
        0x57f669dd35be2b984cd4ab48c0a0c588,
        0x1c,
        0x1,
        0x0,
    ];

    let (rosettanet, account, strk) = deploy_funded_account_from_rosettanet(eth_address);

    let receiver = deploy_account_from_existing_rosettanet(
        receiver_address, rosettanet.contract_address,
    );
    assert_eq!(strk.balance_of(receiver.contract_address), 0);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(strk.balance_of(receiver.contract_address), 1);
    assert_eq!(execution, array![array![].span()]);
}

#[test]
fn test_execute_erc20_transfer_receiver_not_registered() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let erc20_eth: EthAddress = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238.try_into().unwrap();
    let tx = RosettanetCall {
        to: erc20_eth, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 77,
        max_priority_fee_per_gas: 1638611,
        max_fee_per_gas: 18610805637,
        gas_price: 0,
        gas_limit: 45439,
        value: 0,
        calldata: array![
            0xa9059cbb,
            0x000000000000000000000000b756b1bc,
            0x042fa70d85ee84eab646a3b438a285ee,
            0x00000000000000000000000000000000,
            0x000000000000000000000000000f4240,
        ]
            .span(),
    };

    let signature = array![
        0x6ddb2d56bf6b847af890501e1a44bf19,
        0xcc8d431460ddb8f3a228d1cdfe069be1,
        0xdbeff1d03deae8859e16491d3c7d4b89,
        0x62b4b646ff3c09068d04eb98eec04413,
        0x1b,
        0x0,
        0x0,
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);
    register_function(
        rosettanet,
        "transfer(address,uint256)",
        array![EVMTypes::Address, EVMTypes::Uint256].span(),
    );
    let erc20 = deploy_erc20();
    erc20.mint(account.contract_address, 1500000);

    manipulate_rosettanet_registry(rosettanet.contract_address, erc20.contract_address, erc20_eth);

    let fallback_account_address = rosettanet
        .get_starknet_address_with_fallback(
            0xb756b1bc042fa70d85ee84eab646a3b438a285ee.try_into().unwrap(),
        );

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(erc20.balance_of(fallback_account_address), 0xf4240);
}

#[test]
fn test_execute_erc20_transfer_legacy() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let erc20_eth: EthAddress = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238.try_into().unwrap();
    let tx = RosettanetCall {
        to: erc20_eth, // we dont need to deploy account, we only check validation here
        tx_type: 0,
        nonce: 23,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_price: 39191,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0xa9059cbb,
            0x000000000000000000000000b756b1bc,
            0x042fa70d85ee84eab646a3b438a285ee,
            0x00000000000000000000000000000000,
            0x000000000000000000000000000f4240,
        ]
            .span() // sends 1000000 tokens
    };

    let signature = array![
        0x8dbeaba3292e8da5751fe696af7248f3,
        0xad1e5653ac0873d540479f7a9619e94b,
        0x5142bfaa68b44d063e3ca9a1e71dff21,
        0x6dcaafc193c6f1ad9eb684ab8d87c49b,
        0x1c,
        0x0,
        0x0,
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);
    register_function(
        rosettanet,
        "transfer(address,uint256)",
        array![EVMTypes::Address, EVMTypes::Uint256].span(),
    );

    let receiver = deploy_account_from_existing_rosettanet(
        0xb756b1bc042fa70d85ee84eab646a3b438a285ee.try_into().unwrap(), rosettanet.contract_address,
    );

    let erc20 = deploy_erc20();

    erc20.mint(account.contract_address, 1500000); // Fund account

    manipulate_rosettanet_registry(rosettanet.contract_address, erc20.contract_address, erc20_eth);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(erc20.balance_of(receiver.contract_address), 1000000);
    assert_eq!(erc20.balance_of(account.contract_address), 500000);
    assert_eq!(execution, array![array![0x1].span()]); // erc20 transfer returns true
}

#[test]
fn test_execute_erc20_transfer() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let erc20_eth: EthAddress = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238.try_into().unwrap();
    let tx = RosettanetCall {
        to: erc20_eth, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 77,
        max_priority_fee_per_gas: 1638611,
        max_fee_per_gas: 18610805637,
        gas_price: 0,
        gas_limit: 45439,
        value: 0,
        calldata: array![
            0xa9059cbb,
            0x000000000000000000000000b756b1bc,
            0x042fa70d85ee84eab646a3b438a285ee,
            0x00000000000000000000000000000000,
            0x000000000000000000000000000f4240,
        ]
            .span() // sends 1000000 tokens
    };

    let signature = array![
        0x6ddb2d56bf6b847af890501e1a44bf19,
        0xcc8d431460ddb8f3a228d1cdfe069be1,
        0xdbeff1d03deae8859e16491d3c7d4b89,
        0x62b4b646ff3c09068d04eb98eec04413,
        0x1b,
        0x0,
        0x0,
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);
    register_function(
        rosettanet,
        "transfer(address,uint256)",
        array![EVMTypes::Address, EVMTypes::Uint256].span(),
    );
    let receiver = deploy_account_from_existing_rosettanet(
        0xb756b1bc042fa70d85ee84eab646a3b438a285ee.try_into().unwrap(), rosettanet.contract_address,
    );

    let erc20 = deploy_erc20();

    erc20.mint(account.contract_address, 1500000); // Fund account

    manipulate_rosettanet_registry(rosettanet.contract_address, erc20.contract_address, erc20_eth);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(erc20.balance_of(receiver.contract_address), 1000000);
    assert_eq!(erc20.balance_of(account.contract_address), 500000);
    assert_eq!(execution, array![array![0x1].span()]); // erc20 transfer returns true
}

#[test]
#[should_panic(expected: 'ERC20: insufficient balance')]
fn test_execute_erc20_transfer_exceeds_balance() {
    // Example usdc transfer
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let erc20_eth: EthAddress = 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238.try_into().unwrap();
    let tx = RosettanetCall {
        to: erc20_eth, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 77,
        max_priority_fee_per_gas: 1638611,
        max_fee_per_gas: 18610805637,
        gas_price: 0,
        gas_limit: 45439,
        value: 0,
        calldata: array![
            0xa9059cbb,
            0x000000000000000000000000b756b1bc,
            0x042fa70d85ee84eab646a3b438a285ee,
            0x00000000000000000000000000000000,
            0x000000000000000000000000000f4240,
        ]
            .span() // sends 1000000 tokens
    };

    let signature = array![
        0x6ddb2d56bf6b847af890501e1a44bf19,
        0xcc8d431460ddb8f3a228d1cdfe069be1,
        0xdbeff1d03deae8859e16491d3c7d4b89,
        0x62b4b646ff3c09068d04eb98eec04413,
        0x1b,
        0x0,
        0x0,
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);
    register_function(
        rosettanet,
        "transfer(address,uint256)",
        array![EVMTypes::Address, EVMTypes::Uint256].span(),
    );

    deploy_account_from_existing_rosettanet(
        0xb756b1bc042fa70d85ee84eab646a3b438a285ee.try_into().unwrap(), rosettanet.contract_address,
    );

    let erc20 = deploy_erc20();

    erc20.mint(account.contract_address, 500000); // Fund account but not enough

    manipulate_rosettanet_registry(rosettanet.contract_address, erc20.contract_address, erc20_eth);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
fn test_execute_value_transfer_and_call() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let target: EthAddress = 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9.try_into().unwrap();
    let tx = RosettanetCall {
        to: target, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 96,
        max_priority_fee_per_gas: 13620452,
        max_fee_per_gas: 46700970384,
        gas_price: 0,
        gas_limit: 28156,
        value: 10000000000000000,
        calldata: array![0xd0e30db0].span(),
    };

    let signature = array![
        0x6032b3e971d4c254e37e5ee46891d63e,
        0xd09052bb95e3f38497e93e934b96860f,
        0x3ba19d6fd34eaf4ad1b155397ecd056a,
        0x2344e2307c2852957a9bf7d25d0d7dbf,
        0x1c,
        0x2386F26FC10000,
        0x0,
    ];
    let (rosettanet, account, strk) = deploy_specificly_funded_account_from_rosettanet(
        eth_address, 20000000000000000_u256,
    );

    register_function(rosettanet, "deposit()", array![].span());

    let weth = deploy_weth();
    manipulate_rosettanet_registry(rosettanet.contract_address, weth.contract_address, target);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(strk.balance_of(weth.contract_address), tx.value);
    assert_eq!(strk.balance_of(account.contract_address), 20000000000000000_u256 - tx.value);
    assert_eq!(weth.last_deposit(), tx.value);
}

#[test]
#[should_panic(expected: 'ACC: multicall value non zero')]
fn test_multicall_with_value() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let feature_target: EthAddress = 0x4645415455524553.try_into().unwrap();
    let tx = RosettanetCall {
        to: feature_target, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 96,
        max_priority_fee_per_gas: 13620452,
        max_fee_per_gas: 46700970384,
        gas_price: 0,
        gas_limit: 28156,
        value: 10,
        calldata: array![0x76971d7f].span(),
    };

    let signature = array![
        0x6032b3e971d4c254e37e5ee46891d63e,
        0xd09052bb95e3f38497e93e934b96860f,
        0x3ba19d6fd34eaf4ad1b155397ecd056a,
        0x2344e2307c2852957a9bf7d25d0d7dbf,
        0x1c,
        0x2386F26FC10000,
        0x0,
    ];
    let (_, account, _) = deploy_specificly_funded_account_from_rosettanet(
        eth_address, 20000000000000000_u256,
    );

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
#[should_panic(expected: 'ACC: unimplemented feature')]
fn test_multicall_wrong_selector() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let feature_target: EthAddress = 0x4645415455524553.try_into().unwrap();
    let tx = RosettanetCall {
        to: feature_target, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 96,
        max_priority_fee_per_gas: 13620452,
        max_fee_per_gas: 46700970384,
        gas_price: 0,
        gas_limit: 28156,
        value: 10,
        calldata: array![0xabcabcab].span(),
    };

    let signature = array![
        0x6032b3e971d4c254e37e5ee46891d63e,
        0xd09052bb95e3f38497e93e934b96860f,
        0x3ba19d6fd34eaf4ad1b155397ecd056a,
        0x2344e2307c2852957a9bf7d25d0d7dbf,
        0x1c,
        0x2386F26FC10000,
        0x0,
    ];
    let (_, account, _) = deploy_specificly_funded_account_from_rosettanet(
        eth_address, 20000000000000000_u256,
    );

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
fn test_validation_real_data_failing() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let target: EthAddress = 0xbec5832bd3f642d090891b4991da42fa4d5d9e2d.try_into().unwrap();
    let tx = RosettanetCall {
        to: target,
        tx_type: 2,
        nonce: 0,
        max_priority_fee_per_gas: 55,
        max_fee_per_gas: 55,
        gas_price: 0,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0x095ea7b3,
            0x0,
            0x1,
            0xffffffffffffffffffffffffffffffff,
            0xffffffffffffffffffffffffffffffff,
        ]
            .span(),
    };
    let signature = array![
        0xf27b86a27ae43862e6e64081580df755,
        0x8ee75676ef46e4d6ac52208cb1aefcc,
        0x26bf4fe05e755d37cb6f0897d63bd3c3,
        0x593a0778ec047fb37433dd7b3afa8b5c,
        0x1b,
        0x0,
        0x0,
    ];
    let (rosettanet, account, _) = deploy_funded_account_from_rosettanet(eth_address);
    deploy_account_from_existing_rosettanet(target, rosettanet.contract_address);

    let unsigned_tx_hash: u256 = 0xa884f6c9d26ae3506a565e4ffa48941d12044648e39c25dd87a7e97760499d19;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    start_cheat_resource_bounds_global(create_resource_bounds(21000, 55));
    account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
fn test_validate_multicall_transaction() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        to: eth_address, // Target is same bcs its feature call
        tx_type: 2,
        nonce: 0,
        max_priority_fee_per_gas: 55,
        max_fee_per_gas: 55,
        gas_price: 0,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0x76971d7f,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000020,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000002,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000040,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000100,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000123123,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000456456,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000002,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000111,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000222,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000888888,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000999999,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000002,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000654,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000321,
        ]
            .span(),
    };
    let signature = array![
        0x9e9516edb1ea8f724a0b86e5eb50ec9a,
        0x137a221f07c16e6534b55c60ed3aa2d3,
        0x3da8a0978e492fcc0493864d69963785,
        0x1e59b7003ad2af3e9561e7d49a217f37,
        0x1b,
        0x0,
        0x0,
    ];
    let (_, account, _) = deploy_funded_account_from_rosettanet(eth_address);

    let unsigned_tx_hash: u256 = 0x9faa1cb60c7989dad181adb1096dd2a61ae16125ebc86017ce9062c0d9da39df;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    start_cheat_resource_bounds_global(create_resource_bounds(21000, 55));
    let validation = account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
#[should_panic(expected: 'Invalid signature')]
fn test_validate_multicall_transaction_wrong_signature() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        to: eth_address, // Target is same bcs its feature call
        tx_type: 2,
        nonce: 0,
        max_priority_fee_per_gas: 55,
        max_fee_per_gas: 55,
        gas_price: 0,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0x76971d7f,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000020,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000002,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000040,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000100,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000123123,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000456456,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000002,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000111,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000222,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000888888,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000999999,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000002,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000654,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000321,
        ]
            .span(),
    };
    let signature = array![
        0x42607df1d32b89c5c789fa3d5d70f9c9,
        0xf30f73b6dfecb122e9c33e94d8d9c2ec,
        0x7ed1b0a8c87e84909580b659562d251f,
        0x711d7b42f0c91ee717f4770dff7c7f00,
        0x1b,
        0x0,
        0x0,
    ];
    let (_, account, _) = deploy_funded_account_from_rosettanet(eth_address);

    let unsigned_tx_hash: u256 = 0x9faa1cb60c7989dad181adb1096dd2a61ae16125ebc86017ce9062c0d9da39df;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(1);
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    start_cheat_resource_bounds_global(create_resource_bounds(21000, 55));
    let validation = account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
#[ignore] // Ignore for now, probably strk deployed address changed bcs of snforge updated
fn test_execute_multicall_transaction() {
    let eth_address: EthAddress = 0x30ffDf2c33b929F749afE49D7aBf3f4B8D399B40.try_into().unwrap();
    let strk_receiver_1_felt: felt252 = 0x555666;
    let strk_receiver_2_felt: felt252 = 0x111222;
    // We dont use eth addresses on multicall
    let (_, account, strk) = deploy_funded_account_from_rosettanet(eth_address);

    let tx = RosettanetCall {
        to: eth_address,
        tx_type: 2,
        nonce: 59,
        max_priority_fee_per_gas: 55,
        max_fee_per_gas: 55,
        gas_price: 0,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0x76971d7f,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000020,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000002,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000040,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000120,
            0x00a551825f2e7d5313ee03b1dfe40e2a,
            0x7b78b27a7fed40fa17aec27e010bfa96,
            0x0083afd3f4caedc6eebf44246fe54e38,
            0xc95e3179a5ec9ea81740eca5b482d12e,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000003,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000555666,
            0x00000000000000000000000000000000,
            0x000000000000000000000000000005dc,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000000,
            0x00a551825f2e7d5313ee03b1dfe40e2a,
            0x7b78b27a7fed40fa17aec27e010bfa96,
            0x0083afd3f4caedc6eebf44246fe54e38,
            0xc95e3179a5ec9ea81740eca5b482d12e,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000003,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000111222,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000bb8,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000000,
        ]
            .span(),
    };

    let signature = array![
        0xd03d6316a9c7a356fe828ff6f480e13,
        0x67a799adb268ebc0a3a0341d630e75a5,
        0xa67278e4452483d2a00060209eb90af5,
        0x6e815045d6e8dba8cfca66127f36410c,
        0x1b,
        0x0,
        0x0,
    ];

    let unsigned_tx_hash: u256 = 0x942981158784d2e2f45f187022e9112fd987d666276d74b76ce656c9cbad80da;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(strk.balance_of(strk_receiver_1_felt.try_into().unwrap()), 1500);
    assert_eq!(strk.balance_of(strk_receiver_2_felt.try_into().unwrap()), 3000);
    assert_eq!(execution, array![array![0x1].span(), array![0x1].span()]);
}

#[test]
fn test_multicall_validate_actual_values() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        to: eth_address,
        tx_type: 2,
        nonce: 0,
        max_priority_fee_per_gas: 55,
        max_fee_per_gas: 55,
        gas_price: 0,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0x76971d7f,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000020,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000002,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000040,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000120,
            0x049d36570d4e46f48e99674bd3fcc846,
            0x44ddd6b96f7c741b1562b82f9e004dc7,
            0x0083afd3f4caedc6eebf44246fe54e38,
            0xc95e3179a5ec9ea81740eca5b482d12e,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000003,
            0x07d33254052409c04510c3652bc5be56,
            0x56f1eff1b131c7c031592e3fa73f1f70,
            0x00000000000000000000000000000000,
            0x0000000000000000000221b262dd8000,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000000,
            0x04c5772d1914fe6ce891b64eb35bf352,
            0x2aeae1315647314aac58b01137607f3f,
            0x00e5b455a836c7a254df57ed39d023d4,
            0x6b641b331162c6c0b369647056655409,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000003,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000455448,
            0x000000000000000000000000e4306a06,
            0xb19fdc04fdf98cf3c00472f29254c0e1,
            0x00000000000000000000000000000000,
            0x000000000000000000038d7ea4c68000,
        ]
            .span(),
    };

    let signature = array![
        0x8e05eeda7b6eee7d51a6368316315985,
        0x53b6fa69365273bab7d01ae6b0b7cd5a,
        0x173e3c1c4714cff739fdfdd750444e2a,
        0xe23fc865ebd6156e3b9da79bf099614,
        0x1b,
        0x0,
        0x0,
    ];

    let (_, account, _) = deploy_funded_account_from_rosettanet(eth_address);

    let unsigned_tx_hash: u256 = 0xae202a1f7ecbdfbcb9707991617274c211bb89db235854d015a6ff5ee4151137;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    start_cheat_resource_bounds_global(create_resource_bounds(21000, 55));
    let validation = account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_eip1559_transaction_validation_first_transaction_different_nonce() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let tx = RosettanetCall {
        tx_type: 2,
        to: 0xB756B1BC042Fa70D85Ee84eab646a3b438A285Ee.try_into().unwrap(),
        nonce: 0,
        max_priority_fee_per_gas: 55,
        max_fee_per_gas: 55,
        gas_price: 0,
        gas_limit: 21000,
        value: 100,
        calldata: array![].span(),
    };

    let signature = array![
        0xd88f1332001bc417b7e35d96e1f5243b,
        0x3572e8cf3accc63b5e9e3d87501b4a,
        0x20104c9d60f58499afda372c7b19724,
        0x5bb1ee81c2669729c255ac84b9c9ef65,
        0x1b,
        0x64,
        0x0,
    ];
    let unsigned_tx_hash: u256 = 0x025c58064f05e7f76019d7c754a3f9257ba4567538d1fad14749903945028087;

    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    let (_, account) = deploy_account_from_rosettanet(eth_address);
    assert_eq!(account.get_ethereum_address(), eth_address);

    start_cheat_nonce_global(1);
    start_cheat_signature_global(signature.span());
    start_cheat_resource_bounds_global(create_resource_bounds(21000, 55));
    let validation = account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(validation, starknet::VALIDATED);
}

#[test]
fn test_legacy_multicall_validation() {}

#[test]
fn test_eip1559_validate_second_nonce() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let target: EthAddress = 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9.try_into().unwrap();
    let tx = RosettanetCall {
        to: target, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 96, // No check on execution so this will be executed.
        max_priority_fee_per_gas: 13620452,
        max_fee_per_gas: 46700970384,
        gas_price: 0,
        gas_limit: 28156,
        value: 10000000000000000,
        calldata: array![0xd0e30db0].span(),
    };

    let signature = array![
        0x6032b3e971d4c254e37e5ee46891d63e,
        0xd09052bb95e3f38497e93e934b96860f,
        0x3ba19d6fd34eaf4ad1b155397ecd056a,
        0x2344e2307c2852957a9bf7d25d0d7dbf,
        0x1c,
        0x2386F26FC10000,
        0x0,
    ];
    let (rosettanet, account, strk) = deploy_specificly_funded_account_from_rosettanet(
        eth_address, 20000000000000000_u256,
    );

    register_function(rosettanet, "deposit()", array![].span());

    let weth = deploy_weth();
    manipulate_rosettanet_registry(rosettanet.contract_address, weth.contract_address, target);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(strk.balance_of(weth.contract_address), tx.value);
    assert_eq!(strk.balance_of(account.contract_address), 20000000000000000_u256 - tx.value);
    assert_eq!(weth.last_deposit(), tx.value);

    let target: EthAddress = 0x7b79995e5f793A07Bc00c21412e50Ecae098E7f9.try_into().unwrap();
    let tx = RosettanetCall {
        to: target, // we dont need to deploy account, we only check validation here
        tx_type: 2,
        nonce: 1,
        max_priority_fee_per_gas: 13620452,
        max_fee_per_gas: 46700970384,
        gas_price: 0,
        gas_limit: 28156,
        value: 10000000000000000,
        calldata: array![0xd0e30db0].span(),
    };

    let signature = array![
        0x86070d15a0fd24ac6f4ef4dade8c31f7,
        0xd8369d5232a767a74d12e10f5db0fd24,
        0xe53b184c32d903ce217cb2d3c1fb6c27,
        0x350e5ac1c99163e07e9a7326ed166b3f,
        0x1b,
        0x2386f26fc10000,
        0x0,
    ];

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    start_cheat_resource_bounds_global(create_resource_bounds(28156, 46700970384));
    account.__validate__(tx);
    stop_cheat_resource_bounds_global();
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();
}

#[test]
fn test_eip1559_multicall_execute() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let strk_receiver_1_felt: felt252 = 0x555666;
    let strk_receiver_2_felt: felt252 = 0x111222;

    let (_, account, strk) = deploy_funded_account_from_rosettanet(eth_address);

    let tx = RosettanetCall {
        to: 0x0000000000000000000000004645415455524553.try_into().unwrap(),
        tx_type: 2,
        nonce: 1,
        max_priority_fee_per_gas: 13620452,
        max_fee_per_gas: 46700970384,
        gas_price: 0,
        gas_limit: 28156,
        value: 0,
        calldata: array![
            0x76971d7f,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000020,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000002,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000040,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000120,
            0x02494fd97dcb965ece595376ebefa989,
            0x07116210eed818a14970fbaa52b88255,
            0x02f0b3c5710379609eb5495f1ecd348c,
            0xb28167711b73609fe565a72734550354,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000003,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000555666,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000002710,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000000,
            0x02494fd97dcb965ece595376ebefa989,
            0x07116210eed818a14970fbaa52b88255,
            0x02f0b3c5710379609eb5495f1ecd348c,
            0xb28167711b73609fe565a72734550354,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000003,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000111222,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000004e20,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000000
        ]
            .span(),
    };

    let signature = array![
        0x89a2a6052b877ac33bba35de642edb97,0x14e7a5bb625cb9c5f7cc2e6fbb808974, 0xee2ec7d35170dffd1282e08cc468cc0e,0x4ba16945f9c9239e1f082f2fd6efe9d, 0x1b, 0x0,0x0
    ];

    let weth = deploy_weth();

    let unsigned_tx_hash: u256 = 0x9c04d3e908ccac13516704a96ce2dcc9d45520b5b763886b9f2b2bec2c0471be;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(weth.balance_of(strk_receiver_1_felt.try_into().unwrap()), 10000);
    assert_eq!(weth.balance_of(strk_receiver_2_felt.try_into().unwrap()), 20000);
    assert_eq!(execution, array![array![].span(), array![].span()]);
}

#[test]
fn test_legacy_multicall_execute() {
    let eth_address: EthAddress = 0xE4306a06B19Fdc04FDf98cF3c00472f29254c0e1.try_into().unwrap();
    let strk_receiver_1_felt: felt252 = 0x555666;
    let strk_receiver_2_felt: felt252 = 0x111222;

    let (_, account, strk) = deploy_funded_account_from_rosettanet(eth_address);

    let tx = RosettanetCall {
        to: 0x0000000000000000000000004645415455524553.try_into().unwrap(),
        tx_type: 0,
        nonce: 0,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: 0,
        gas_price: 45235,
        gas_limit: 21000,
        value: 0,
        calldata: array![
            0x76971d7f,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000020,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000002,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000040,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000120,
            0x02494fd97dcb965ece595376ebefa989,
            0x07116210eed818a14970fbaa52b88255,
            0x02f0b3c5710379609eb5495f1ecd348c,
            0xb28167711b73609fe565a72734550354,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000003,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000555666,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000002710,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000000,
            0x02494fd97dcb965ece595376ebefa989,
            0x07116210eed818a14970fbaa52b88255,
            0x02f0b3c5710379609eb5495f1ecd348c,
            0xb28167711b73609fe565a72734550354,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000060,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000003,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000111222,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000004e20,
            0x00000000000000000000000000000000,
            0x00000000000000000000000000000000
        ]
            .span(),
    };

    let signature = array![
        0x948a693f899dd8be371b65689f5feaa,0xb79c80e04f0bcc92ff21ac02da45950a, 0xc5f9e9cf61218a825736499ee134dbd8,0x139807befd878ad8e8d4752b2a2e2d14, 0x1c, 0x0,0x0
    ];

    let weth = deploy_weth();

    let unsigned_tx_hash: u256 = 0x86f3bfe692fc58818e8453be90a763069d54cffa4dc94fb57a84f43b2d3bf459;
    let generated_tx_hash: u256 = generate_tx_hash(tx);
    assert_eq!(generated_tx_hash, unsigned_tx_hash);

    start_cheat_nonce_global(tx.nonce.into());
    start_cheat_signature_global(signature.span());
    start_cheat_caller_address(account.contract_address, starknet::contract_address_const::<0>());
    let execution = account.__execute__(tx);
    stop_cheat_caller_address(account.contract_address);
    stop_cheat_signature_global();
    stop_cheat_nonce_global();

    assert_eq!(weth.balance_of(strk_receiver_1_felt.try_into().unwrap()), 10000);
    assert_eq!(weth.balance_of(strk_receiver_2_felt.try_into().unwrap()), 20000);
    assert_eq!(execution, array![array![].span(), array![].span()]);
}
// TODO NONCE DIFFERENT VALIDATION
// TODO MULTICALL LEGACY VALIDATION
// TODO: Multicall execution tests


