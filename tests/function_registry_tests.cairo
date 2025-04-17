use crate::test_utils::{deploy_rosettanet};
//use rosettacontracts::rosettanet::{IRosettanetDispatcherTrait};
use rosettacontracts::components::function_registry::{
    IFunctionRegistryDispatcherTrait, IFunctionRegistryDispatcher,
};
use rosettacontracts::utils::decoder::{EVMTypes};

#[test]
fn test_register_function() {
    let rosettanet = deploy_rosettanet();

    let function_registry = IFunctionRegistryDispatcher {
        contract_address: rosettanet.contract_address,
    };

    function_registry
        .register_function(
            "transfer(address,uint256)", array![EVMTypes::Address, EVMTypes::Uint256].span(),
        );

    let (entrypoint, directives) = function_registry.get_function_decoding(0xa9059cbb_u32);

    assert_eq!(*directives.at(0), EVMTypes::Address);
    assert_eq!(*directives.at(1), EVMTypes::Uint256);
    assert_eq!(entrypoint, 0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e);
}

#[test]
fn test_register_function_initial_byte_zero() {
    let rosettanet = deploy_rosettanet();
    let function_registry = IFunctionRegistryDispatcher {
        contract_address: rosettanet.contract_address,
    };

    function_registry
        .register_function(
            "approve(address,uint256)", array![EVMTypes::Address, EVMTypes::Uint256].span(),
        );

    let (entrypoint, directives) = function_registry.get_function_decoding(0x095ea7b3_u32);

    assert_eq!(*directives.at(0), EVMTypes::Address);
    assert_eq!(*directives.at(1), EVMTypes::Uint256);
    assert_eq!(entrypoint, 0x0219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c);
}

#[test]
fn print_enums() {
    let mut serialized: Array<felt252> = array![];
    let sample = array![EVMTypes::Address, EVMTypes::Uint256].span();

    sample.serialize(ref serialized);
    for element in serialized {
        println!("{:x}",element);
    };

    let fn_name: ByteArray = "transfer(address,uint256)";
    let mut fn_name_serialized = array![];
    fn_name.serialize(ref fn_name_serialized);
    println!("FN NAME");
    for element in fn_name_serialized {
        println!("{:x}",element);
    };
}