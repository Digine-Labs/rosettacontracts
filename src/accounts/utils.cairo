use starknet::secp256_trait::{Signature, signature_from_vrs};
use starknet::{EthAddress};
use crate::accounts::encoding::{Eip1559Transaction, deserialize_bytes, deserialize_u256_span, bytes_from_felts};
use crate::utils::constants::{POW_2_250};
use crate::utils::traits::SpanDefault;
use crate::utils::bytes::{U8SpanExTrait, ByteArrayExTrait};
use starknet::eth_signature::{verify_eth_signature};

pub const CHAIN_ID: u64 = 2933; // TODO: Correct it

#[derive(Copy, Drop, Serde)]
pub struct EthSignature {
    pub r: u256,
    pub s: u256,
}

#[derive(Copy, Drop, Serde)]
pub struct RosettanetSignature {
    pub v: u32, // 27 or 28
    pub r: u256,
    pub s: u256,
}

#[derive(Copy, Drop, Clone, Serde)]
pub struct RosettanetCall {
    pub to: EthAddress, // This has to be this account address for multicalls
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub value: u256, // To be used future
    pub calldata: Span<felt252>,
    pub directives: Span<bool>, // We use this directives to figure out u256 splitting happened in element in same index For ex if 3rd element of this array is true, it means 3rd elem is low, 4th elem is high of u256
    pub target_function: Span<felt252> // Function name and types to used to calculate eth func signature
}

pub fn parse_transaction(call: RosettanetCall) -> Eip1559Transaction {
    let calldata = call.calldata;
    let directives = call.directives;

    let mut merged_calldata = merge_u256s(calldata, directives); // Bunun içinde test yaz
    let deserialized_calldata = deserialize_u256_span(ref merged_calldata); // TODO: check is correct Loop ile byte ayırmalı 
    // TODO: u256 span decodesi içi test yaz

    let eip1559 = Eip1559Transaction {
        chain_id: CHAIN_ID,
        nonce: call.nonce,
        max_priority_fee_per_gas: call.max_priority_fee_per_gas,
        max_fee_per_gas: call.max_fee_per_gas,
        gas_limit: call.gas_limit,
        to: call.to,
        value: call.value,
        access_list: array![].span(),
        input: deserialized_calldata
    };

    eip1559
}

// Merges u256s coming from calldata according to directives
pub fn merge_u256s(calldata: Span<felt252>, directives: Span<bool>) -> Span<u256> {
    assert(calldata.len() == directives.len(), 'R-AU-1 Sanity check fails');
    let mut merged_array = ArrayTrait::<u256>::new();
    let mut index = 0;

    while index < calldata.len() {
        let current_directive = *directives.at(index);
        if(current_directive) {
            let element = u256 {
                low: (*calldata.at(index)).try_into().unwrap(), // We can assume it always fits u128 limit since u256s already splitted low highs
                high: (*calldata.at(index + 1)).try_into().unwrap()
            };
            merged_array.append(element);
            index +=1;
        } else {
            merged_array.append((*calldata.at(index)).into());
        }
        index +=1;
    };

    merged_array.span()
}

#[inline(always)]
pub fn compute_hash(encoded_tx_data: Span<u8>) -> u256 {
    encoded_tx_data.compute_keccak256_hash()
}


pub fn is_valid_eth_signature(
    msg_hash: u256, eth_address: EthAddress, signature: RosettanetSignature
) -> bool {
    let secp256_signature: Signature = signature_from_vrs(signature.v, signature.r, signature.s);
    verify_eth_signature(msg_hash, secp256_signature, eth_address); // TODO: how to check and revert?
    true
}

// Validates target function is correct and returns sn selector
// target_function is array of felts that holds ascii of function name and params
pub fn validate_target_function(target_function: Span<felt252>, calldata: Span<felt252>) -> felt252 {
    let function_signature = *calldata.at(0);
    assert(function_signature.into() <= 0xFFFFFFFF_u256, 'Calldata first param high');

    let target_function_eth_signature = eth_function_signature_from_felts(target_function);
    let function_signature_bytes = deserialize_bytes(function_signature, 4);

    assert(target_function_eth_signature == function_signature_bytes, 'calldata target mismatch');
    0 // Todo
}

// func: ascii function name selector transfer(address,uint256)
// returns sn entrypoint
pub fn calculate_sn_entrypoint(func: Span<u8>) -> felt252 {
    let mut func_clone = func;
    let func_name = parse_function_name(ref func_clone);

    let keccak_hash: u256 = func_name.compute_keccak256_hash(); // full name

    let (_, sn_keccak) =  DivRem::div_rem(keccak_hash, POW_2_250.try_into().unwrap());

    sn_keccak.try_into().unwrap()
}

// Returns only function name from ethereum function selector
// transfer(address,uint256) -> transfer
fn parse_function_name(ref func: Span<u8>) -> Span<u8> {
    let mut name = array![];

    loop {
        match func.pop_front() {
            Option::None => { break; },
            Option::Some(val) => {
                if(*val == 0x28) {
                    break;
                }
                name.append(*val);
            }
        };
    };

    name.span()
}

// Returns function signature 
// Pass array of felts containing ascii of function name
// Check parse_function_name tests for examples
fn eth_function_signature_from_felts(func: Span<felt252>) -> Span<u8> {
    let mut func_clone = func;
    let bytes = bytes_from_felts(ref func_clone);

    calculate_eth_function_signature(bytes)
}


pub fn calculate_eth_function_signature(func: Span<u8>) -> Span<u8> {
    let mut ba = Default::default();
    ba.append_word(func.compute_keccak256_hash().high.into(), 16);
    let bytes = ba.into_bytes_without_initial_zeroes();
    
    array![*bytes.at(0), *bytes.at(1), *bytes.at(2), *bytes.at(3)].span()
}


#[cfg(test)]
mod tests {
    use crate::accounts::utils::{merge_u256s, calculate_eth_function_signature, parse_function_name, eth_function_signature_from_felts, calculate_sn_entrypoint};
    use crate::accounts::encoding::{bytes_from_felts};
    use crate::utils::bytes::{ByteArrayExTrait};

    #[test]
    fn test_sn_entrypoint() {
        // transfer(address, uint256)
        let mut fn_name_arr = array![0x7472616E7366657228616464726573732C75696E7432353629].span();
        let mut function_name = bytes_from_felts(ref fn_name_arr);

        let entry_point:felt252 = calculate_sn_entrypoint(function_name);
        assert_eq!(entry_point, 0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e);
    }

    #[test]
    fn test_eth_fn_signature() {
        // transfer
        let mut fn_name_arr = array![0x7472616E7366657228616464726573732C75696E7432353629].span();
        let signature = eth_function_signature_from_felts(fn_name_arr);

        assert_eq!(*signature.at(0), 0xa9);
        assert_eq!(*signature.at(1), 0x05);
        assert_eq!(*signature.at(2), 0x9c);
        assert_eq!(*signature.at(3), 0xbb);
    }

    #[test]
    fn test_eth_fn_signature_long() {
        // transferFrom
        let mut fn_name_arr = array![0x7472616E7366657246726F6D28616464726573732C616464726573732C, 0x75696E7432353629].span();
        let signature = eth_function_signature_from_felts(fn_name_arr);

        assert_eq!(*signature.at(0), 0x23);
        assert_eq!(*signature.at(1), 0xb8);
        assert_eq!(*signature.at(2), 0x72);
        assert_eq!(*signature.at(3), 0xdd);
    }

    #[test]
    fn test_parse_function_name() {
        // transfer
        let mut fn_name_arr = array![0x7472616E7366657228616464726573732C75696E7432353629].span();
        let mut function_name = bytes_from_felts(ref fn_name_arr);

        let val = parse_function_name(ref function_name);
        assert_eq!(val.len(), 8);
        assert_eq!(*val.at(0), 0x74);
        assert_eq!(*val.at(1), 0x72);
        assert_eq!(*val.at(2), 0x61);
        assert_eq!(*val.at(3), 0x6E);
        assert_eq!(*val.at(4), 0x73);
        assert_eq!(*val.at(5), 0x66);
        assert_eq!(*val.at(6), 0x65);
        assert_eq!(*val.at(7), 0x72);
    }

    #[test]
    fn test_parse_function_name_long() {
        // transferFrom
        let mut arr = array![0x7472616E7366657246726F6D28616464726573732C616464726573732C, 0x75696E7432353629].span();
        let mut function_name = bytes_from_felts(ref arr);

        let val = parse_function_name(ref function_name);
        assert_eq!(val.len(), 12);
        assert_eq!(*val.at(0), 0x74);
        assert_eq!(*val.at(1), 0x72);
        assert_eq!(*val.at(2), 0x61);
        assert_eq!(*val.at(3), 0x6E);
        assert_eq!(*val.at(4), 0x73);
        assert_eq!(*val.at(5), 0x66);
        assert_eq!(*val.at(6), 0x65);
        assert_eq!(*val.at(7), 0x72);
        assert_eq!(*val.at(8), 0x46);
        assert_eq!(*val.at(9), 0x72);
        assert_eq!(*val.at(10), 0x6F);
        assert_eq!(*val.at(11), 0x6D);
    }

    #[test]
    fn test_eth_function_signature_transfer() {
        let bytes = "transfer(address,uint256)".into_bytes_without_initial_zeroes();
        let signature = calculate_eth_function_signature(bytes);

        assert_eq!(*signature.at(0), 0xa9);
        assert_eq!(*signature.at(1), 0x05);
        assert_eq!(*signature.at(2), 0x9c);
        assert_eq!(*signature.at(3), 0xbb);
    }

    #[test]
    fn test_eth_function_signature_transfer_from() {
        let bytes = "transferFrom(address,address,uint256)".into_bytes_without_initial_zeroes();
        let signature = calculate_eth_function_signature(bytes);

        assert_eq!(*signature.at(0), 0x23);
        assert_eq!(*signature.at(1), 0xb8);
        assert_eq!(*signature.at(2), 0x72);
        assert_eq!(*signature.at(3), 0xdd);
    }

    #[test]
    fn test_eth_function_signature_approve() {
        let bytes = "approve(address,uint256)".into_bytes_without_initial_zeroes();
        let signature = calculate_eth_function_signature(bytes);

        assert_eq!(*signature.at(0), 0x09);
        assert_eq!(*signature.at(1), 0x5e);
        assert_eq!(*signature.at(2), 0xa7);
        assert_eq!(*signature.at(3), 0xb3);
    }

    #[test]
    fn test_eth_function_signature_total_supply() {
        let bytes = "totalSupply()".into_bytes_without_initial_zeroes();
        let signature = calculate_eth_function_signature(bytes);

        assert_eq!(*signature.at(0), 0x18);
        assert_eq!(*signature.at(1), 0x16);
        assert_eq!(*signature.at(2), 0x0d);
        assert_eq!(*signature.at(3), 0xdd);
    }

    #[test]
    fn test_merge_one() {
        let data = array![0xFF, 0xAB].span();
        let directive = array![true, false].span();

        let merged = merge_u256s(data, directive);

        assert_eq!(*merged.at(0), u256 {low: 0xFF, high: 0xAB});
    }

    #[test]
    fn test_merge_two() {
        let data = array![0xFF, 0xAB, 0x123123, 0x0].span();
        let directive = array![true, false, true, false].span();

        let merged = merge_u256s(data, directive);

        assert_eq!(*merged.at(0), u256 {low: 0xFF, high: 0xAB});
        assert_eq!(*merged.at(1), u256 {low: 0x123123, high: 0x0});
    }

    #[test]
    #[should_panic(expected: 'R-AU-1 Sanity check fails')]
    fn test_merge_wrong_sanity() {
        let data = array![0xFF, 0xAB, 0x123123, 0x0].span();
        let directive = array![true, false, true, false, true].span();

        let merged = merge_u256s(data, directive);

        assert_eq!(*merged.at(0), u256 {low: 0xFF, high: 0xAB});
        assert_eq!(*merged.at(1), u256 {low: 0x123123, high: 0x0});
    }
}