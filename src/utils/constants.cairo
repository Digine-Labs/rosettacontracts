use crate::utils::traits::{U8IntoEthAddress};

// FELT PRIME
// 2^251 + 17 * 2^192 + 1
pub const FELT252_PRIME: u256 = 0x800000000000011000000000000000000000000000000000000000000000001;

// Prefix used to compute the address of a Starknet contract being deployed.
// <https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/starknet/core/os/contract_address/contract_address.cairo>
pub const CONTRACT_ADDRESS_PREFIX: felt252 = 'STARKNET_CONTRACT_ADDRESS';


// BLOCK
pub const BLOCK_GAS_LIMIT: u64 = 7_000_000;
pub const MIN_BASE_FEE_PER_BLOB_GAS: u64 = 1;
// CHAIN_ID = KKRT (0x4b4b5254) in ASCII
pub const CHAIN_ID: u64 = 1263227476;

// STACK
pub const STACK_MAX_DEPTH: usize = 1024;

// CODE
pub const MAX_CODE_SIZE: usize = 0x6000;
pub const MAX_INITCODE_SIZE: usize = 0x6000 * 2;

// KECCAK
// The empty keccak256 hash, Solidity equivalent:
// contract EmptyHash {
//     function emptyHash() public pure returns(bytes32) {
//         return keccak256("");
//     }
// }
// Reproducing link:
// <https://emn178.github.io/online-tools/keccak_256.html?input=&input_type=hex>
pub const EMPTY_KECCAK: u256 = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

pub const BURN_ADDRESS: felt252 = 0xdead;


// Numeric constants
pub const POW_256_0: u128 = 0x1;
pub const POW_256_1: u128 = 0x100;
pub const POW_256_2: u128 = 0x10000;
pub const POW_256_3: u128 = 0x1000000;
pub const POW_256_4: u128 = 0x100000000;
pub const POW_256_5: u128 = 0x10000000000;
pub const POW_256_6: u128 = 0x1000000000000;
pub const POW_256_7: u128 = 0x100000000000000;
pub const POW_256_8: u128 = 0x10000000000000000;
pub const POW_256_9: u128 = 0x1000000000000000000;
pub const POW_256_10: u128 = 0x100000000000000000000;
pub const POW_256_11: u128 = 0x10000000000000000000000;
pub const POW_256_12: u128 = 0x1000000000000000000000000;
pub const POW_256_13: u128 = 0x100000000000000000000000000;
pub const POW_256_14: u128 = 0x10000000000000000000000000000;
pub const POW_256_15: u128 = 0x1000000000000000000000000000000;
pub const POW_256_16: u256 = 0x100000000000000000000000000000000;


pub const POW_256_REV: [
    u256
    ; 17] = [
    0x100000000000000000000000000000000,
    0x1000000000000000000000000000000,
    0x10000000000000000000000000000,
    0x100000000000000000000000000,
    0x1000000000000000000000000,
    0x10000000000000000000000,
    0x100000000000000000000,
    0x1000000000000000000,
    0x10000000000000000,
    0x100000000000000,
    0x1000000000000,
    0x10000000000,
    0x100000000,
    0x1000000,
    0x10000,
    0x100,
    0x1
];

pub const POW_2: [
    u128
    ; 128] = [
    0x1,
    0x2,
    0x4,
    0x8,
    0x10,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    0x10000,
    0x20000,
    0x40000,
    0x80000,
    0x100000,
    0x200000,
    0x400000,
    0x800000,
    0x1000000,
    0x2000000,
    0x4000000,
    0x8000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x100000000,
    0x200000000,
    0x400000000,
    0x800000000,
    0x1000000000,
    0x2000000000,
    0x4000000000,
    0x8000000000,
    0x10000000000,
    0x20000000000,
    0x40000000000,
    0x80000000000,
    0x100000000000,
    0x200000000000,
    0x400000000000,
    0x800000000000,
    0x1000000000000,
    0x2000000000000,
    0x4000000000000,
    0x8000000000000,
    0x10000000000000,
    0x20000000000000,
    0x40000000000000,
    0x80000000000000,
    0x100000000000000,
    0x200000000000000,
    0x400000000000000,
    0x800000000000000,
    0x1000000000000000,
    0x2000000000000000,
    0x4000000000000000,
    0x8000000000000000,
    0x10000000000000000,
    0x20000000000000000,
    0x40000000000000000,
    0x80000000000000000,
    0x100000000000000000,
    0x200000000000000000,
    0x400000000000000000,
    0x800000000000000000,
    0x1000000000000000000,
    0x2000000000000000000,
    0x4000000000000000000,
    0x8000000000000000000,
    0x10000000000000000000,
    0x20000000000000000000,
    0x40000000000000000000,
    0x80000000000000000000,
    0x100000000000000000000,
    0x200000000000000000000,
    0x400000000000000000000,
    0x800000000000000000000,
    0x1000000000000000000000,
    0x2000000000000000000000,
    0x4000000000000000000000,
    0x8000000000000000000000,
    0x10000000000000000000000,
    0x20000000000000000000000,
    0x40000000000000000000000,
    0x80000000000000000000000,
    0x100000000000000000000000,
    0x200000000000000000000000,
    0x400000000000000000000000,
    0x800000000000000000000000,
    0x1000000000000000000000000,
    0x2000000000000000000000000,
    0x4000000000000000000000000,
    0x8000000000000000000000000,
    0x10000000000000000000000000,
    0x20000000000000000000000000,
    0x40000000000000000000000000,
    0x80000000000000000000000000,
    0x100000000000000000000000000,
    0x200000000000000000000000000,
    0x400000000000000000000000000,
    0x800000000000000000000000000,
    0x1000000000000000000000000000,
    0x2000000000000000000000000000,
    0x4000000000000000000000000000,
    0x8000000000000000000000000000,
    0x10000000000000000000000000000,
    0x20000000000000000000000000000,
    0x40000000000000000000000000000,
    0x80000000000000000000000000000,
    0x100000000000000000000000000000,
    0x200000000000000000000000000000,
    0x400000000000000000000000000000,
    0x800000000000000000000000000000,
    0x1000000000000000000000000000000,
    0x2000000000000000000000000000000,
    0x4000000000000000000000000000000,
    0x8000000000000000000000000000000,
    0x10000000000000000000000000000000,
    0x20000000000000000000000000000000,
    0x40000000000000000000000000000000,
    0x80000000000000000000000000000000
];

pub const POW_2_256: [
    u256
    ; 256] = [
    0x1,
    0x2,
    0x4,
    0x8,
    0x10,
    0x20,
    0x40,
    0x80,
    0x100,
    0x200,
    0x400,
    0x800,
    0x1000,
    0x2000,
    0x4000,
    0x8000,
    0x10000,
    0x20000,
    0x40000,
    0x80000,
    0x100000,
    0x200000,
    0x400000,
    0x800000,
    0x1000000,
    0x2000000,
    0x4000000,
    0x8000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x100000000,
    0x200000000,
    0x400000000,
    0x800000000,
    0x1000000000,
    0x2000000000,
    0x4000000000,
    0x8000000000,
    0x10000000000,
    0x20000000000,
    0x40000000000,
    0x80000000000,
    0x100000000000,
    0x200000000000,
    0x400000000000,
    0x800000000000,
    0x1000000000000,
    0x2000000000000,
    0x4000000000000,
    0x8000000000000,
    0x10000000000000,
    0x20000000000000,
    0x40000000000000,
    0x80000000000000,
    0x100000000000000,
    0x200000000000000,
    0x400000000000000,
    0x800000000000000,
    0x1000000000000000,
    0x2000000000000000,
    0x4000000000000000,
    0x8000000000000000,
    0x10000000000000000,
    0x20000000000000000,
    0x40000000000000000,
    0x80000000000000000,
    0x100000000000000000,
    0x200000000000000000,
    0x400000000000000000,
    0x800000000000000000,
    0x1000000000000000000,
    0x2000000000000000000,
    0x4000000000000000000,
    0x8000000000000000000,
    0x10000000000000000000,
    0x20000000000000000000,
    0x40000000000000000000,
    0x80000000000000000000,
    0x100000000000000000000,
    0x200000000000000000000,
    0x400000000000000000000,
    0x800000000000000000000,
    0x1000000000000000000000,
    0x2000000000000000000000,
    0x4000000000000000000000,
    0x8000000000000000000000,
    0x10000000000000000000000,
    0x20000000000000000000000,
    0x40000000000000000000000,
    0x80000000000000000000000,
    0x100000000000000000000000,
    0x200000000000000000000000,
    0x400000000000000000000000,
    0x800000000000000000000000,
    0x1000000000000000000000000,
    0x2000000000000000000000000,
    0x4000000000000000000000000,
    0x8000000000000000000000000,
    0x10000000000000000000000000,
    0x20000000000000000000000000,
    0x40000000000000000000000000,
    0x80000000000000000000000000,
    0x100000000000000000000000000,
    0x200000000000000000000000000,
    0x400000000000000000000000000,
    0x800000000000000000000000000,
    0x1000000000000000000000000000,
    0x2000000000000000000000000000,
    0x4000000000000000000000000000,
    0x8000000000000000000000000000,
    0x10000000000000000000000000000,
    0x20000000000000000000000000000,
    0x40000000000000000000000000000,
    0x80000000000000000000000000000,
    0x100000000000000000000000000000,
    0x200000000000000000000000000000,
    0x400000000000000000000000000000,
    0x800000000000000000000000000000,
    0x1000000000000000000000000000000,
    0x2000000000000000000000000000000,
    0x4000000000000000000000000000000,
    0x8000000000000000000000000000000,
    0x10000000000000000000000000000000,
    0x20000000000000000000000000000000,
    0x40000000000000000000000000000000,
    0x80000000000000000000000000000000,
    0x100000000000000000000000000000000,
    0x200000000000000000000000000000000,
    0x400000000000000000000000000000000,
    0x800000000000000000000000000000000,
    0x1000000000000000000000000000000000,
    0x2000000000000000000000000000000000,
    0x4000000000000000000000000000000000,
    0x8000000000000000000000000000000000,
    0x10000000000000000000000000000000000,
    0x20000000000000000000000000000000000,
    0x40000000000000000000000000000000000,
    0x80000000000000000000000000000000000,
    0x100000000000000000000000000000000000,
    0x200000000000000000000000000000000000,
    0x400000000000000000000000000000000000,
    0x800000000000000000000000000000000000,
    0x1000000000000000000000000000000000000,
    0x2000000000000000000000000000000000000,
    0x4000000000000000000000000000000000000,
    0x8000000000000000000000000000000000000,
    0x10000000000000000000000000000000000000,
    0x20000000000000000000000000000000000000,
    0x40000000000000000000000000000000000000,
    0x80000000000000000000000000000000000000,
    0x100000000000000000000000000000000000000,
    0x200000000000000000000000000000000000000,
    0x400000000000000000000000000000000000000,
    0x800000000000000000000000000000000000000,
    0x1000000000000000000000000000000000000000,
    0x2000000000000000000000000000000000000000,
    0x4000000000000000000000000000000000000000,
    0x8000000000000000000000000000000000000000,
    0x10000000000000000000000000000000000000000,
    0x20000000000000000000000000000000000000000,
    0x40000000000000000000000000000000000000000,
    0x80000000000000000000000000000000000000000,
    0x100000000000000000000000000000000000000000,
    0x200000000000000000000000000000000000000000,
    0x400000000000000000000000000000000000000000,
    0x800000000000000000000000000000000000000000,
    0x1000000000000000000000000000000000000000000,
    0x2000000000000000000000000000000000000000000,
    0x4000000000000000000000000000000000000000000,
    0x8000000000000000000000000000000000000000000,
    0x10000000000000000000000000000000000000000000,
    0x20000000000000000000000000000000000000000000,
    0x40000000000000000000000000000000000000000000,
    0x80000000000000000000000000000000000000000000,
    0x100000000000000000000000000000000000000000000,
    0x200000000000000000000000000000000000000000000,
    0x400000000000000000000000000000000000000000000,
    0x800000000000000000000000000000000000000000000,
    0x1000000000000000000000000000000000000000000000,
    0x2000000000000000000000000000000000000000000000,
    0x4000000000000000000000000000000000000000000000,
    0x8000000000000000000000000000000000000000000000,
    0x10000000000000000000000000000000000000000000000,
    0x20000000000000000000000000000000000000000000000,
    0x40000000000000000000000000000000000000000000000,
    0x80000000000000000000000000000000000000000000000,
    0x100000000000000000000000000000000000000000000000,
    0x200000000000000000000000000000000000000000000000,
    0x400000000000000000000000000000000000000000000000,
    0x800000000000000000000000000000000000000000000000,
    0x1000000000000000000000000000000000000000000000000,
    0x2000000000000000000000000000000000000000000000000,
    0x4000000000000000000000000000000000000000000000000,
    0x8000000000000000000000000000000000000000000000000,
    0x10000000000000000000000000000000000000000000000000,
    0x20000000000000000000000000000000000000000000000000,
    0x40000000000000000000000000000000000000000000000000,
    0x80000000000000000000000000000000000000000000000000,
    0x100000000000000000000000000000000000000000000000000,
    0x200000000000000000000000000000000000000000000000000,
    0x400000000000000000000000000000000000000000000000000,
    0x800000000000000000000000000000000000000000000000000,
    0x1000000000000000000000000000000000000000000000000000,
    0x2000000000000000000000000000000000000000000000000000,
    0x4000000000000000000000000000000000000000000000000000,
    0x8000000000000000000000000000000000000000000000000000,
    0x10000000000000000000000000000000000000000000000000000,
    0x20000000000000000000000000000000000000000000000000000,
    0x40000000000000000000000000000000000000000000000000000,
    0x80000000000000000000000000000000000000000000000000000,
    0x100000000000000000000000000000000000000000000000000000,
    0x200000000000000000000000000000000000000000000000000000,
    0x400000000000000000000000000000000000000000000000000000,
    0x800000000000000000000000000000000000000000000000000000,
    0x1000000000000000000000000000000000000000000000000000000,
    0x2000000000000000000000000000000000000000000000000000000,
    0x4000000000000000000000000000000000000000000000000000000,
    0x8000000000000000000000000000000000000000000000000000000,
    0x10000000000000000000000000000000000000000000000000000000,
    0x20000000000000000000000000000000000000000000000000000000,
    0x40000000000000000000000000000000000000000000000000000000,
    0x80000000000000000000000000000000000000000000000000000000,
    0x100000000000000000000000000000000000000000000000000000000,
    0x200000000000000000000000000000000000000000000000000000000,
    0x400000000000000000000000000000000000000000000000000000000,
    0x800000000000000000000000000000000000000000000000000000000,
    0x1000000000000000000000000000000000000000000000000000000000,
    0x2000000000000000000000000000000000000000000000000000000000,
    0x4000000000000000000000000000000000000000000000000000000000,
    0x8000000000000000000000000000000000000000000000000000000000,
    0x10000000000000000000000000000000000000000000000000000000000,
    0x20000000000000000000000000000000000000000000000000000000000,
    0x40000000000000000000000000000000000000000000000000000000000,
    0x80000000000000000000000000000000000000000000000000000000000,
    0x100000000000000000000000000000000000000000000000000000000000,
    0x200000000000000000000000000000000000000000000000000000000000,
    0x400000000000000000000000000000000000000000000000000000000000,
    0x800000000000000000000000000000000000000000000000000000000000,
    0x1000000000000000000000000000000000000000000000000000000000000,
    0x2000000000000000000000000000000000000000000000000000000000000,
    0x4000000000000000000000000000000000000000000000000000000000000,
    0x8000000000000000000000000000000000000000000000000000000000000,
    0x10000000000000000000000000000000000000000000000000000000000000,
    0x20000000000000000000000000000000000000000000000000000000000000,
    0x40000000000000000000000000000000000000000000000000000000000000,
    0x80000000000000000000000000000000000000000000000000000000000000,
    0x100000000000000000000000000000000000000000000000000000000000000,
    0x200000000000000000000000000000000000000000000000000000000000000,
    0x400000000000000000000000000000000000000000000000000000000000000,
    0x800000000000000000000000000000000000000000000000000000000000000,
    0x1000000000000000000000000000000000000000000000000000000000000000,
    0x2000000000000000000000000000000000000000000000000000000000000000,
    0x4000000000000000000000000000000000000000000000000000000000000000,
    0x8000000000000000000000000000000000000000000000000000000000000000,
];

pub const POW_2_0: u128 = 0x1;
pub const POW_2_8: u128 = 0x100;
pub const POW_2_16: u128 = 0x10000;
pub const POW_2_24: u128 = 0x1000000;
pub const POW_2_32: u128 = 0x100000000;
pub const POW_2_40: u128 = 0x10000000000;
pub const POW_2_48: u128 = 0x1000000000000;
pub const POW_2_53: u128 = 0x20000000000000;
pub const POW_2_56: u128 = 0x100000000000000;
pub const POW_2_64: u128 = 0x10000000000000000;
pub const POW_2_72: u128 = 0x1000000000000000000;
pub const POW_2_80: u128 = 0x100000000000000000000;
pub const POW_2_88: u128 = 0x10000000000000000000000;
pub const POW_2_96: u128 = 0x1000000000000000000000000;
pub const POW_2_104: u128 = 0x100000000000000000000000000;
pub const POW_2_112: u128 = 0x10000000000000000000000000000;
pub const POW_2_120: u128 = 0x1000000000000000000000000000000;
pub const POW_2_127: u128 = 0x80000000000000000000000000000000;
pub const POW_2_250: u256 = 0x400000000000000000000000000000000000000000000000000000000000000;

pub const MAX_ADDRESS: u256 = 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;