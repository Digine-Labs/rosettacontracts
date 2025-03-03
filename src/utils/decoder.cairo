use crate::utils::bytes::{Bytes, BytesTrait};
use crate::utils::bits::{get_bit_at, U256BitShift};
use crate::constants::{FELT252_MAX};
use core::num::traits::Bounded;
use core::traits::{DivRem};

#[derive(Serde, Copy, Drop)]
pub struct i257 {
    abs: u256,
    is_negative: bool,
}

#[derive(Clone, Drop, Serde)]
pub struct EVMCalldata {
    calldata: Bytes,
    offset: usize,
    relative_offset: usize
}

pub trait AbiDecodeTrait {
    fn decode(
        ref self: EVMCalldata, types: Span<EVMTypes>
    ) -> Span<felt252>; // Returns span of felt252 which directly will be passed to call_syscall
}

// Tuples can be decoded like basic types in order
#[derive(Copy, Drop, Serde)]
pub enum EVMTypes {
    Tuple: Span<EVMTypes>,
    Array: Span<EVMTypes>,
    FunctionSignature, // RM bytes4 can be used
    Address, // TODO
    Bool,
    Uint8,
    Uint16,
    Uint24,
    Uint32,
    Uint40,
    Uint48,
    Uint56,
    Uint64,
    Uint72,
    Uint80,
    Uint88,
    Uint96,
    Uint104,
    Uint112,
    Uint120,
    Uint128,
    Uint136,
    Uint144,
    Uint152,
    Uint160,
    Uint168,
    Uint176,
    Uint184,
    Uint192,
    Uint200,
    Uint208,
    Uint216,
    Uint224,
    Uint232,
    Uint240,
    Uint248,
    Uint256,
    Int8,
    Int16,
    Int24,
    Int32,
    Int40,
    Int48,
    Int56,
    Int64,
    Int72,
    Int80,
    Int88,
    Int96,
    Int104,
    Int112,
    Int120,
    Int128,
    Int136,
    Int144,
    Int152,
    Int160,
    Int168,
    Int176,
    Int184,
    Int192,
    Int200,
    Int208,
    Int216,
    Int224,
    Int232,
    Int240,
    Int248,
    Int256, // Decoded as i257 Because there is no i256 type in cairo. Closest is i257
    Bytes1,
    Bytes2,
    Bytes3,
    Bytes4,
    Bytes5,
    Bytes6,
    Bytes7,
    Bytes8,
    Bytes9,
    Bytes10,
    Bytes11,
    Bytes12,
    Bytes13,
    Bytes14,
    Bytes15,
    Bytes16,
    Bytes17,
    Bytes18,
    Bytes19,
    Bytes20,
    Bytes21,
    Bytes22,
    Bytes23,
    Bytes24,
    Bytes25,
    Bytes26,
    Bytes27,
    Bytes28,
    Bytes29,
    Bytes30,
    Bytes31,
    Bytes32, // Decoded as serialized ByteArray
    Bytes,
    String, // Same as bytes
}

impl EVMTypesImpl of AbiDecodeTrait {
    fn decode(ref self: EVMCalldata, types: Span<EVMTypes>) -> Span<felt252> {
        let mut decoded = array![];

        for evm_type in types {
            let decoded_type = match evm_type {
                EVMTypes::Tuple(tuple_types) => { self.decode(*tuple_types) },
                EVMTypes::Array(array_types) => { decode_array(ref self, *array_types) },
                EVMTypes::FunctionSignature => { decode_function_signature(ref self) },
                EVMTypes::Address => { decode_address(ref self) },
                EVMTypes::Bool => { decode_bool(ref self) },
                EVMTypes::Uint8 => { decode_uint(ref self, 8_u32) },
                EVMTypes::Uint16 => { decode_uint(ref self, 16_u32) },
                EVMTypes::Uint24 => { decode_uint(ref self, 24_u32) },
                EVMTypes::Uint32 => { decode_uint(ref self, 32_u32) },
                EVMTypes::Uint40 => { decode_uint(ref self, 40_u32) },
                EVMTypes::Uint48 => { decode_uint(ref self, 48_u32) },
                EVMTypes::Uint56 => { decode_uint(ref self, 56_u32) },
                EVMTypes::Uint64 => { decode_uint(ref self, 64_u32) },
                EVMTypes::Uint72 => { decode_uint(ref self, 72_u32) },
                EVMTypes::Uint80 => { decode_uint(ref self, 80_u32) },
                EVMTypes::Uint88 => { decode_uint(ref self, 88_u32) },
                EVMTypes::Uint96 => { decode_uint(ref self, 96_u32) },
                EVMTypes::Uint104 => { decode_uint(ref self, 104_u32) },
                EVMTypes::Uint112 => { decode_uint(ref self, 112_u32) },
                EVMTypes::Uint120 => { decode_uint(ref self, 120_u32) },
                EVMTypes::Uint128 => { decode_uint(ref self, 128_u32) },
                EVMTypes::Uint136 => { decode_uint(ref self, 136_u32) },
                EVMTypes::Uint144 => { decode_uint(ref self, 144_u32) },
                EVMTypes::Uint152 => { decode_uint(ref self, 152_u32) },
                EVMTypes::Uint160 => { decode_uint(ref self, 160_u32) },
                EVMTypes::Uint168 => { decode_uint(ref self, 168_u32) },
                EVMTypes::Uint176 => { decode_uint(ref self, 176_u32) },
                EVMTypes::Uint184 => { decode_uint(ref self, 184_u32) },
                EVMTypes::Uint192 => { decode_uint(ref self, 192_u32) },
                EVMTypes::Uint200 => { decode_uint(ref self, 200_u32) },
                EVMTypes::Uint208 => { decode_uint(ref self, 208_u32) },
                EVMTypes::Uint216 => { decode_uint(ref self, 216_u32) },
                EVMTypes::Uint224 => { decode_uint(ref self, 224_u32) },
                EVMTypes::Uint232 => { decode_uint(ref self, 232_u32) },
                EVMTypes::Uint240 => { decode_uint(ref self, 240_u32) },
                EVMTypes::Uint248 => { decode_uint(ref self, 248_u32) },
                EVMTypes::Uint256 => { decode_uint256(ref self) },
                EVMTypes::Int8 => { decode_int(ref self, 8_u32) },
                EVMTypes::Int16 => { decode_int(ref self, 16_u32) },
                EVMTypes::Int24 => { decode_int(ref self, 24_u32) },
                EVMTypes::Int32 => { decode_int(ref self, 32_u32) },
                EVMTypes::Int40 => { decode_int(ref self, 40_u32) },
                EVMTypes::Int48 => { decode_int(ref self, 48_u32) },
                EVMTypes::Int56 => { decode_int(ref self, 56_u32) },
                EVMTypes::Int64 => { decode_int(ref self, 64_u32) },
                EVMTypes::Int72 => { decode_int(ref self, 72_u32) },
                EVMTypes::Int80 => { decode_int(ref self, 80_u32) },
                EVMTypes::Int88 => { decode_int(ref self, 88_u32) },
                EVMTypes::Int96 => { decode_int(ref self, 96_u32) },
                EVMTypes::Int104 => { decode_int(ref self, 104_u32) },
                EVMTypes::Int112 => { decode_int(ref self, 112_u32) },
                EVMTypes::Int120 => { decode_int(ref self, 120_u32) },
                EVMTypes::Int128 => { decode_int(ref self, 128_u32) },
                EVMTypes::Int136 => { decode_int(ref self, 136_u32) },
                EVMTypes::Int144 => { decode_int(ref self, 144_u32) },
                EVMTypes::Int152 => { decode_int(ref self, 152_u32) },
                EVMTypes::Int160 => { decode_int(ref self, 160_u32) },
                EVMTypes::Int168 => { decode_int(ref self, 168_u32) },
                EVMTypes::Int176 => { decode_int(ref self, 176_u32) },
                EVMTypes::Int184 => { decode_int(ref self, 184_u32) },
                EVMTypes::Int192 => { decode_int(ref self, 192_u32) },
                EVMTypes::Int200 => { decode_int(ref self, 200_u32) },
                EVMTypes::Int208 => { decode_int(ref self, 208_u32) },
                EVMTypes::Int216 => { decode_int(ref self, 216_u32) },
                EVMTypes::Int224 => { decode_int(ref self, 224_u32) },
                EVMTypes::Int232 => { decode_int(ref self, 232_u32) },
                EVMTypes::Int240 => { decode_int(ref self, 240_u32) },
                EVMTypes::Int248 => { decode_int(ref self, 248_u32) },
                EVMTypes::Int256 => { decode_int256(ref self) },
                EVMTypes::Bytes1 => { decode_fixed_bytes(ref self, 1_usize) },
                EVMTypes::Bytes2 => { decode_fixed_bytes(ref self, 2_usize) },
                EVMTypes::Bytes3 => { decode_fixed_bytes(ref self, 3_usize) },
                EVMTypes::Bytes4 => { decode_fixed_bytes(ref self, 4_usize) },
                EVMTypes::Bytes5 => { decode_fixed_bytes(ref self, 5_usize) },
                EVMTypes::Bytes6 => { decode_fixed_bytes(ref self, 6_usize) },
                EVMTypes::Bytes7 => { decode_fixed_bytes(ref self, 7_usize) },
                EVMTypes::Bytes8 => { decode_fixed_bytes(ref self, 8_usize) },
                EVMTypes::Bytes9 => { decode_fixed_bytes(ref self, 9_usize) },
                EVMTypes::Bytes10 => { decode_fixed_bytes(ref self, 10_usize) },
                EVMTypes::Bytes11 => { decode_fixed_bytes(ref self, 11_usize) },
                EVMTypes::Bytes12 => { decode_fixed_bytes(ref self, 12_usize) },
                EVMTypes::Bytes13 => { decode_fixed_bytes(ref self, 13_usize) },
                EVMTypes::Bytes14 => { decode_fixed_bytes(ref self, 14_usize) },
                EVMTypes::Bytes15 => { decode_fixed_bytes(ref self, 15_usize) },
                EVMTypes::Bytes16 => { decode_fixed_bytes(ref self, 16_usize) },
                EVMTypes::Bytes17 => { decode_fixed_bytes(ref self, 17_usize) },
                EVMTypes::Bytes18 => { decode_fixed_bytes(ref self, 18_usize) },
                EVMTypes::Bytes19 => { decode_fixed_bytes(ref self, 19_usize) },
                EVMTypes::Bytes20 => { decode_fixed_bytes(ref self, 20_usize) },
                EVMTypes::Bytes21 => { decode_fixed_bytes(ref self, 21_usize) },
                EVMTypes::Bytes22 => { decode_fixed_bytes(ref self, 22_usize) },
                EVMTypes::Bytes23 => { decode_fixed_bytes(ref self, 23_usize) },
                EVMTypes::Bytes24 => { decode_fixed_bytes(ref self, 24_usize) },
                EVMTypes::Bytes25 => { decode_fixed_bytes(ref self, 25_usize) },
                EVMTypes::Bytes26 => { decode_fixed_bytes(ref self, 26_usize) },
                EVMTypes::Bytes27 => { decode_fixed_bytes(ref self, 27_usize) },
                EVMTypes::Bytes28 => { decode_fixed_bytes(ref self, 28_usize) },
                EVMTypes::Bytes29 => { decode_fixed_bytes(ref self, 29_usize) },
                EVMTypes::Bytes30 => { decode_fixed_bytes(ref self, 30_usize) },
                EVMTypes::Bytes31 => { decode_fixed_bytes(ref self, 31_usize) },
                EVMTypes::Bytes32 => { decode_bytes_32(ref self) },
                EVMTypes::Bytes => { decode_bytes(ref self) },
                EVMTypes::String => { decode_bytes(ref self) },
            };
            decoded.append_span(decoded_type);
        };

        decoded.span()
    }
}

// read(0x0) -> 0x20
// read(0x20) -> 0x2
// read(0x40) -> 0x40
// read(0x80) -> 0x2
// read(0xa0) -> 123
// read(0xc0) -> 444
// read(0x60) -> 0xa0
// read(0xe0) -> 0x2
// read(0x100) -> 555
// read(0x120) -> 32
fn decode_array(ref ctx: EVMCalldata, types: Span<EVMTypes>) -> Span<felt252> {
    // ctx.relative_offset = ctx.offset;
    // 2. array başladığında burası defer offset olduğu için bir sonraki slot geliyor
    
    println!("Relative offset init: {}", ctx.relative_offset);
    let (defer_offset, data_start_offset) = ctx.calldata.read_u256(ctx.offset);
    if(data_start_offset % 32 != 0) {
        println!("Readed at: {}, Returned wrong offset: {}", ctx.relative_offset, data_start_offset);
        println!("ctx.offset: {}, ctx.relative_offset: {}", ctx.offset, ctx.relative_offset);
        panic!("Wrong offset read");
    }
    
    ctx.offset = data_start_offset.try_into().unwrap(); // Move to where array length begins
    

    let (new_offset, items_length) = ctx.calldata.read_u256(ctx.relative_offset + ctx.offset);

    ctx.offset = new_offset;

    let mut decoded = array![items_length.try_into().unwrap()];
    let mut item_idx = 0;
    while item_idx < items_length {
        ctx.relative_offset = new_offset;
        // Loopun dışında array içi elemanlar dynamic mi check edilmeli
        // Eğer dynamicse yeni context açılıp offset sıfırlanabilir
        let decoded_inner_type = ctx.decode(types);
        decoded.append_span(decoded_inner_type);
        println!("decode item {}", item_idx);

        item_idx += 1;
    };
    ctx.relative_offset = 0;
    ctx.offset = defer_offset;
    decoded.span()
}

fn decode_bytes(ref ctx: EVMCalldata) -> Span<felt252> {
    let (defer_offset, data_start_offset) = ctx
        .calldata
        .read_u256(
            ctx.offset
        ); // We will move back to defer_offset after complete reading this dynamic type
    ctx
        .offset = data_start_offset
        .try_into()
        .unwrap(); // Data start offset has to be lower than u32 range. TODO: Add check?
    let (new_offset, items_length) = ctx.calldata.read_u256(ctx.offset); // length of bytes
    ctx.offset = new_offset;

    let mut ba: ByteArray = Default::default();

    let (slot_count, last_slot_bytes) = DivRem::<u256>::div_rem(items_length, 32);

    let mut curr_slot_idx = 0;
    while curr_slot_idx < slot_count {
        let (new_offset, current_slot) = ctx.calldata.read_u256(ctx.offset);
        ctx.offset = new_offset;

        ba.append_word(current_slot.high.into(), 16);
        ba.append_word(current_slot.low.into(), 16);

        curr_slot_idx += 1;
    };

    // Append last bytes
    if (last_slot_bytes > 0) {
        let (new_offset, last_slot) = ctx.calldata.read_u256(ctx.offset);
        ctx.offset = new_offset;

        let last_word = U256BitShift::shr(last_slot, 256 - (last_slot_bytes * 8));
        ba
            .append_word(
                last_word.try_into().unwrap(), last_slot_bytes.try_into().unwrap()
            ); // We can assume try_into is safe because we shifted bits line above.
    }
    ctx.offset = defer_offset;

    let mut serialized = array![];
    ba.serialize(ref serialized);
    serialized.span()
}

#[inline(always)]
fn decode_bytes_32(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    let complete_word = U256BitShift::shr(value, 8); // This is 31 byte
    let pending_byte = U256BitShift::shr(value, 248); // This is first byte
    array![0x1, complete_word.try_into().unwrap(), pending_byte.try_into().unwrap(), 0x1].span()
}

// TODO: ensure bytes order? Maybe its better to shl for bytes32 ???

#[inline(always)]
fn decode_fixed_bytes(ref ctx: EVMCalldata, size: usize) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    let value = U256BitShift::shr(value, ((32_usize - size) * 8).into());

    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_function_signature(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u32(ctx.offset);
    ctx.offset = new_offset;
    array![value.into()].span()
}

#[inline(always)]
fn decode_address(ref ctx: EVMCalldata) -> Span<felt252> {
    // TODO
    array![].span()
}

#[inline(always)]
fn decode_bool(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint(ref ctx: EVMCalldata, size: u32) -> Span<felt252> {
    // TODO: maybe range check with size?
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_int(ref ctx: EVMCalldata, size: u32) -> Span<felt252> {
    // Todo: add range checks maybe??
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    let msb: bool = get_bit_at(value, 255);
    if (msb) {
        let u256_max: u256 = Bounded::MAX;
        let value = (u256_max - value) + 1; // Absolute value

        let sn_value = FELT252_MAX.into() - value + 1;

        array![sn_value.try_into().unwrap()].span()
    } else {
        array![value.try_into().unwrap()].span()
    }
}

#[inline(always)]
fn decode_uint256(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.low.into(), value.high.into()].span()
}

#[inline(always)]
fn decode_int256(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;

    if (value == 0) {
        return array![0x0, 0x0, 0x0].span();
    }
    let msb: bool = get_bit_at(value, 255); // TBD

    if (msb) {
        let u256_max: u256 = Bounded::MAX;
        let value = (u256_max - value) + 1; // Because zero is msb == false
        return array![value.low.into(), value.high.into(), msb.into()].span();
    } else {
        return array![value.low.into(), value.high.into(), msb.into()].span();
    }
}


#[cfg(test)]
mod tests {
    use crate::utils::decoder::{EVMCalldata, EVMTypesImpl, EVMTypes};
    use crate::utils::bytes::{Bytes, BytesTrait};

    fn cd(mut data: Bytes) -> EVMCalldata {
        EVMCalldata { relative_offset: 0_usize, offset: 0_usize, calldata: data }
    }

    #[test]
    fn test_decode_array_of_array() {
        let mut data: Bytes = BytesTrait::blank();
        
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020); // 0:20
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000002); // 20:40
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000040); // 40:60
        data.append_u256(0x00000000000000000000000000000000000000000000000000000000000000a0); // 60:80
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000002); // 80:a0
        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000007b); // a0:c0
        data.append_u256(0x00000000000000000000000000000000000000000000000000000000000001bc); // c0:e0
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000002); // e0:100
        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000022b); // 100:120
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000021); // 120:140

        let mut calldata = cd(data);
        let decoded = calldata.decode(array![EVMTypes::Array(array![EVMTypes::Array(array![EVMTypes::Uint128].span())].span())].span());

        assert_eq!(*decoded.at(0), 0x2);
        assert_eq!(*decoded.at(1), 0x2);
        assert_eq!(*decoded.at(2), 123);
        assert_eq!(*decoded.at(3), 444);
        assert_eq!(*decoded.at(4), 0x2);
        assert_eq!(*decoded.at(5), 555);
        assert_eq!(*decoded.at(6), 33);
    }

    #[test]
    fn test_decode_array_of_tuple_with_array() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000002);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000040);
        data.append_u256(0x00000000000000000000000000000000000000000000000000000000000000e0);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000003);
        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000006f);
        data.append_u256(0x00000000000000000000000000000000000000000000000000000000000000de);
        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000014d);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000003);
        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000029a);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000309);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000378);

        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Array(array![EVMTypes::Tuple(array![EVMTypes::Array(array![EVMTypes::Uint128].span())].span())].span())].span());

        assert_eq!(*decoded.at(0), 0x2);
        assert_eq!(*decoded.at(1), 0x3);
        assert_eq!(*decoded.at(2), 111);
        assert_eq!(*decoded.at(3), 222);
        assert_eq!(*decoded.at(4), 333);
        assert_eq!(*decoded.at(5), 0x3);
        assert_eq!(*decoded.at(6), 666);
        assert_eq!(*decoded.at(7), 777);
        assert_eq!(*decoded.at(8), 888);
    }

    #[test]
    fn test_decode_complex() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000080);
        data.append_u256(0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        data.append_u256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff40e5);
        data.append_u256(0x00000000000000000000000000000000000000000000000000000000000000c0);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000005);
        data.append_u256(0x00bbffaa00000000000000000000000000000000000000000000000000000000);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000002);
        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000006f);
        data.append_u256(0x00000000000000000000000000000000000000000000000000000000000000de);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000309);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000378);

        let mut calldata = cd(data);

        let decoded = calldata
            .decode(
                array![
                    EVMTypes::Bytes,
                    EVMTypes::Uint256,
                    EVMTypes::Int128,
                    EVMTypes::Array(
                        array![EVMTypes::Tuple(array![EVMTypes::Uint128, EVMTypes::Uint128].span())]
                            .span()
                    )
                ]
                    .span()
            );

        assert_eq!(*decoded.at(0), 0x0);
        assert_eq!(*decoded.at(1), 0x00bbffaa00);
        assert_eq!(*decoded.at(2), 0x5); // Bytes len
        assert_eq!(*decoded.at(3), 0xffffffffffffffffffffffffffffffff); // Uint256
        assert_eq!(*decoded.at(4), 0xffffffffffffffffffffffffffff);
        assert_eq!(*decoded.at(5), -48923); // Int128
        assert_eq!(*decoded.at(6), 0x2); // Arr len
        assert_eq!(*decoded.at(7), 111);
        assert_eq!(*decoded.at(8), 222);
        assert_eq!(*decoded.at(9), 777);
        assert_eq!(*decoded.at(10), 888);
    }

    #[test]
    fn test_decode_array_of_struct() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000003);
        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000000b);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000016);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000001618);
        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000036f);
        data.append_u256(0x000000000000000000000000000000000000000000000000000000e8d4a50fff);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000989680);

        let mut calldata = cd(data);

        let decoded = calldata
            .decode(
                array![
                    EVMTypes::Array(
                        array![EVMTypes::Tuple(array![EVMTypes::Uint128, EVMTypes::Uint128].span())]
                            .span()
                    )
                ]
                    .span()
            );
        assert_eq!(*decoded.at(0), 0x3);
        assert_eq!(*decoded.at(1), 0xb);
        assert_eq!(*decoded.at(2), 0x16);
        assert_eq!(*decoded.at(3), 0x1618);
        assert_eq!(*decoded.at(4), 0x36f);
        assert_eq!(*decoded.at(5), 0xe8d4a50fff);
        assert_eq!(*decoded.at(6), 0x989680);
    }

    #[test]
    fn test_decode_array_uint128s() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000003);
        data.append_u256(0x00000000000000000000000000000000000000000000000000000000000001bd);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000016462);
        data.append_u256(0x000000000000000000000000000000000000000000000000000000001a6e41e3);

        let mut calldata = cd(data);

        let decoded = calldata
            .decode(array![EVMTypes::Array(array![EVMTypes::Uint128].span())].span());

        assert_eq!(*decoded.at(0), 0x3);
        assert_eq!(*decoded.at(1), 0x1bd);
        assert_eq!(*decoded.at(2), 0x16462);
        assert_eq!(*decoded.at(3), 0x1a6e41e3);
    }

    #[test]
    fn test_decode_tuple_of_two() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000007b);
        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000022b);

        let mut calldata = cd(data);

        let decoded = calldata
            .decode(
                array![EVMTypes::Tuple(array![EVMTypes::Uint128, EVMTypes::Uint128].span())].span()
            );

        assert_eq!(*decoded.at(0), 0x7b);
        assert_eq!(*decoded.at(1), 0x22b);
    }

    #[test]
    fn test_decode_tuple_of_two_uint256() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000007b);
        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000022b);

        let mut calldata = cd(data);

        let decoded = calldata
            .decode(
                array![EVMTypes::Tuple(array![EVMTypes::Uint256, EVMTypes::Uint256].span())].span()
            );

        assert_eq!(*decoded.at(0), 0x7b);
        assert_eq!(*decoded.at(1), 0x0);
        assert_eq!(*decoded.at(2), 0x22b);
        assert_eq!(*decoded.at(3), 0x0);
    }

    #[test]
    fn test_decode_int128_neg() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int128].span());
        assert_eq!(*decoded.at(0), -128);
    }

    #[test]
    fn test_decode_multi_uint256() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000044);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Uint256, EVMTypes::Uint128].span());
        assert_eq!(*decoded.at(0), 0x20);
        assert_eq!(*decoded.at(1), 0x0);
        assert_eq!(*decoded.at(2), 0x44);
    }

    #[test]
    fn test_decode_multi_uint128() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000044);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Uint128, EVMTypes::Uint128].span());
        assert_eq!(*decoded.at(0), 0x20);
        assert_eq!(*decoded.at(1), 0x44);
    }

    #[test]
    fn test_decode_bytes_one_full_slot() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0xffffffffffffffffffaaaaaaaaaaaaaaaaaaafffffffffffffffffafafafaffa);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes].span());
        assert_eq!(*decoded.at(0), 0x1);
        assert_eq!(
            *decoded.at(1), 0xffffffffffffffffffaaaaaaaaaaaaaaaaaaafffffffffffffffffafafafaf
        );
        assert_eq!(*decoded.at(2), 0xfa);
        assert_eq!(*decoded.at(3), 0x1);
    }

    #[test]
    fn test_decode_bytes_one_slot() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000003);
        data.append_u256(0xffaabb0000000000000000000000000000000000000000000000000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes].span());
        assert_eq!(*decoded.at(0), 0x0);
        assert_eq!(*decoded.at(1), 0xffaabb);
        assert_eq!(*decoded.at(2), 0x3);
    }

    #[test]
    fn test_decode_bytes() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000020);
        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000039);
        data.append_u256(0xffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaa);
        data.append_u256(0xbbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabb00000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes].span());
        assert_eq!(*decoded.at(0), 0x1);
        assert_eq!(
            *decoded.at(1), 0xffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbff
        );
        assert_eq!(*decoded.at(2), 0xaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabbffaabb);
        assert_eq!(*decoded.at(3), 0x1a);
    }

    #[test]
    fn test_decode_bytes32_zeroes() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes32].span());
        assert_eq!(*decoded.at(0), 0x1);
        assert_eq!(*decoded.at(1), 0x000fffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        assert_eq!(*decoded.at(2), 0x00);
        assert_eq!(*decoded.at(3), 0x1);
    }

    #[test]
    fn test_decode_bytes32() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes32].span());
        assert_eq!(*decoded.at(0), 0x1);
        assert_eq!(
            *decoded.at(1), 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        );
        assert_eq!(*decoded.at(2), 0xff);
        assert_eq!(*decoded.at(3), 0x1);
    }

    #[test]
    fn test_decode_bytes2() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0xff22000000000000000000000000000000000000000000000000000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes2].span());
        assert_eq!(*decoded.at(0), 0xff22);
    }

    #[test]
    fn test_decode_bytes31() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0xff22000000000000000000000000000000000000000000000000000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes31].span());
        assert_eq!(
            *decoded.at(0), 0xff220000000000000000000000000000000000000000000000000000000000
        );
    }

    #[test]
    fn test_decode_bytes2_zero() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0022000000000000000000000000000000000000000000000000000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Bytes2].span());
        assert_eq!(*decoded.at(0), 0x0022);
    }

    #[test]
    fn test_decode_int256_neg() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffce);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int256].span());
        assert_eq!(*decoded.at(0), 50);
        assert_eq!(*decoded.at(1), 0);
        assert_eq!(*decoded.at(2), 0x1);
    }

    #[test]
    fn test_decode_int256_pos() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x000000000000000000000000000000000000000000000000000000000000003c);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int256].span());
        assert_eq!(*decoded.at(0), 60);
        assert_eq!(*decoded.at(1), 0);
        assert_eq!(*decoded.at(2), 0x0);
    }

    #[test]
    fn test_decode_int256_zero() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int256].span());
        assert_eq!(*decoded.at(0), 0);
        assert_eq!(*decoded.at(1), 0);
        assert_eq!(*decoded.at(2), 0x0);
    }

    #[test]
    fn test_decode_int8_neg() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int8].span());
        assert_eq!(*decoded.at(0), -5);
    }

    #[test]
    fn test_decode_int8_pos() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000005);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int8].span());
        assert_eq!(*decoded.at(0), 5);
    }

    #[test]
    fn test_decode_int8_zero() {
        let mut data: Bytes = BytesTrait::blank();

        data.append_u256(0x0000000000000000000000000000000000000000000000000000000000000000);
        let mut calldata = cd(data);

        let decoded = calldata.decode(array![EVMTypes::Int8].span());
        assert_eq!(*decoded.at(0), 0);
    }
}
