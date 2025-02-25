use crate::utils::bytes::{Bytes, BytesTrait};

#[derive(Drop, Serde)]
pub struct EVMCalldata {
    calldata: Bytes,
    offset: usize
}

pub trait AbiDecodeTrait {
    fn decode(ref self: EVMCalldata, types: Span<EVMTypes>) -> Span<felt252>; // Returns span of felt252 which directly will be passed to call_syscall
}

pub enum DecodingMethod {
    Basic,
    Dynamic
}

// Tuples can be decoded like basic types in order
#[derive(Drop, Serde)]
pub enum EVMTypes {
    FunctionSignature,
    Address,
    Bool,
    Uint8, 
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Uint256
}


impl EVMTypesImpl of AbiDecodeTrait {
    fn decode(ref self: EVMCalldata, mut types: Span<EVMTypes>) -> Span<felt252> {
        if(types.len() == 1) {
            // This means only one basic type decoding

            return match types.pop_front().unwrap() {
                EVMTypes::FunctionSignature => { decode_function_signature(ref self) },
                EVMTypes::Address => { decode_address(ref self) },
                EVMTypes::Bool => { decode_bool(ref self) },
                EVMTypes::Uint8 => { decode_uint8(ref self) },
                EVMTypes::Uint16 => { decode_uint16(ref self) },
                EVMTypes::Uint32 => { decode_uint32(ref self) },
                EVMTypes::Uint64 => { decode_uint64(ref self) },
                EVMTypes::Uint128 => { decode_uint128(ref self) },
                EVMTypes::Uint256 => { decode_uint256(ref self) },
            };
        }

        array![].span()
    }
}

// Usage will be
// let x = EVMCalldata { calldata: ByteArray of evm calldata, offset: 0};
// let params_list = array xxx
// each param element calls x.decode(param) and result appended to sn_calldata

#[inline(always)]
fn decode_function_signature(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u32(ctx.offset);
    ctx.offset = new_offset;
    array![value.into()].span()
}

#[inline(always)]
fn decode_address(ref ctx: EVMCalldata) -> Span<felt252> {
    array![].span()
}

#[inline(always)]
fn decode_bool(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint8(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint16(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint32(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint64(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint128(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.try_into().unwrap()].span()
}

#[inline(always)]
fn decode_uint256(ref ctx: EVMCalldata) -> Span<felt252> {
    let (new_offset, value) = ctx.calldata.read_u256(ctx.offset);
    ctx.offset = new_offset;
    array![value.low.into(), value.high.into()].span()
}


#[cfg(test)]
mod tests { 
    use crate::utils::decoder::{EVMCalldata, EVMTypesImpl, EVMTypes};
    use crate::utils::bytes::{Bytes, BytesTrait};

    fn cd() -> EVMCalldata {

        let mut data: Bytes = BytesTrait::blank();

        data.append_u32(0x095ea7b3_u32);
        data.append_u128(0x0_u128);
        data.append_u128(0xffff_u128);
        data.append_u128(0xffffffffffffffffffffffffffffffff_u128);
        data.append_u128(0xffffffffffffffffffffffffffffffff_u128);

        EVMCalldata {
            offset: 0_usize,
            calldata: data
        }
    }

    #[test]
    fn test_decode_signature() {
        let mut calldata = cd();

        let decoded = calldata.decode(array![EVMTypes::FunctionSignature].span());

        assert_eq!(decoded.len(), 1);
        assert_eq!(*decoded.at(0), 0x095ea7b3);
        assert_eq!(calldata.offset, 4);

        let second_param = calldata.decode(array![EVMTypes::Uint32].span());

        assert_eq!(second_param.len(), 1);
        assert_eq!(*second_param.at(0), 0xffff);
        assert_eq!(calldata.offset, 4 + 32);

        let third_param = calldata.decode(array![EVMTypes::Uint256].span());
        assert_eq!(third_param.len(), 2);
        assert_eq!(*third_param.at(0), 0xffffffffffffffffffffffffffffffff);
        assert_eq!(*third_param.at(1), 0xffffffffffffffffffffffffffffffff);
        assert_eq!(calldata.offset, 4 + 32 + 32);


    }
}