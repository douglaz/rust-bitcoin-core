use bitcoin::blockdata::opcodes::all::*;

fn main() {
    // Test what opcodes are available
    println!("OP_PUSHBYTES_0: {:?}", OP_PUSHBYTES_0);
    println!("OP_PUSHNUM_1: {:?}", OP_PUSHNUM_1);
    println!("OP_PUSHNUM_NEG1: {:?}", OP_PUSHNUM_NEG1);
}