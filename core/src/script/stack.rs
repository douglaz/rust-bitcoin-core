use crate::script::error::{ScriptError, ScriptResult};

/// Maximum stack size during script execution
const MAX_STACK_SIZE: usize = 1000;

/// Maximum size of a stack element
const MAX_ELEMENT_SIZE: usize = 520;

/// Stack for script execution
#[derive(Debug, Clone)]
pub struct Stack {
    items: Vec<Vec<u8>>,
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

impl Stack {
    pub fn new() -> Self {
        Stack { items: Vec::new() }
    }

    pub fn push(&mut self, item: Vec<u8>) -> ScriptResult<()> {
        if self.items.len() >= MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        if item.len() > MAX_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
        self.items.push(item);
        Ok(())
    }

    pub fn push_vec(&mut self, item: Vec<u8>) -> ScriptResult<()> {
        self.push(item)
    }

    pub fn push_bool(&mut self, b: bool) -> ScriptResult<()> {
        self.push(if b { vec![1] } else { vec![] })
    }

    pub fn push_int(&mut self, n: i64) -> ScriptResult<()> {
        self.push(encode_num(n))
    }

    pub fn pop(&mut self) -> ScriptResult<Vec<u8>> {
        self.items.pop().ok_or(ScriptError::InvalidStackOperation)
    }

    pub fn top(&self) -> ScriptResult<&Vec<u8>> {
        self.items.last().ok_or(ScriptError::InvalidStackOperation)
    }

    pub fn top_mut(&mut self) -> ScriptResult<&mut Vec<u8>> {
        self.items
            .last_mut()
            .ok_or(ScriptError::InvalidStackOperation)
    }

    pub fn get(&self, index: isize) -> ScriptResult<&Vec<u8>> {
        if index < 0 {
            // Negative index: -1 = top of stack, -2 = second from top, etc.
            let len = self.items.len() as isize;
            let idx = (len + index) as usize;
            if idx >= self.items.len() {
                return Err(ScriptError::InvalidStackOperation);
            }
            self.items
                .get(idx)
                .ok_or(ScriptError::InvalidStackOperation)
        } else {
            self.items
                .get(index as usize)
                .ok_or(ScriptError::InvalidStackOperation)
        }
    }

    pub fn remove(&mut self, index: isize) -> ScriptResult<Vec<u8>> {
        if index < 0 {
            // Negative index: -1 = top of stack, -2 = second from top, etc.
            let len = self.items.len() as isize;
            let idx = (len + index) as usize;
            if idx >= self.items.len() {
                return Err(ScriptError::InvalidStackOperation);
            }
            Ok(self.items.remove(idx))
        } else {
            if index as usize >= self.items.len() {
                return Err(ScriptError::InvalidStackOperation);
            }
            Ok(self.items.remove(index as usize))
        }
    }

    pub fn swap(&mut self, a: usize, b: usize) -> ScriptResult<()> {
        let len = self.items.len();
        if a >= len || b >= len {
            return Err(ScriptError::InvalidStackOperation);
        }
        self.items.swap(len - a - 1, len - b - 1);
        Ok(())
    }

    pub fn dup(&mut self, index: isize) -> ScriptResult<()> {
        let item = self.get(index)?.clone();
        self.push(item)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    pub fn reverse(&mut self) {
        self.items.reverse();
    }

    pub fn items(&self) -> &[Vec<u8>] {
        &self.items
    }
}

/// Script number encoding/decoding
pub fn decode_num(data: &[u8], max_size: usize, minimal: bool) -> ScriptResult<i64> {
    if data.is_empty() {
        return Ok(0);
    }

    if data.len() > max_size {
        return Err(ScriptError::NumberOverflow);
    }

    if minimal {
        // Check for minimal encoding
        if data.len() > 1 {
            // If the last byte has sign bit...
            if (data[data.len() - 1] & 0x7f) == 0 {
                // ...and if it's not because we need the sign bit...
                if data.len() > 1 && (data[data.len() - 2] & 0x80) == 0 {
                    return Err(ScriptError::MinimalData);
                }
            }
        }
    }

    let mut result: i64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i == data.len() - 1 {
            // Last byte contains sign
            let value = (byte & 0x7f) as i64;
            result |= value << (8 * i);
            if byte & 0x80 != 0 {
                result = -result;
            }
        } else {
            result |= (byte as i64) << (8 * i);
        }
    }

    Ok(result)
}

pub fn encode_num(mut n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }

    let negative = n < 0;
    if negative {
        n = -n;
    }

    let mut result = Vec::new();

    while n > 0 {
        result.push((n & 0xff) as u8);
        n >>= 8;
    }

    // If the MSB is set, we need an extra byte for the sign
    if result[result.len() - 1] & 0x80 != 0 {
        if negative {
            result.push(0x80);
        } else {
            result.push(0);
        }
    } else if negative {
        let last = result.len() - 1;
        result[last] |= 0x80;
    }

    result
}

impl StackItem for Vec<u8> {
    fn to_bool(&self) -> bool {
        for (i, &byte) in self.iter().enumerate() {
            if byte != 0 {
                // Negative zero is still zero
                if i == self.len() - 1 && byte == 0x80 {
                    return false;
                }
                return true;
            }
        }
        false
    }

    fn to_i64(&self) -> ScriptResult<i64> {
        decode_num(self, 4, false)
    }
}

pub trait StackItem {
    fn to_bool(&self) -> bool;
    fn to_i64(&self) -> ScriptResult<i64>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_num() {
        assert_eq!(encode_num(0), Vec::<u8>::new());
        assert_eq!(encode_num(1), vec![1]);
        assert_eq!(encode_num(-1), vec![0x81]);
        assert_eq!(encode_num(127), vec![127]);
        assert_eq!(encode_num(-127), vec![0xff]);
        assert_eq!(encode_num(128), vec![0x80, 0x00]);
        assert_eq!(encode_num(-128), vec![0x80, 0x80]);

        assert_eq!(decode_num(&[], 4, false).unwrap(), 0);
        assert_eq!(decode_num(&[1], 4, false).unwrap(), 1);
        assert_eq!(decode_num(&[0x81], 4, false).unwrap(), -1);
        assert_eq!(decode_num(&[127], 4, false).unwrap(), 127);
        assert_eq!(decode_num(&[0xff], 4, false).unwrap(), -127);
        assert_eq!(decode_num(&[0x80, 0x00], 4, false).unwrap(), 128);
        assert_eq!(decode_num(&[0x80, 0x80], 4, false).unwrap(), -128);
    }

    #[test]
    fn test_stack_operations() {
        let mut stack = Stack::new();

        stack.push(vec![1, 2, 3]).unwrap();
        stack.push(vec![4, 5]).unwrap();

        assert_eq!(stack.len(), 2);
        assert_eq!(stack.top().unwrap(), &vec![4, 5]);

        let popped = stack.pop().unwrap();
        assert_eq!(popped, vec![4, 5]);
        assert_eq!(stack.len(), 1);

        stack.push_bool(true).unwrap();
        assert_eq!(stack.top().unwrap(), &vec![1]);

        stack.push_bool(false).unwrap();
        assert_eq!(stack.top().unwrap(), &Vec::<u8>::new());
    }
}
