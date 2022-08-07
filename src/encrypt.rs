use crypto::aes::KeySize::KeySize128;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use std::error::Error;

const AES_KEY: [u8; 16] = [
    152u8, 249u8, 122u8, 121u8, 30u8, 241u8, 69u8, 117u8, 121u8, 165u8, 183u8, 232u8, 138u8, 73u8,
    80u8, 99u8,
];

/// 加密
/// 16, 24, or 32 字节的 key 对应 KeySize128, KeySize192, or KeySize256
pub fn encrypt(text: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut encrypt = crypto::aes::ecb_encryptor(KeySize128, &AES_KEY, PkcsPadding);
    let mut read_buffer = RefReadBuffer::new(text);
    let mut result = vec![0; text.len() * 4];
    let mut write_buffer = RefWriteBuffer::new(&mut result);
    encrypt
        .encrypt(&mut read_buffer, &mut write_buffer, true)
        .unwrap();
    Ok(result.into_iter().filter(|v| *v != 0).collect())
}

/// 解密
pub fn decrypt(text: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut decrypt = crypto::aes::ecb_decryptor(KeySize128, &AES_KEY, PkcsPadding);
    let mut read_buffer = RefReadBuffer::new(text);
    let mut result = vec![0; text.len()];
    let mut write_buffer = RefWriteBuffer::new(&mut result);
    decrypt
        .decrypt(&mut read_buffer, &mut write_buffer, true)
        .unwrap();
    Ok(result)
}
