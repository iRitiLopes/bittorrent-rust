use serde_json::{self};
use std::{env};

// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    // If encoded_value starts with a digit, it's a number
    if encoded_value.chars().next().unwrap().is_digit(10) {
        // Example: "5:hello" -> "hello"
        let colon_index = encoded_value.find(':').unwrap();
        let number_string = &encoded_value[..colon_index];
        let number = number_string.parse::<i64>().unwrap();
        let string = &encoded_value[colon_index + 1..colon_index + 1 + number as usize];
        return serde_json::Value::String(string.to_string());
    } else {
        // Example: "i43e" -> 43
        let first_char = &encoded_value[0..1];
        let number_string = &encoded_value[1..encoded_value.len() - 1];
        let last_char = &encoded_value[encoded_value.len() - 1..];

        return match (first_char, last_char) {
            ("i", "e") => serde_json::Value::Number(number_string.parse::<i64>().unwrap().into()),
            ("l", "e") => {
                let mut pivot = 1;
                let mut values = Vec::<serde_json::Value>::new();
                while pivot < encoded_value.len() - 1 {
                    let value = decode_bencoded_value(&encoded_value[pivot..encoded_value.len() - 1]);
                    if value.is_string() {
                        pivot = pivot + value.as_str().unwrap().len() + 2
                    }
                    if value.is_i64() {
                        pivot = pivot + 2 + value.as_i64().unwrap().to_string().len()
                    }
                    values.push(value);
                }
                serde_json::Value::Array(values)
            }
            _ => panic!("Not implemented type")
        };
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        //println!("Logs from your program will appear here!");

        // Uncomment this block to pass the first stage
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else {
        println!("unknown command: {}", args[1])
    }
}
