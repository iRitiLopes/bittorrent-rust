use std::{collections::HashMap, env, hash::Hash};

use anyhow::Ok;
use serde_json::{self};

// Available if you need it!
// use serde_bencode


#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> anyhow::Result<serde_json::Value> {
    let a = serde_bencode::de::from_bytes::<serde_bencode::value::Value>(encoded_value.as_bytes()).unwrap();
    convert(a)
}

fn convert(value: serde_bencode::value::Value) -> anyhow::Result<serde_json::Value> {
    match value {
        serde_bencode::value::Value::Bytes(b) => {
            let string = String::from_utf8(b)?;
            Ok(serde_json::Value::String(string))
        }
        serde_bencode::value::Value::Int(i) => {
            Ok(serde_json::Value::Number(serde_json::Number::from(i)))
        }
        serde_bencode::value::Value::List(l) => {
            let array = l
                .into_iter()
                .map(|item| convert(item))
                .collect::<anyhow::Result<Vec<serde_json::Value>>>()?;
            Ok(serde_json::Value::Array(array))
        }
        serde_bencode::value::Value::Dict(d) => {
            let mut dict = serde_json::Map::new();
            let hm = d.into_iter()
            .map(|(k,v)| {
                let key = String::from_utf8(k).unwrap();
                let value = convert(v).unwrap();
                dict.insert(key, value);
            });

            Ok(serde_json::Value::Object(dict))
        }
        _ => {
            panic!("Unhandled encoded value: {:?}", value)
        }
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
        let decoded_value = decode_bencoded_value(encoded_value).unwrap();
        println!("{}", decoded_value.to_string());
    } else {
        println!("unknown command: {}", args[1])
    }
}
