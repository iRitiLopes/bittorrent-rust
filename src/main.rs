use serde_json::{self};
use std::{env, ops::Add};

// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    //println!("{}", encoded_value);
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

        return match first_char {
            "i" => {
                let last_char = &encoded_value.find("e");
                if last_char.is_none() {
                    panic!("Need e");
                }
                let number_string = &encoded_value[1..last_char.unwrap()];
                serde_json::Value::Number(number_string.parse::<i64>().unwrap().into())
            }
            "l" => {
                let mut values = Vec::<serde_json::Value>::new();
                let mut pivot = 1;
                let mut end_pivot = encoded_value.len() - 1;

                while pivot < end_pivot {
                    let all_values = &encoded_value[pivot..end_pivot];
                    let decoded_value = decode_bencoded_value(all_values);
                    let (aux_pivot, aux_end_pivot) = find_pivot(decoded_value.clone());
                    pivot = pivot + aux_pivot;
                    end_pivot = end_pivot - aux_end_pivot;
                    values.push(decoded_value);
                }

                serde_json::Value::Array(values)
            }
            _ => panic!("Not implemented type"),
        };
    }
}

fn find_pivot(v: serde_json::Value) -> (usize, usize) {
    if v.is_string() {
        //println!("DEBUG - v: {:?}",v);
        let digit_size = v.as_str().unwrap().len();
        return (v.as_str().unwrap().len().add(1 + digit_size), 0);
    }

    if v.is_i64() {
        return (v.as_i64().map(|x| x.to_string()).unwrap().len().add(2), 0);
    }

    if v.is_array() {
        let a = v.as_array().map(|a| {
            let b = a
                .iter()
                .map(|x| {
                    let z = find_pivot(x.clone());
                    z
                })
                .collect::<Vec<(usize, usize)>>();
            if b.len() == 0 {
                return (1, 1)
            }
            //println!("DEBUG - {:?} - b {:?}", v, b);
            let mut aux_a = 0;
            let mut aux_b = 0;
            for ele in b {
                aux_a += ele.0 + 1;
                aux_b += ele.1 + 1;
            }
            (aux_a, aux_b)
        });
        //println!("DEBUG - {:?}", a);
        return a.unwrap();
    }

    (0, 0)
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
