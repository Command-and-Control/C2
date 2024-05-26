use base64::{engine::general_purpose::STANDARD, Engine as _};
use proc_macro::TokenStream;
#[proc_macro]
pub fn prepare_encryption(_tokens: TokenStream) -> TokenStream {
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    let key =
        String::from_utf8(thread_rng().sample_iter(&Alphanumeric).take(20).collect()).unwrap();
    std::env::set_var("ENCRYPT", &key);
    format!(
        "
        use base64::{{engine::general_purpose::STANDARD, Engine as _}};
        const KEY: &[u8] = b\"{}\";
        fn xor(input: &[u8]) -> Vec<u8> {{
            let key = KEY.repeat((input.len()/KEY.len()) + 1)[..input.len()].to_vec();
            input.iter().zip(key).map(|(x, y)| *x^y).collect::<Vec<u8>>()
        }}

        fn decrypt(input: String) -> String {{
            let decoded = STANDARD.decode(input.as_bytes()).unwrap();
            String::from_utf8(xor(decoded.as_slice())).unwrap()
        }}
    ",
        &key
    )
    .parse()
    .unwrap()
}

#[proc_macro]
pub fn e(tokens: TokenStream) -> TokenStream {
    let tokens = tokens.to_string();
    let encrypted = xor(tokens[1..tokens.len() - 1].as_bytes());
    let encoded = STANDARD.encode(encrypted);
    format!("decrypt(\"{}\".to_string())", encoded)
        .parse()
        .unwrap()
}

fn xor(input: &[u8]) -> Vec<u8> {
    let key = std::env::var("ENCRYPT").unwrap();
    let key = key.repeat((input.len() / key.len()) + 1)[..input.len()]
        .as_bytes()
        .to_vec();
    input
        .iter()
        .zip(key)
        .map(|(x, y)| *x ^ y)
        .collect::<Vec<u8>>()
}
