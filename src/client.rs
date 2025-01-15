pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use std::io::stdin;
use num_bigint::BigUint;
use zkp_auth::auth_client;
use crate::zkp_auth::auth_client::AuthClient;
use crate::zkp_auth::RegisterRequest;

use zkp::ZKP;

#[tokio::main]
async fn main() {

    let (alpha,beta,p,q) = ZKP::get_constants();
    let zkp = ZKP { alpha, beta, p, q};

    let mut buf = String::new();
    let mut client = AuthClient::connect("http://127.0.0.1:50051").await.expect("Failed to connect");
    println!("Hello from client");

    println!("Please provide username");
    stdin().read_line(&mut buf).expect("Failed to read line");
    let username = buf.trim().to_string();

    println!("Please provide password");
    stdin().read_line(&mut buf).expect("Failed to read line");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());

    let y1 = ZKP::exponentiate(&zkp.alpha, &password, &zkp.p);
    let y2 = ZKP::exponentiate(&zkp.beta, &password, &zkp.p);

    let request = RegisterRequest {
        user_name: username,
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };
    let _response = client.register(request).await.expect("Failed to send request");
    println!("✅ Registration was successful");



}