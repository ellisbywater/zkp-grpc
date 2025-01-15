pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use std::io::stdin;
use num_bigint::BigUint;
use zkp_auth::auth_client;
use crate::zkp_auth::auth_client::AuthClient;
use crate::zkp_auth::{AuthenticationAnswerRequest, AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest};

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
    buf.clear();
    println!("Please provide password");
    stdin().read_line(&mut buf).expect("Failed to read line");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());

    let y1 = ZKP::exponentiate(&zkp.alpha, &password, &zkp.p);
    let y2 = ZKP::exponentiate(&zkp.beta, &password, &zkp.p);

    let request = RegisterRequest {
        user_name: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };
    let _response = client.register(request).await.expect("Failed to send request");
    println!("✅ Registration was successful");

    buf.clear();

    println!("Please provide password to login");
    stdin().read_line(&mut buf).expect("Failed to read line");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());

    let k = ZKP::generate_random_below(&zkp.q);
    let r1 = ZKP::exponentiate(&zkp.alpha, &k, &zkp.p);
    let r2 = ZKP::exponentiate(&zkp.beta, &k, &zkp.p);

    let request = AuthenticationChallengeRequest {
        user: username.clone(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };
    let response = client.create_authentication_challenge(request).await.expect("Failed to send request").into_inner();
    println!("{:#?}", response);

    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);

    let s = zkp.solve(&k, &c, &password);
    let request = AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be(),
    };
    let response = client.verify_authentication(request).await.expect("Failed to verify").into_inner();
    println!("You logged in successfully: {:#?}", response.session_id);

}