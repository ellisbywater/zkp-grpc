use std::collections::HashMap;
use std::sync::Mutex;
use num_bigint::BigUint;
use tonic::{transport::Server, Code, Request, Response, Status};

use zkp::ZKP;
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{auth_server::{self, Auth, AuthServer}, AuthenticationAnswerResponse, AuthenticationChallengeRequest, RegisterRequest, RegisterResponse};
use crate::zkp_auth::{AuthenticationAnswerRequest, AuthenticationChallengeResponse};

#[derive(Default)]
pub struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserInfo>>,
    pub auth_to_user: Mutex<HashMap<String, String>>,
}

#[derive(Debug, Default)]
pub struct UserInfo {
    // registration
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
    // authorization
    pub r1: BigUint,
    pub r2: BigUint,
    // verification
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        
        let request = request.into_inner();
        let username = request.user_name;
        // let mut user_info = UserInfo::default();
        // user_info.user_name = username.clone();
        // user_info.y1 = BigUint::from_bytes_be(&request.y1);
        // user_info.y2 = BigUint::from_bytes_be(&request.y2);
        let user_info = UserInfo {
            user_name: username.clone(),
            y1: BigUint::from_bytes_be(&request.y1),
            y2: BigUint::from_bytes_be(&request.y2),
            ..Default::default()
        };

        let mut user_info_map = self.user_info.lock().unwrap();
        user_info_map.insert(username.clone(), user_info);


        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        let request = request.into_inner();
        let username = request.user;

        let mut user_info_map = self.user_info.lock().unwrap();
        if let Some(user_info) = user_info_map.get_mut(&username) {
            let (_,_,_,q) = ZKP::get_constants();
            let c  = ZKP::generate_random_below(&q);
            user_info.c = c.clone();
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);



            let auth_id = ZKP::generate_random_string(12);

            let mut auth_to_user = self.auth_to_user.lock().unwrap();
            auth_to_user.insert(auth_id.clone(), user_info.user_name.clone());
            Ok(Response::new(AuthenticationChallengeResponse { auth_id, c: c.to_bytes_be()}))
        } else {
            Err(Status::unauthenticated("Username does not exist"))?
        }
    }

    async fn verify_authentication(&self, request: Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        let request = request.into_inner();
        let auth_id = request.auth_id;

        let mut auth_to_user = self.auth_to_user.lock().unwrap();

        if let Some(user_name) = auth_to_user.get(&auth_id) {
            let mut user_info_map = self.user_info.lock().unwrap();
            let user_info = user_info_map.get_mut(user_name).expect("UserInfo does not exist");
            let s = BigUint::from_bytes_be(&request.s);
            user_info.s = s;

            let (alpha,beta,p,q) = ZKP::get_constants();
            let zkp = ZKP { alpha, beta, p, q};
            let verification = zkp.verify(&user_info.r1, &user_info.r2, &user_info.y1, &user_info.y2, &user_info.c, &user_info.s);

            if verification {
                let session_id = ZKP::generate_random_string(12);
                Ok(Response::new(AuthenticationAnswerResponse {session_id}))
            } else {
                Err(Status::unauthenticated("User is Invalid"))?
            }

        } else {
            Err(Status::unauthenticated("AuthId does not exist"))?
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:50051".to_string();

    let auth_impl = AuthImpl::default();
    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("Could not parse address"))
        .await
        .unwrap();
}