use std::collections::HashMap;
use std::sync::Mutex;
use num_bigint::BigUint;
use tonic::{transport::Server, Code, Request, Response, Status};

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{auth_server::{self, Auth, AuthServer}, AuthenticationAnswerResponse, AuthenticationChallengeRequest, RegisterRequest, RegisterResponse};


#[derive(Default)]
pub struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserInfo>>
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

    async fn create_authentication_challenge(&self, request: Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        todo!()
    }

    async fn verify_authentication(&self, request: Request<AuthenticationAnswerResponse>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        todo!()
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