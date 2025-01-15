use tonic::{transport::Server, Code, Request, Response, Status};

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{auth_server::{self, Auth}, AuthenticationAnswerResponse, AuthenticationChallengeRequest, RegisterRequest, RegisterResponse};


#[derive(Debug, Default)]
struct AuthImpl {}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(&self, request: Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
        todo!()
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