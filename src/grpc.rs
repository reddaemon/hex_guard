use hex_guard::pb::hex_guard_server::HexGuard;
use hex_guard::pb::{Message, AnalysisResult};
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

pub use hex_guard::pb::hex_guard_server::HexGuardServer;

pub struct HexGuardService {
    tx: mpsc::Sender<AnalyzeRequest>,
}

pub struct AnalyzeRequest {
    pub chat_id: i64,
    pub text: String,
    pub sender_id: i64,
    pub sender_name: String,
}

impl HexGuardService {
    pub fn new(tx: mpsc::Sender<AnalyzeRequest>) -> Self {
        Self { tx }
    }
}

#[tonic::async_trait]
impl HexGuard for HexGuardService {
    async fn analyze_message(
        &self,
        request: Request<Message>,
    ) -> Result<Response<AnalysisResult>, Status> {
        let msg = request.into_inner();
        let req = AnalyzeRequest {
            chat_id: msg.chat_id,
            text: msg.text,
            sender_id: msg.sender_id,
            sender_name: msg.sender_name,
        };

        match self.tx.try_send(req) {
            Ok(()) => Ok(Response::new(AnalysisResult {
                score: 0,
                zones: vec![],
                final_url: String::new(),
            })),
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::warn!("Queue full, dropping message");
                Ok(Response::new(AnalysisResult {
                    score: 0,
                    zones: vec![],
                    final_url: String::new(),
                }))
            }
            Err(e) => Err(Status::internal(format!("Queue error: {}", e))),
        }
    }
}

pub fn create_server(tx: mpsc::Sender<AnalyzeRequest>) -> HexGuardServer<HexGuardService> {
    HexGuardServer::new(HexGuardService::new(tx))
}
