use super::storage_worker::api_error;
use piko_ipc::{ApiData, ApiError, Command};
use piko_response_engine::ResponseEngine;
use std::{path::PathBuf, time::Instant};
use tokio::sync::{mpsc, oneshot};

struct Job {
    actor: String,
    command: Command,
    deadline: Instant,
    reply: oneshot::Sender<Result<ApiData, ApiError>>,
}
#[derive(Clone)]
pub struct ResponseClient {
    sender: mpsc::Sender<Job>,
}
impl ResponseClient {
    pub async fn start(directory: PathBuf, roots: Vec<PathBuf>) -> Result<Self, String> {
        let (sender, mut receiver) = mpsc::channel::<Job>(4);
        let (ready, started) = oneshot::channel();
        std::thread::Builder::new()
            .name("piko-response".into())
            .spawn(move || {
                let mut engine = match ResponseEngine::open(&directory, roots) {
                    Ok(engine) => engine,
                    Err(error) => {
                        let _ = ready.send(Err(error.to_string()));
                        return;
                    }
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                while let Some(job) = receiver.blocking_recv() {
                    if job.reply.is_closed() || Instant::now() >= job.deadline {
                        continue;
                    }
                    if let Err(error) = engine.set_actor(job.actor) {
                        let _ = job
                            .reply
                            .send(Err(api_error("response_unauthorized", &error.to_string())));
                        continue;
                    }
                    // Once accepted, a confirmed action completes/journals even if
                    // its caller disconnects. The same UUID never replays effects.
                    let result = match job.command {
                        Command::GetResponseStatus => engine.status().map(ApiData::ResponseStatus),
                        Command::PrepareQuarantine { path } => {
                            engine.prepare_quarantine(&path).map(ApiData::Action)
                        }
                        Command::PrepareRestore { action_id } => {
                            engine.prepare_restore(action_id).map(ApiData::Action)
                        }
                        Command::ExecuteAction {
                            action_id,
                            expected_sha256,
                        } => engine
                            .execute(action_id, &expected_sha256)
                            .map(ApiData::Action),
                        _ => Err("invalid response command".into()),
                    }
                    .map_err(|e| api_error("response_rejected", &e.to_string()));
                    let _ = job.reply.send(result);
                }
            })
            .map_err(|e| e.to_string())?;
        started.await.map_err(|e| e.to_string())??;
        Ok(Self { sender })
    }
    pub async fn call(
        &self,
        command: Command,
        deadline: Instant,
        actor: String,
    ) -> Result<ApiData, ApiError> {
        let (reply, result) = oneshot::channel();
        self.sender
            .try_send(Job {
                actor,
                command,
                deadline,
                reply,
            })
            .map_err(|_| api_error("response_busy", "response worker busy or unavailable"))?;
        tokio::time::timeout_at(deadline.into(), result).await
            .map_err(|_| api_error("response_timeout", "Read the action journal before retrying: an accepted action may still be completing."))?
            .map_err(|_| api_error("response_unavailable", "response worker unavailable"))?
    }
}
