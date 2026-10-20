use piko_common_model::SensorHealth;
use piko_win_platform::event_log::{LogRecord, Subscription, CHANNELS};
use std::{
    collections::HashMap,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, watch};

pub struct EventLogCollector {
    pub records: mpsc::Receiver<LogRecord>,
    pub health: watch::Receiver<Vec<SensorHealth>>,
    stopped: Arc<AtomicBool>,
}
impl EventLogCollector {
    pub fn start(checkpoints: HashMap<String, String>) -> io::Result<Self> {
        let (sender, records) = mpsc::channel(8);
        let initial: Vec<_> = CHANNELS
            .iter()
            .map(|channel| SensorHealth {
                id: format!("windows.event_log.{channel}"),
                state: "starting".into(),
                detail: "Opening Windows Event Log channel".into(),
                last_seen_unix_ms: None,
            })
            .collect();
        let (health_sender, health) = watch::channel(initial.clone());
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        std::thread::Builder::new().name("piko-event-log".into()).spawn(move || {
            let mut states = initial;
            // Native handles never leave their creating thread.
            let mut subscriptions: Vec<Option<Subscription>> = CHANNELS.iter().enumerate().map(|(index, channel)| {
                match Subscription::open(channel, checkpoints.get(&format!("windows.event_log.{channel}")).map(String::as_str)) {
                    Ok(subscription) => {
                        states[index].state = "active".into();
                        states[index].detail = "Windows Event Log subscription; durable bookmark; source level is not a malware verdict".into();
                        Some(subscription)
                    }
                    Err(error) => {
                        states[index].state = "degraded".into();
                        states[index].detail = format!("Cannot subscribe: {error}. No events skipped or audit policy changed.");
                        None
                    }
                }
            }).collect();
            health_sender.send_replace(states.clone());
            while !stop.load(Ordering::Acquire) && !sender.is_closed() {
                let mut received = false;
                for index in 0..subscriptions.len() {
                    if stop.load(Ordering::Acquire) { break; }
                    if let Some(subscription) = &mut subscriptions[index] {
                        match subscription.poll() {
                            Ok(Some(mut record)) => {
                                received = true;
                                // Keep the same record under backpressure; never advance past a
                                // rejected record. Shutdown can drop uncommitted copies because
                                // restart uses only the last durable bookmark.
                                loop {
                                    match sender.try_send(record) {
                                        Ok(()) => break,
                                        Err(mpsc::error::TrySendError::Full(value)) => {
                                            if stop.load(Ordering::Acquire) { return; }
                                            record = value;
                                            std::thread::sleep(Duration::from_millis(25));
                                        }
                                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                                    }
                                }
                            }
                            Ok(None) => {},
                            Err(error) => {
                                states[index].state = "degraded".into();
                                states[index].detail = format!("Subscription stopped: {error}. Restart resumes the last durable bookmark; a cleared/expired bookmark requires operator review.");
                                subscriptions[index] = None;
                                health_sender.send_replace(states.clone());
                            }
                        }
                    }
                }
                if !received { std::thread::sleep(Duration::from_millis(250)); }
            }
        })?;
        Ok(Self {
            records,
            health,
            stopped,
        })
    }
    pub fn stop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        self.records.close();
    }
}
impl Drop for EventLogCollector {
    fn drop(&mut self) {
        self.stop();
    }
}
