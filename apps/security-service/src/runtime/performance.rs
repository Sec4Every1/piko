use piko_common_model::RuntimePerformance;
use piko_win_platform::diagnostics;
use std::{
    io,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
#[derive(Default)]
pub struct Sampler {
    previous: Option<(Instant, u64)>,
}
fn percent(delta_ticks: u64, elapsed_ns: u128, processors: Option<u32>) -> Option<u16> {
    let processors = processors.filter(|n| *n > 0)?;
    if elapsed_ns < 1_000_000 {
        return None;
    }
    let value = u128::from(delta_ticks)
        .checked_mul(100)?
        .checked_mul(10_000)?
        / elapsed_ns.checked_mul(u128::from(processors))?;
    Some(value.min(10_000) as u16)
}
impl Sampler {
    pub fn sample(&mut self) -> io::Result<RuntimePerformance> {
        let now = Instant::now();
        let counters = match diagnostics::current_process() {
            Ok(v) => v,
            Err(e) => {
                self.previous = None;
                return Err(e);
            }
        };
        let processors = std::thread::available_parallelism()
            .ok()
            .and_then(|n| u32::try_from(n.get()).ok());
        let window = self.previous.map(|(time, ticks)| {
            (
                now.duration_since(time),
                counters.cpu_ticks.checked_sub(ticks),
            )
        });
        let cpu_percent_x100 = window.and_then(|(elapsed, delta)| {
            delta.and_then(|ticks| percent(ticks, elapsed.as_nanos(), processors))
        });
        let interval_ms = window
            .map(|(d, _)| d.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0);
        self.previous = Some((now, counters.cpu_ticks));
        let sampled_at_unix_ms = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_millis(),
        )
        .map_err(io::Error::other)?;
        Ok(RuntimePerformance {
            sampled_at_unix_ms,
            working_set_bytes: counters.working_set_bytes,
            private_bytes: counters.private_bytes,
            cpu_percent_x100,
            interval_ms,
            logical_processors: processors,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cpu_is_normalized_and_unknown_stays_unknown() {
        assert_eq!(percent(10_000_000, 1_000_000_000, Some(4)), Some(2500));
        assert_eq!(percent(0, 1_000_000_000, Some(4)), Some(0));
        assert_eq!(percent(1, 0, Some(4)), None);
        assert_eq!(percent(1, 1000000, None), None);
        assert_eq!(percent(u64::MAX, 1000000, Some(1)), Some(10000));
    }
}
