//! The request log line of the fetch handler: every answered request is
//! settled and written here, and only here.
//!
//! [`Answered::finish`] reconciles the request's observation with the
//! status the client got ([`ingress::settled_log_line`]), writes the
//! line, and returns the status to count. A 5xx line or an opted-in
//! child grant refusal line ends with `stage=.. err=.. code=..`:
//! names and numbers only.

use velmora_bridge::ingress;
use velmora_bridge::metrics::RequestObservation;

/// What the line names of a request, whatever its answer.
pub struct Answered<'a> {
    pub method: &'a str,
    /// The raw target, or `-` before it is known.
    pub target: &'a str,
    pub request_id: &'a str,
    pub admin: bool,
}

impl Answered<'_> {
    /// Settles `observed` with the `wire` status, writes the line, and
    /// returns the status to count.
    pub fn finish(&self, intended: u16, wire: u16, observed: &mut RequestObservation) -> u16 {
        let (counted, line) = ingress::settled_log_line(
            self.method,
            self.target,
            self.request_id,
            self.admin,
            intended,
            wire,
            observed,
        );
        write_line(&line);
        counted
    }
}

#[cfg(not(test))]
fn write_line(line: &str) {
    worker::console_log!("{line}");
}

#[cfg(test)]
thread_local! {
    static WRITTEN: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn write_line(line: &str) {
    WRITTEN.with(|w| w.borrow_mut().push(line.to_owned()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use velmora_bridge::metrics::{FailureStage, Fault};
    use velmora_bridge::BridgeError;

    fn written() -> Vec<String> {
        WRITTEN.with(|w| std::mem::take(&mut *w.borrow_mut()))
    }

    fn answered(target: &str) -> Answered<'_> {
        Answered {
            method: "PUT",
            target,
            request_id: "ray-1",
            admin: false,
        }
    }

    #[test]
    fn each_answer_writes_one_line_with_the_wire_status_and_its_reason() {
        written();
        // A handled request with a failure it observed.
        let mut observed = RequestObservation::default();
        observed.mark_error(
            FailureStage::R2,
            &BridgeError::Blob("r2: put failed: internal (10001)".into()),
        );
        let counted = answered("/b/secret-key").finish(500, 500, &mut observed);
        assert_eq!(counted, 500);
        // A request that did not convert.
        let mut observed = RequestObservation::default();
        observed.mark_fault(FailureStage::Other, Fault::named("RequestConversion"));
        answered("-").finish(500, 500, &mut observed);
        // The handler meant 200; the response conversion answered 500.
        let mut observed = RequestObservation::default();
        let counted = answered("/b/k").finish(200, 500, &mut observed);
        assert_eq!(counted, 500);
        // A success.
        answered("/b/k").finish(200, 200, &mut RequestObservation::default());

        let lines = written();
        assert_eq!(lines.len(), 4, "{lines:?}");
        let ends = [
            " status=500 id=ray-1 stage=r2 err=Blob code=r2_put_internal_10001",
            " status=500 id=ray-1 stage=other err=RequestConversion code=-",
            " status=500 id=ray-1 stage=other err=ResponseConversion code=-",
            " status=200 id=ray-1",
        ];
        for (line, end) in lines.iter().zip(ends) {
            assert!(line.starts_with("req method=PUT "), "{line}");
            assert!(line.ends_with(end), "{line}");
            assert!(!line.contains("secret-key"), "{line}");
        }
    }
}
