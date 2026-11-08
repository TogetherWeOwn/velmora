//! NNTP adapter preserving the existing client, yEnc and caller-owned pool.
//!
//! Borrow a leased, authenticated client through `ClientIo`, or implement `Io`
//! using the product's existing bounded multi-account broker. No account choice,
//! connection creation, new pool or repair process is installed here. `ClientIo`
//! supervises in-flight operations using the caller's event-driven control.
//! Optimized client operations remain available unchanged.

use super::*;
use crate::{article, nntp::NntpClient, transport::Transport, yenc};

/// Persist before POST together with the intent. Mint these fields with
/// `article::obfuscate_article` once, not afresh on retry. No payload is stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostHeaders {
    pub message_id: Id,
    pub from: Id,
    pub subject: Id,
    pub date: String,
    pub newsgroup: Id,
    pub yenc_name: Id,
}

impl PostHeaders {
    pub fn from_obfuscated(value: &article::ObfuscatedArticle) -> Result<Self> {
        let result = Self {
            message_id: Id::new(value.message_id.clone())?,
            from: Id::new(value.from.clone())?,
            subject: Id::new(value.subject.clone())?,
            date: value.date.clone(),
            newsgroup: Id::new(value.newsgroup.clone())?,
            yenc_name: Id::new(value.yenc_name.clone())?,
        };
        result.render()?;
        Ok(result)
    }

    fn render(&self) -> Result<Vec<u8>> {
        if self.date.len() > 128 {
            return Err(Failure::Invalid);
        }
        article::ArticleHeaders::new(
            self.from.as_str(),
            &[self.newsgroup.as_str()],
            self.subject.as_str(),
            &self.date,
            self.message_id.as_str(),
        )
        .and_then(|headers| headers.render())
        .map_err(|_| Failure::Invalid)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostingPlan {
    pub intent_binding: [u8; 32],
    pub headers: Vec<PostHeaders>,
}

/// The product owns stable request journaling, account admission, leases and
/// physical close on revocation/deadline/cancellation. Every in-flight operation
/// remains charged to its account until closure/settlement is proven. POST I/O
/// failures are uncertain. Absence after STAT never settles an in-flight POST.
#[allow(async_fn_in_trait)]
pub trait Io {
    async fn post(
        &mut self,
        target: &Target,
        message_id: &str,
        article: &[u8],
        control: &impl Control,
    ) -> Result<()>;
    async fn body(
        &mut self,
        target: &Target,
        message_id: &str,
        control: &impl Control,
    ) -> Result<Vec<u8>>;
    async fn stat(
        &mut self,
        target: &Target,
        message_id: &str,
        control: &impl Control,
    ) -> Result<()>;
}

/// Does not dial or release a pool slot. Construct only after existing guarded
/// authentication and resource admission; the caller retains close authority.
/// The client's configured article cap remains enforced (hard maximum 64 MiB).
pub struct ClientIo<'a, T: Transport> {
    pub client: &'a mut NntpClient<T>,
}

fn read_error(error: crate::Error) -> Failure {
    match error {
        crate::Error::ArticleNotFound(_) => Failure::Missing,
        crate::Error::AuthFailed(_) | crate::Error::NoPermission(_) => Failure::Denied,
        crate::Error::Io(ref error) if crate::transport::is_article_limit_error(error) => {
            Failure::Limit
        }
        crate::Error::Io(_) => Failure::Transient,
        crate::Error::Bounds { .. } => Failure::Limit,
        crate::Error::NntpReply {
            code: 400..=499, ..
        } => Failure::Transient,
        _ => Failure::Integrity,
    }
}

async fn controlled<F: Future>(
    operation: F,
    target: &Target,
    action: Action,
    control: &impl Control,
) -> Result<F::Output> {
    let mut operation = std::pin::pin!(operation);
    let mut cancelled = std::pin::pin!(control.cancelled(target, action));
    std::future::poll_fn(|cx| {
        if let Err(error) = control.check(target, action) {
            return std::task::Poll::Ready(Err(error));
        }
        if let std::task::Poll::Ready(error) = cancelled.as_mut().poll(cx) {
            return std::task::Poll::Ready(Err(error));
        }
        match operation.as_mut().poll(cx) {
            std::task::Poll::Ready(result) => {
                std::task::Poll::Ready(control.check(target, action).map(|()| result))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}

impl<T: Transport> Io for ClientIo<'_, T> {
    async fn post(
        &mut self,
        target: &Target,
        message_id: &str,
        article: &[u8],
        control: &impl Control,
    ) -> Result<()> {
        control.check(target, Action::Write)?;
        let result = controlled(
            self.client.post_article(message_id, article),
            target,
            Action::Write,
            control,
        )
        .await;
        let result = match result {
            Ok(result) => result,
            Err(_) => {
                let _ = self.client.shutdown_unusable().await;
                return Err(Failure::Uncertain);
            }
        };
        result.map_err(|error| match error {
            crate::Error::AuthFailed(_)
            | crate::Error::NoPermission(_)
            | crate::Error::PostProhibited(_) => Failure::Denied,
            _ => Failure::Uncertain,
        })?;
        control
            .check(target, Action::Write)
            .map_err(|_| Failure::Uncertain)
    }

    async fn body(
        &mut self,
        target: &Target,
        message_id: &str,
        control: &impl Control,
    ) -> Result<Vec<u8>> {
        control.check(target, Action::Read)?;
        let mut out = Vec::new();
        let result = controlled(
            self.client.body_to(message_id, &mut out),
            target,
            Action::Read,
            control,
        )
        .await;
        match result {
            Ok(result) => result.map_err(read_error)?,
            Err(error) => {
                let _ = self.client.shutdown_unusable().await;
                return Err(error);
            }
        }
        control.check(target, Action::Read)?;
        Ok(out)
    }

    async fn stat(
        &mut self,
        target: &Target,
        message_id: &str,
        control: &impl Control,
    ) -> Result<()> {
        control.check(target, Action::Read)?;
        let result = controlled(self.client.stat(message_id), target, Action::Read, control).await;
        match result {
            Ok(result) => {
                result.map_err(read_error)?;
            }
            Err(error) => {
                let _ = self.client.shutdown_unusable().await;
                return Err(error);
            }
        }
        control.check(target, Action::Read)
    }
}

pub struct Provider<I> {
    account: Id,
    io: I,
    posting: Option<PostingPlan>,
}

impl<I: Io> Provider<I> {
    /// `None` is a read-only adapter, independent of new-write target policy.
    pub fn new(account: Id, io: I, posting: Option<PostingPlan>) -> Self {
        Self {
            account,
            io,
            posting,
        }
    }

    pub fn into_io(self) -> I {
        self.io
    }

    fn check(&self, target: &Target, action: Action, control: &impl Control) -> Result<()> {
        if target.backend != Backend::Nntp || target.account != self.account {
            return Err(Failure::Configuration);
        }
        control.check(target, action)
    }

    fn validate_intent(&self, intent: &WriteIntent) -> Result<()> {
        intent.validate()?;
        if intent
            .parts
            .iter()
            .any(|part| !crate::segment_identity::valid_segment_id(part.reference.as_str()))
        {
            return Err(Failure::Invalid);
        }
        Ok(())
    }

    fn posting(&self, intent: &WriteIntent) -> Result<&PostingPlan> {
        self.validate_intent(intent)?;
        let plan = self.posting.as_ref().ok_or(Failure::Unsupported)?;
        if plan.intent_binding != intent.binding()? || plan.headers.len() != intent.parts.len() {
            return Err(Failure::Conflict);
        }
        for (header, part) in plan.headers.iter().zip(&intent.parts) {
            if header.message_id != part.reference {
                return Err(Failure::Conflict);
            }
            header.render()?;
        }
        Ok(plan)
    }

    fn record(&self, session: &WriteSession) -> Result<ObjectRecord> {
        self.validate_intent(&session.intent)?;
        if session.remote != session.intent.target.generation {
            return Err(Failure::Conflict);
        }
        Ok(ObjectRecord {
            identity: ObjectIdentity {
                target: session.intent.target.clone(),
                version: session.remote.clone(),
                bytes: session.intent.bytes,
                sha256: session.intent.sha256,
            },
            operation: session.intent.operation.clone(),
            parts: session.intent.parts.clone(),
        })
    }

    async fn fetch_part(
        &mut self,
        record: &ObjectRecord,
        part: &Part,
        control: &impl Control,
    ) -> Result<Vec<u8>> {
        self.check(&record.identity.target, Action::Read, control)?;
        let article = self
            .io
            .body(&record.identity.target, part.reference.as_str(), control)
            .await?;
        // A custom Io must honor this same bounded wire contract. The native
        // client additionally enforces its configured cap while receiving.
        if article.len() > crate::transport::MAX_ARTICLE_BYTES {
            return Err(Failure::Limit);
        }
        self.check(&record.identity.target, Action::Read, control)?;
        let mut out = vec![0; part.bytes as usize];
        let count = yenc::decode_to(part.reference.as_str(), &article, &mut out)
            .map_err(|_| Failure::Integrity)?;
        if count != out.len() || digest(&out) != part.sha256 {
            return Err(Failure::Integrity);
        }
        Ok(out)
    }

    async fn prove(&mut self, record: ObjectRecord, control: &impl Control) -> Result<WriteProof> {
        record.validate()?;
        self.validate_intent(&record.intent())?;
        let mut hash = Sha256::new();
        for part in &record.parts {
            hash.update(self.fetch_part(&record, part, control).await?);
        }
        let actual: [u8; 32] = hash.finalize().into();
        if actual != record.identity.sha256 {
            return Err(Failure::Integrity);
        }
        self.check(&record.identity.target, Action::Read, control)?;
        self.check(&record.identity.target, Action::Write, control)
            .map_err(|_| Failure::Uncertain)?;
        Ok(WriteProof {
            record,
            acknowledged: true,
            full_ciphertext_readback: true,
            backend: Backend::Nntp,
        })
    }
}

impl<I: Io> ArchiveProvider for Provider<I> {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            write: self.posting.is_some(),
            range: true,
            reconcile: true,
            physical_delete: false,
            max_part_bytes: MAX_PART_BYTES,
        }
    }

    async fn begin(
        &mut self,
        intent: &WriteIntent,
        control: &impl Control,
    ) -> Result<WriteSession> {
        self.check(&intent.target, Action::Write, control)?;
        self.posting(intent)?;
        Ok(WriteSession {
            intent: intent.clone(),
            remote: intent.target.generation.clone(),
        })
    }

    async fn write_part(
        &mut self,
        session: &WriteSession,
        index: usize,
        bytes: &[u8],
        control: &impl Control,
    ) -> Result<PartReceipt> {
        self.check(&session.intent.target, Action::Write, control)?;
        self.record(session)?;
        let part = session.intent.check_part(index, bytes)?;
        let header = &self.posting(&session.intent)?.headers[index];
        let headers = header.render()?;
        let mut body = Vec::new();
        yenc::encode_segment(
            &mut body,
            &yenc::SegmentParams::single(header.yenc_name.as_str()),
            bytes,
        )
        .map_err(|_| Failure::Invalid)?;
        let article = article::assemble_article(&headers, &body).map_err(|_| Failure::Invalid)?;
        self.io
            .post(
                &session.intent.target,
                part.reference.as_str(),
                &article,
                control,
            )
            .await?;
        self.check(&session.intent.target, Action::Write, control)
            .map_err(|_| Failure::Uncertain)?;
        Ok(PartReceipt {
            index,
            intent_binding: session.intent.binding()?,
            acknowledgement: part.reference.clone(),
        })
    }

    async fn commit(
        &mut self,
        session: &WriteSession,
        receipts: &[PartReceipt],
        control: &impl Control,
    ) -> Result<WriteProof> {
        self.check(&session.intent.target, Action::Write, control)?;
        self.posting(&session.intent)?;
        check_receipts(session, receipts)?;
        if receipts
            .iter()
            .zip(&session.intent.parts)
            .any(|(receipt, part)| receipt.acknowledgement != part.reference)
        {
            return Err(Failure::Conflict);
        }
        let record = self.record(session)?;
        // POST receipts already acknowledge irreversible effects. A failed
        // readback (including propagation delay or revocation) is not absence.
        self.prove(record, control)
            .await
            .map_err(|_| Failure::Uncertain)
    }

    async fn abort(
        &mut self,
        session: &WriteSession,
        control: &impl Control,
    ) -> Result<AbortOutcome> {
        self.check(&session.intent.target, Action::AbortIncomplete, control)?;
        self.record(session)?;
        // No CANCEL article, erase command, inline GC or cache deletion.
        Ok(AbortOutcome::Irreversible)
    }

    async fn stat(
        &mut self,
        record: &ObjectRecord,
        control: &impl Control,
    ) -> Result<ObjectIdentity> {
        self.check(&record.identity.target, Action::Read, control)?;
        record.validate()?;
        self.validate_intent(&record.intent())?;
        for part in &record.parts {
            self.io
                .stat(&record.identity.target, part.reference.as_str(), control)
                .await?;
        }
        self.check(&record.identity.target, Action::Read, control)?;
        // STAT establishes presence only. Metadata is the trusted manifest, not
        // a measurement or cryptographic readback of the observed article.
        Ok(record.identity.clone())
    }

    async fn read_range(
        &mut self,
        record: &ObjectRecord,
        range: Range,
        sink: &mut impl Sink,
        control: &impl Control,
    ) -> Result<()> {
        self.check(&record.identity.target, Action::Read, control)?;
        record.validate()?;
        self.validate_intent(&record.intent())?;
        let end = range.end(record.identity.bytes)?;
        for part in &record.parts {
            let start = range.offset.max(part.offset);
            let stop = end.min(part.offset + u64::from(part.bytes));
            if start < stop {
                let bytes = self.fetch_part(record, part, control).await?;
                emit(
                    &bytes[(start - part.offset) as usize..(stop - part.offset) as usize],
                    &record.identity.target,
                    sink,
                    control,
                )
                .await?;
            }
        }
        self.check(&record.identity.target, Action::Read, control)
    }

    async fn reconcile(
        &mut self,
        session: &WriteSession,
        control: &impl Control,
    ) -> Result<Reconciled> {
        self.check(&session.intent.target, Action::Write, control)?;
        let record = self.record(session)?;
        match self.prove(record, control).await {
            Ok(proof) => Ok(Reconciled::Verified(Box::new(proof))),
            // Missing, corrupt or oversized readback never establishes that
            // nothing irreversible has happened to possibly-posted articles.
            Err(_) => Ok(Reconciled::Uncertain),
        }
    }

    async fn health(&mut self, target: &Target, control: &impl Control) -> Result<Health> {
        self.check(target, Action::Health, control)?;
        // Availability of the admitted adapter only, not a provider probe.
        Ok(Health::Available)
    }
}
