//! Signed bucket CORS configuration and unauthenticated browser preflight.

use crate::ingress::{read_upload, upload_lengths, UploadReadError};
use crate::{
    BlobStore, Bridge, Catalog, Clock, Guard, JobSink, Kek, Method, NntpConnector, RespBody,
    S3Request, S3Response,
};
use velmora_s3_proto::mutation::{
    valid_cors_header, valid_cors_origin, CorsConfiguration, MAX_CORS_BYTES,
};
use velmora_s3_proto::{ErrorCode, Target, UploadValidator};

use super::common::{
    authenticate, catalog_error, mutation_gate, policy, policy_with, restore_gate, s3_error,
    signed_host,
};

const PREFLIGHT_VARY: &str =
    "Origin, Access-Control-Request-Headers, Access-Control-Request-Method";

fn empty(status: u16) -> S3Response {
    S3Response {
        status,
        headers: vec![],
        body: RespBody::Empty,
    }
}

fn allow_origin(response: &mut S3Response, origin: &str) {
    response
        .headers
        .push(("access-control-allow-origin".into(), origin.into()));
    // As in S3, only an explicitly echoed origin allows credentials mode.
    // This changes no SigV4 or presign checks on the actual request.
    if origin != "*" {
        response
            .headers
            .push(("access-control-allow-credentials".into(), "true".into()));
    }
}

fn values<'a>(req: &'a S3Request, header: &'static str) -> impl Iterator<Item = &'a str> {
    req.headers.iter().filter_map(move |(name, value)| {
        name.eq_ignore_ascii_case(header)
            .then_some(value.trim_matches([' ', '\t']))
    })
}

fn single<'a>(req: &'a S3Request, header: &'static str) -> Option<&'a str> {
    let mut values = values(req, header);
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

/// Shared by ingress and the router: only bodyless OPTIONS with both
/// browser preflight headers on a configured S3 host and bucket path.
pub(crate) fn preflight_bucket(config: &crate::BridgeConfig, req: &S3Request) -> Option<String> {
    if req.method.as_str() != "OPTIONS"
        || single(req, "origin").is_none()
        || single(req, "access-control-request-method").is_none()
        || !matches!(req.body, crate::Body::Empty)
        || !matches!(
            crate::ingress::declared_length(&req.headers),
            Ok(None | Some(0))
        )
    {
        return None;
    }
    target_bucket(config, req)
}

fn target_bucket(config: &crate::BridgeConfig, req: &S3Request) -> Option<String> {
    let (host, _) = config.s3_host_for(single(req, "host")?)?;
    let policy = policy(config, host).ok()?;
    let bucket = Target::parse(&req.raw_target, &policy).ok()?.bucket;
    (!bucket.is_empty() && bucket != "_admin").then_some(bucket)
}

pub(super) async fn preflight<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: &S3Request,
    bucket: &str,
) -> S3Response {
    async fn evaluate<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
        bridge: &Bridge<C, B, N, J, K, T>,
        req: &S3Request,
        bucket: &str,
    ) -> Option<S3Response> {
        let origin = single(req, "origin").filter(|v| valid_cors_origin(v))?;
        let method = single(req, "access-control-request-method")?;
        let mut headers = Vec::new();
        for value in values(req, "access-control-request-headers") {
            if !value.is_empty() {
                for h in value.split(',').map(|h| h.trim_matches([' ', '\t'])) {
                    if !valid_cors_header(h) {
                        return None;
                    }
                    headers.push(h);
                }
            }
        }
        let config = match bridge
            .catalog
            .cached_bucket_cors(bucket, bridge.clock.now())
            .await
        {
            Ok(config) => config?,
            Err(err) => return Some(catalog_error(err)),
        };
        let found = config.first_match(origin, method, &headers)?;
        let mut response = empty(200);
        allow_origin(&mut response, found.allow_origin);
        response.headers.push((
            "access-control-allow-methods".into(),
            found.methods.join(", "),
        ));
        if !headers.is_empty() {
            response
                .headers
                .push(("access-control-allow-headers".into(), headers.join(", ")));
        }
        if let Some(seconds) = found.max_age_seconds {
            response
                .headers
                .push(("access-control-max-age".into(), seconds.to_string()));
        }
        Some(response)
    }
    let mut response = evaluate(bridge, req, bucket).await.unwrap_or_else(|| {
        S3Response::error(
            403,
            "AccessForbidden",
            "CORSResponse: This CORS request is not allowed.",
        )
    });
    response
        .headers
        .push(("vary".into(), PREFLIGHT_VARY.into()));
    response
}

pub(crate) struct ActualRequest {
    bucket: String,
    origin: String,
    method: Method,
}

impl ActualRequest {
    pub(crate) fn from_request(config: &crate::BridgeConfig, req: &S3Request) -> Option<Self> {
        if matches!(req.method, Method::Other(_)) {
            return None;
        }
        let origin = single(req, "origin")
            .filter(|v| valid_cors_origin(v))?
            .to_owned();
        Some(Self {
            bucket: target_bucket(config, req)?,
            origin,
            method: req.method.clone(),
        })
    }

    pub(crate) async fn apply<
        C: Catalog,
        B: BlobStore,
        N: NntpConnector,
        J: JobSink,
        K: Kek,
        T: Clock,
    >(
        self,
        bridge: &Bridge<C, B, N, J, K, T>,
        response: &mut S3Response,
    ) {
        // A lookup failure never replaces or changes a normal S3 status.
        let Ok(Some(config)) = bridge
            .catalog
            .cached_bucket_cors(&self.bucket, bridge.clock.now())
            .await
        else {
            return;
        };
        let Some(found) = config.first_match(&self.origin, self.method.as_str(), &[]) else {
            return;
        };
        allow_origin(response, found.allow_origin);
        if !found.expose_headers.is_empty() {
            response.headers.push((
                "access-control-expose-headers".into(),
                found.expose_headers.join(", "),
            ));
        }
        if !response.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("vary")
                && value
                    .split(',')
                    .any(|v| v.trim() == "*" || v.trim().eq_ignore_ascii_case("Origin"))
        }) {
            response.headers.push(("vary".into(), "Origin".into()));
        }
    }
}

pub(super) async fn configuration<
    C: Catalog,
    B: BlobStore,
    N: NntpConnector,
    J: JobSink,
    K: Kek,
    T: Clock,
>(
    bridge: &Bridge<C, B, N, J, K, T>,
    req: S3Request,
) -> S3Response {
    async fn handle<C: Catalog, B: BlobStore, N: NntpConnector, J: JobSink, K: Kek, T: Clock>(
        bridge: &Bridge<C, B, N, J, K, T>,
        req: S3Request,
    ) -> Result<S3Response, S3Response> {
        let authed = authenticate(bridge, &req).await?;
        let bucket = authed
            .bucket
            .as_ref()
            .ok_or_else(|| s3_error(ErrorCode::NoSuchBucket))?;
        if req.method == Method::Get {
            return Ok(
                match bridge
                    .catalog
                    .bucket_cors(&bucket.id)
                    .await
                    .map_err(catalog_error)?
                {
                    Some(doc) => S3Response {
                        status: 200,
                        headers: vec![("content-type".into(), "application/xml".into())],
                        body: RespBody::Bytes(doc.into_bytes()),
                    },
                    None => S3Response::error(
                        404,
                        "NoSuchCORSConfiguration",
                        "The CORS configuration does not exist.",
                    ),
                },
            );
        }
        mutation_gate(&bridge.cfg, &authed.headers, bucket)?;
        restore_gate(bridge).await?;
        let doc_and_rules = if req.method == Method::Put {
            let max = MAX_CORS_BYTES as u64;
            let xml_policy = policy_with(
                &bridge.cfg,
                signed_host(&bridge.cfg, &req),
                MAX_CORS_BYTES,
                max,
            )?;
            let lengths = upload_lengths(&req.headers, max).map_err(|err| err.response())?;
            let mut validator =
                UploadValidator::new(&authed.headers, &authed.verified, &xml_policy)
                    .map_err(s3_error)?;
            let charge = bridge
                .budget
                .charge_body(lengths.decoded)
                .await
                .map_err(|err| err.response())?;
            let body = read_upload(req.body, lengths, &charge, &mut validator)
                .await
                .map_err(|err| match err {
                    UploadReadError::Ingress(err) => err.response(),
                    UploadReadError::Proto(err) => s3_error(err),
                })?;
            let integrity = validator.finish().map_err(s3_error)?;
            if authed.headers.get("content-md5").is_none() && integrity.checksum().is_none() {
                return Err(S3Response::error(
                    400,
                    "InvalidRequest",
                    "Missing required header for this request: Content-MD5.",
                ));
            }
            let config = CorsConfiguration::parse(&body).map_err(s3_error)?;
            Some((config.document().map_err(s3_error)?, config.rule_count()))
        } else {
            None
        };
        let input = doc_and_rules
            .as_ref()
            .map(|(doc, rules)| (doc.as_str(), *rules));
        match bridge
            .catalog
            .set_bucket_cors(bucket, input, bridge.clock.now())
            .await
            .map_err(catalog_error)?
        {
            Guard::Applied(()) => Ok(empty(if input.is_some() { 200 } else { 204 })),
            Guard::Lost => {
                restore_gate(bridge).await?;
                Err(s3_error(ErrorCode::NoSuchBucket))
            }
        }
    }
    handle(bridge, req).await.unwrap_or_else(|resp| resp)
}
