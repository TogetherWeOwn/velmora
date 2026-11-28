# S3 compatibility: bucket CORS

On endpoints with bucket CORS enabled, configure CORS with `PutBucketCors`,
inspect it with `GetBucketCors`, and remove it with `DeleteBucketCors`. These
are signed, path-style S3 bucket operations and use the same bucket grant
checks as other S3 operations. `GetBucketCors` on a bucket with no CORS
configuration returns `404 NoSuchCORSConfiguration`.

For example, save this as `cors.json` to allow a web app to use signed PUTs
and read the resulting ETag:

```json
{
  "CORSRules": [
    {
      "AllowedOrigins": ["https://app.example.com"],
      "AllowedMethods": ["PUT"],
      "AllowedHeaders": ["authorization", "content-type", "x-amz-*"],
      "ExposeHeaders": ["ETag"],
      "MaxAgeSeconds": 600,
      "ID": "browser-upload"
    }
  ]
}
```

```sh
aws --endpoint-url "$S3_ENDPOINT" s3api put-bucket-cors --bucket "$BUCKET" \
  --cors-configuration file://cors.json
aws --endpoint-url "$S3_ENDPOINT" s3api get-bucket-cors --bucket "$BUCKET"
aws --endpoint-url "$S3_ENDPOINT" s3api delete-bucket-cors --bucket "$BUCKET"
```

A configuration can contain up to 100 rules and 64 KiB of XML. Use the
browser's exact origin (scheme, host and port if non-default, with no path).
Custom browser schemes such as `chrome-extension://` and `capacitor://` are
supported. One wildcard per allowed origin or allowed request header is
supported.
Methods are `GET`, `PUT`, `POST`, `DELETE`, and `HEAD`. The first rule that
matches the origin, method, and all requested header names answers browser
preflight. Add `POST` or `DELETE` if the app initiates, completes, or aborts
multipart uploads in the browser.

An OPTIONS preflight does not need a signature and does not check whether
an object exists. The actual S3 request still needs valid SigV4 authorization
or a presigned URL. Matching responses, including request-size and similar
S3 errors, carry CORS headers. A specific origin match can include
`Access-Control-Allow-Credentials: true`; a literal `*` match never does.
CORS does not make objects public. Changes can take up to 60 seconds to reach
all server instances; browsers may also retain a successful preflight for the
configured `MaxAgeSeconds`.

CORS configuration is not part of object recovery records. After a rebuild
from those records, run `put-bucket-cors` again for each configured bucket.
