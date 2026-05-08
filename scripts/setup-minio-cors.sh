#!/usr/bin/env bash
# Configure MinIO CORS so the browser can direct-PUT encrypted attachments
# and direct-GET them back. Production R2 is configured via the Cloudflare
# dashboard per docs/17_attachment_upload_r2_spec.md §10.2.
#
# Requires: Docker + running MinIO container at nexusinbox-minio.

set -euo pipefail

BUCKET="${AGENT_INBOX_S3_BUCKET:-nexusinbox-attachments-dev}"
ACCESS_KEY="${AGENT_INBOX_S3_ACCESS_KEY_ID:-agent_inbox}"
SECRET_KEY="${AGENT_INBOX_S3_SECRET_ACCESS_KEY:-agent_inbox}"

# Ensure the bucket exists (idempotent).
docker run --rm --network host \
  -e "MC_HOST_local=http://${ACCESS_KEY}:${SECRET_KEY}@localhost:9000" \
  minio/mc mb --ignore-existing "local/${BUCKET}" >/dev/null

# CORS config in S3-compatible XML format. Allowed headers include
# x-amz-meta-issued-at per spec §10.2.
CORS_XML=$(cat <<'XML'
<CORSConfiguration>
  <CORSRule>
    <AllowedOrigin>http://localhost:3100</AllowedOrigin>
    <AllowedOrigin>http://localhost:3102</AllowedOrigin>
    <AllowedOrigin>https://app.nexusinbox.ai</AllowedOrigin>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedMethod>GET</AllowedMethod>
    <AllowedMethod>HEAD</AllowedMethod>
    <AllowedHeader>Content-Type</AllowedHeader>
    <AllowedHeader>x-amz-meta-attachment-id</AllowedHeader>
    <AllowedHeader>x-amz-meta-owner-user-id</AllowedHeader>
    <AllowedHeader>x-amz-meta-issued-at</AllowedHeader>
    <ExposeHeader>ETag</ExposeHeader>
    <ExposeHeader>Content-Length</ExposeHeader>
    <MaxAgeSeconds>600</MaxAgeSeconds>
  </CORSRule>
</CORSConfiguration>
XML
)

# NOTE: The MinIO community image returns `A header you provided implies
# functionality that is not implemented` for `mc cors set`. Browser direct-PUT
# to MinIO in dev therefore requires either:
#   (a) restart the MinIO container with MINIO_API_CORS_ALLOW_ORIGIN=* to
#       blanket-allow, or
#   (b) skip MinIO direct-upload in the browser and test via the Node E2E
#       script scripts/test_attachment_flow.mjs.
#
# For production, R2 CORS is configured via the Cloudflare dashboard per spec
# §10.2 (include x-amz-meta-issued-at in AllowedHeaders).
#
# Applying (a) here idempotently by restarting the container with the env var.
if ! docker exec nexusinbox-minio env | grep -q '^MINIO_API_CORS_ALLOW_ORIGIN='; then
  echo "Restarting MinIO with MINIO_API_CORS_ALLOW_ORIGIN=* for dev..."
  docker rm -f nexusinbox-minio >/dev/null 2>&1 || true
  docker run -d --name nexusinbox-minio \
    -p 9000:9000 -p 9001:9001 \
    -e "MINIO_ROOT_USER=${ACCESS_KEY}" \
    -e "MINIO_ROOT_PASSWORD=${SECRET_KEY}" \
    -e "MINIO_API_CORS_ALLOW_ORIGIN=*" \
    minio/minio server /data --console-address ":9001" >/dev/null
  sleep 2
  docker run --rm --network host \
    -e "MC_HOST_local=http://${ACCESS_KEY}:${SECRET_KEY}@localhost:9000" \
    minio/mc mb --ignore-existing "local/${BUCKET}" >/dev/null
fi
echo "MinIO CORS configured for bucket: ${BUCKET}"
