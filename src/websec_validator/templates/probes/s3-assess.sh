#!/usr/bin/env bash
# S3 bucket posture assessment.
# ZAP can't meaningfully test an S3 bucket, so this checks it directly with the AWS CLI:
# public-access posture, ACL/policy exposure, CORS, encryption, and anonymous reachability.
#
#   ./s3-assess.sh                          # uses defaults below
#   ./s3-assess.sh my-bucket us-east-2
#   BUCKET=x REGION=y ./s3-assess.sh
#
# Uses your configured AWS credentials. Read-only — never writes, deletes, or changes
# anything. Anonymous probes use --no-sign-request / unauthenticated curl.
set -uo pipefail

BUCKET="${1:-${BUCKET:-<UPLOADS_BUCKET>}}"
REGION="${2:-${REGION:-us-east-1}}"

pass=0; warn=0; fail=0
ok()   { echo "  [ OK ]  $*"; pass=$((pass+1)); }
note() { echo "  [INFO]  $*"; }
wn()   { echo "  [WARN]  $*"; warn=$((warn+1)); }
bad()  { echo "  [FAIL]  $*"; fail=$((fail+1)); }
hdr()  { echo; echo "== $* =="; }

command -v aws >/dev/null || { echo "aws CLI not found. Install it or run from a box that has it."; exit 1; }
echo "Assessing s3://$BUCKET (region $REGION) as: $(aws sts get-caller-identity --query Arn --output text 2>/dev/null || echo 'UNKNOWN')"

hdr "Bucket exists / reachable"
if aws s3api head-bucket --bucket "$BUCKET" --region "$REGION" 2>/tmp/_s3err; then
  ok "head-bucket succeeded"
else
  bad "head-bucket failed: $(tr -d '\n' </tmp/_s3err). Check bucket name/region/credentials."
  echo; echo "Cannot continue without bucket access."; exit 1
fi

hdr "Public Access Block (want all four = true)"
PAB=$(aws s3api get-public-access-block --bucket "$BUCKET" --region "$REGION" \
  --query 'PublicAccessBlockConfiguration' --output text 2>/dev/null)
if [[ -z "$PAB" ]]; then
  bad "No Public Access Block configured — bucket can be made public via ACL/policy."
else
  echo "  BlockPublicAcls/IgnorePublicAcls/BlockPublicPolicy/RestrictPublicBuckets = $PAB"
  if [[ "$PAB" == "True	True	True	True" || "$PAB" == "true	true	true	true" ]]; then
    ok "All public access blocked at the bucket level."
  else
    wn "One or more public-access-block settings are OFF — review above."
  fi
fi

hdr "Bucket policy status (IsPublic should be False)"
PS=$(aws s3api get-bucket-policy-status --bucket "$BUCKET" --region "$REGION" \
  --query 'PolicyStatus.IsPublic' --output text 2>/dev/null)
case "$PS" in
  False|false) ok "Policy status: not public." ;;
  True|true)   bad "Bucket policy is PUBLIC. Inspect the policy below." ;;
  *)           note "No bucket policy (or none readable) — policy status N/A." ;;
esac

hdr "Bucket policy document"
if aws s3api get-bucket-policy --bucket "$BUCKET" --region "$REGION" --query Policy --output text 2>/dev/null > /tmp/_s3pol && [[ -s /tmp/_s3pol ]]; then
  python3 -m json.tool < /tmp/_s3pol 2>/dev/null | sed 's/^/    /' || sed 's/^/    /' /tmp/_s3pol
  if grep -qE '"Principal"[[:space:]]*:[[:space:]]*"\*"|"AWS"[[:space:]]*:[[:space:]]*"\*"' /tmp/_s3pol; then
    wn 'Policy contains a wildcard Principal ("*") — confirm it is paired with a tight Condition, not an open Allow.'
  else
    ok "No wildcard Principal in policy."
  fi
else
  note "No bucket policy set."
fi

hdr "Bucket ACL (look for AllUsers / AuthenticatedUsers grants)"
ACL=$(aws s3api get-bucket-acl --bucket "$BUCKET" --region "$REGION" \
  --query "Grants[?contains(Grantee.URI || 'x','AllUsers') || contains(Grantee.URI || 'x','AuthenticatedUsers')].[Grantee.URI,Permission]" \
  --output text 2>/dev/null)
if [[ -z "$ACL" ]]; then
  ok "No AllUsers/AuthenticatedUsers ACL grants."
else
  bad "Public/cross-account ACL grants found: $ACL"
fi

hdr "Default encryption (want AES256 or aws:kms)"
ENC=$(aws s3api get-bucket-encryption --bucket "$BUCKET" --region "$REGION" \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
  --output text 2>/dev/null)
[[ -n "$ENC" && "$ENC" != "None" ]] && ok "Default encryption: $ENC" || wn "No default encryption configured."

hdr "CORS configuration (watch for AllowedOrigins '*')"
CORS=$(aws s3api get-bucket-cors --bucket "$BUCKET" --region "$REGION" --output json 2>/dev/null)
if [[ -z "$CORS" ]]; then
  ok "No CORS configuration (or none readable)."
else
  echo "$CORS" | sed 's/^/    /'
  echo "$CORS" | grep -q '"\*"' && wn "CORS allows '*' somewhere — confirm that's intended for an uploads bucket." || ok "No wildcard in CORS."
fi

hdr "Versioning"
VER=$(aws s3api get-bucket-versioning --bucket "$BUCKET" --region "$REGION" --query Status --output text 2>/dev/null)
[[ "$VER" == "Enabled" ]] && ok "Versioning enabled." || note "Versioning: ${VER:-not enabled}."

hdr "Anonymous access probes (should all be DENIED)"
if aws s3 ls "s3://$BUCKET" --no-sign-request --region "$REGION" >/dev/null 2>&1; then
  bad "Anonymous ListBucket SUCCEEDED — bucket lists objects without credentials!"
else
  ok "Anonymous ListBucket denied."
fi
CODE=$(curl -s -o /dev/null -w '%{http_code}' "https://${BUCKET}.s3.${REGION}.amazonaws.com/" 2>/dev/null)
case "$CODE" in
  403) ok "Anonymous HTTP GET on bucket root → 403 (denied)." ;;
  200) bad "Anonymous HTTP GET on bucket root → 200 (bucket index is PUBLIC)!" ;;
  *)   note "Anonymous HTTP GET on bucket root → HTTP $CODE." ;;
esac

echo; echo "=================================================="
echo "Summary for s3://$BUCKET : ${pass} OK, ${warn} WARN, ${fail} FAIL"
echo "=================================================="
echo "Reminder — also test the UPLOAD PATH (these are app-layer, not bucket-layer):"
echo "  - content-type bypass on the upload endpoint (mime sniffing vs claimed type)"
echo "  - path traversal in uploaded filenames (../ in the key)"
echo "  - whether media signed-URL / media-token can be forged or replayed"
rm -f /tmp/_s3err /tmp/_s3pol
[[ $fail -gt 0 ]] && exit 1 || exit 0
