#!/bin/bash
set -u
AWS_PROFILE=$1
S3_BUCKET_NAME=$2
CWD=$(pwd)

cd ../lambdazip || exit 1

zip -g ct_flowlog_activator.zip ../code/ct_flowlog_activator.py
zip -g ct_flowlog_lifecycle.zip ../code/ct_flowlog_lifecycle.py
aws s3 cp ./ct_flowlog_activator.zip "s3://${S3_FUNCTIONS_BUCKET_NAME}/ct_flowlog_activator.zip" --profile "${AWS_PROFILE}" 
aws s3 cp ./ct_flowlog_lifecycle.zip "s3://${S3_FUNCTIONS_BUCKET_NAME}/ct_flowlog_lifecycle.zip" --profile "${AWS_PROFILE}"

cd "${CWD}" || exit 1