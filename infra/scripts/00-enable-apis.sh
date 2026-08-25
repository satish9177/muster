#!/usr/bin/env bash
#  Enable exactly the services this deployment uses, and no others.  Idempotent:
#  enabling an already-enabled service is a no-op.
#
#  Every line here is a decision.  A project with more APIs enabled than it uses
#  is a project where "what could this run" is a longer answer than it needs to
#  be, and a reviewer reading this file should be able to map each entry to
#  something in infra/README.md.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

muster::banner "enabling APIs on ${PROJECT_ID}"
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  aiplatform.googleapis.com \
  secretmanager.googleapis.com \
  storage.googleapis.com \
  iamcredentials.googleapis.com \
  compute.googleapis.com \
  sqladmin.googleapis.com \
  servicenetworking.googleapis.com \
  --project="${PROJECT_ID}"

#  compute, for one reason and no other: the hero job attaches Direct VPC egress
#  so that its call to an ``--ingress=internal`` agent is recognised as internal
#  traffic.  Networks and subnets are Compute Engine resources, so a project
#  without this API has no ``default`` network for the job to name and
#  90-hero-job.sh fails at deploy.  Nothing here creates or runs a VM.
echo "enabled: run, artifactregistry, cloudbuild, aiplatform, secretmanager, storage,"
echo "         iamcredentials, compute, sqladmin, servicenetworking"
