#!/usr/bin/env bash
#  Remove everything the scripts here create, in dependency order.
#
#  Destructive by definition, so it asks first.  ``FORCE=1`` skips the prompt,
#  which is for a script that is already inside somebody's own confirmation.
#
#  The bucket goes last and takes its contents with it: the material in it is
#  synthetic, and a teardown that left a bucket behind would leave the one
#  billable thing here running.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

if [[ "${FORCE:-0}" != "1" ]]; then
  cat <<PROMPT
About to delete, from project ${PROJECT_ID}:

  Cloud Run     ${SITE_SERVICE}, ${EMPLOYER_SERVICE}          (region ${REGION})
  Cloud Run     ${PROBE_JOB}, ${HERO_JOB}, ${BOOTSTRAP_JOB}   (jobs, region ${REGION})
  Secrets       ${SITE_SECRET}, ${EMPLOYER_SECRET}
  Bucket        gs://${EVIDENCE_BUCKET}  and everything in it
  Registry      ${REPO}                                        (region ${REGION})
                and both images in it: muster-agent, muster-control-plane
  Accounts      ${CONTROL_PLANE_SA_ID}, ${SITE_SA_ID}, ${EMPLOYER_SA_ID}, ${BUILD_SA_ID},
                ${MIGRATOR_SA_ID}

  NOT deleted: any Cloud SQL instance, its private-services-access range, or the
  database secrets.  Nothing here creates them, they hold the only durable state
  in this deployment, and a teardown that removed a database it did not create
  is a teardown that destroys somebody's data on a stale export.  Remove them
  deliberately, and read 'Teardown' in infra/README.md first.

PROMPT
  #  The bucket, not only the project: ``EVIDENCE_BUCKET`` is overridable
  #  from the environment and ``gcloud storage rm --recursive`` is
  #  irreversible, so a stale export in an operator's shell would destroy
  #  whichever bucket it names.
  read -r -p "type the bucket name to confirm: " confirmation
  if [[ "${confirmation}" != "${EVIDENCE_BUCKET}" ]]; then
    echo "  not confirmed; nothing was deleted"
    exit 1
  fi
fi

FAILURES=0

#  Reports what happened rather than what was attempted.  ``|| true`` followed
#  by an unconditional "removed" is how a teardown that deleted nothing reports
#  success -- and for a script whose purpose is that no billable resource and no
#  source material is left running, that failure mode is exactly backwards.
muster::remove() {
  local what="$1"
  shift
  if "$@"; then
    echo "  removed ${what}"
    return
  fi
  echo "  NOT removed: ${what}" >&2
  FAILURES=$((FAILURES + 1))
}

#  A resource that was never created is not a survivor, and reporting it as one
#  would train an operator to ignore this script's exit code.  So: describe
#  first.  Absent is "nothing to remove"; every other outcome goes through
#  ``muster::remove`` and is reported as what it is.
#
#  The caller writes the command **once**, with ``VERB`` where the verb goes,
#  so the thing that is checked and the thing that is deleted cannot address
#  different resources.  Substituted positionally rather than by searching the
#  whole command line, because a project or a bucket whose name contained the
#  word would otherwise be rewritten -- and this is the script that deletes
#  things.
muster::remove_if_present() {
  local what="$1"
  shift
  local describe=() delete=() word
  for word in "$@"; do
    if [[ "${word}" == "VERB" ]]; then
      describe+=("describe")
      delete+=("delete")
    else
      describe+=("${word}")
      delete+=("${word}")
    fi
  done
  if ! "${describe[@]}" >/dev/null 2>&1; then
    echo "  absent  ${what}"
    return
  fi
  muster::remove "${what}" "${delete[@]}" --quiet
}

muster::banner "Cloud Run services"
for service in "${SITE_SERVICE}" "${EMPLOYER_SERVICE}"; do
  muster::remove_if_present "${service}" \
    gcloud run services VERB "${service}" \
      --project="${PROJECT_ID}" --region="${REGION}"
done

#  **Both jobs, and this is the line the earlier teardown did not have.**  The
#  probe job and the hero job are created by 55-probe-job.sh and 90-hero-job.sh
#  under the control-plane identity; a teardown that deleted the services and
#  left the jobs left resources behind while claiming it had removed everything
#  -- and left the service accounts undeletable for a reason nobody would look
#  for.
muster::banner "Cloud Run jobs"
for job in "${PROBE_JOB}" "${HERO_JOB}" "${BOOTSTRAP_JOB}"; do
  muster::remove_if_present "${job}" \
    gcloud run jobs VERB "${job}" \
      --project="${PROJECT_ID}" --region="${REGION}"
done

muster::banner "secrets"
for secret in "${SITE_SECRET}" "${EMPLOYER_SECRET}"; do
  muster::remove_if_present "${secret}" \
    gcloud secrets VERB "${secret}" --project="${PROJECT_ID}"
done

#  The repository, and with it both images.  Deleting the repository rather than
#  the tags is deliberate: an image left behind is a billable artifact and a
#  copy of the source, and removing them one tag at a time is a list that goes
#  stale the next time a second image is added.
muster::banner "artifact registry"
muster::remove_if_present "${REPO}" \
  gcloud artifacts repositories VERB "${REPO}" \
    --project="${PROJECT_ID}" --location="${REGION}"

muster::banner "evidence bucket"
if gcloud storage buckets describe "gs://${EVIDENCE_BUCKET}" \
    --project="${PROJECT_ID}" >/dev/null 2>&1; then
  muster::remove "gs://${EVIDENCE_BUCKET}" \
    gcloud storage rm --recursive "gs://${EVIDENCE_BUCKET}" --project="${PROJECT_ID}"
else
  echo "  absent  gs://${EVIDENCE_BUCKET}"
fi

#  **Five accounts, not three.**  10-identities.sh creates the build identity
#  and the database migrator too, and an account left behind keeps its
#  project-level role bindings live:
#  ``muster-build`` holds artifactregistry.writer, and the two agent accounts
#  hold aiplatform.user, so a teardown that skipped one would leave a principal
#  able to push images into this project after everything it was for is gone.
muster::banner "service accounts"
accounts=("${CONTROL_PLANE_SA}" "${SITE_SA}" "${EMPLOYER_SA}" "${BUILD_SA}" "${MIGRATOR_SA}")
for account in "${accounts[@]}"; do
  muster::remove_if_present "${account}" \
    gcloud iam service-accounts VERB "${account}" --project="${PROJECT_ID}"
done

cat <<REMAINDER

  Two things are left behind on purpose, and both are named rather than hidden:

  * project-level role bindings for the deleted accounts.  They become inert
    once the principal is gone, and may be pruned with
    'gcloud projects get-iam-policy ${PROJECT_ID}' if you want them gone;

  * the Cloud Build staging bucket.  'gcloud builds submit' creates one per
    project -- typically gs://${PROJECT_ID}_cloudbuild -- and it holds the
    uploaded build context, which is source.  It is **not** deleted here
    because it is the project's, shared with every other build in it, and a
    teardown that removed a resource it did not create is a teardown that can
    break somebody else's work.  Inspect and remove it deliberately:

        gcloud storage ls gs://${PROJECT_ID}_cloudbuild
        gcloud storage rm --recursive gs://${PROJECT_ID}_cloudbuild

REMAINDER

if [[ ${FAILURES} -ne 0 ]]; then
  echo
  echo "  ${FAILURES} resource(s) were NOT removed and may still be billable, and the" >&2
  echo "  bucket may still hold source material.  Check them by hand." >&2
  exit 1
fi
