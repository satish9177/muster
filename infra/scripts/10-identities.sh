#!/usr/bin/env bash
#  Three service accounts, and the asymmetry between them is the architecture.
#
#  The control plane gets NOTHING here.  Not a narrow role, not a read role,
#  none.  Everything it is allowed to do is granted later and per resource: an
#  invoker binding on each agent service, and that is all.  If a later script
#  fails because the control plane cannot reach something, the fix is almost
#  never to grant it a role -- it is to check whether the thing it is reaching
#  for is something a control plane should be able to reach at all.
#
#  Idempotent: accounts that exist are left alone, and add-iam-policy-binding is
#  itself idempotent.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

muster::create_sa() {
  local id="$1" title="$2"
  if gcloud iam service-accounts describe "${id}@${PROJECT_ID}.iam.gserviceaccount.com" \
      --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "  exists  ${id}"
    return
  fi
  gcloud iam service-accounts create "${id}" \
    --project="${PROJECT_ID}" --display-name="${title}"
  echo "  created ${id}"
}

muster::banner "service accounts"
muster::create_sa "${CONTROL_PLANE_SA_ID}" "MUSTER control plane"
muster::create_sa "${SITE_SA_ID}"          "MUSTER site agent (SITE-A)"
muster::create_sa "${EMPLOYER_SA_ID}"      "MUSTER employer agent (EMPLOYER-1)"
muster::create_sa "${BUILD_SA_ID}"         "MUSTER image builds"
#  The database migrator, and it gets nothing here either.  It exists to hold
#  one capability the control plane must not have -- DDL against the control
#  plane's database -- and holding it is the whole reason it is a separate
#  account.  Its only grants are per secret, written when those secrets are
#  created, and 70-verify-iam.sh asserts the rest as refusals: it reads no
#  evidence, no signing key, and not the runtime's credential.
muster::create_sa "${MIGRATOR_SA_ID}"      "MUSTER database migrator"

muster::banner "project-level grants"
#  Vertex AI is a project-scoped API: there is no per-model or per-region role,
#  so roles/aiplatform.user is granted at the project and that is the narrowest
#  form available.  It is stated here rather than buried, because it is the one
#  project-wide grant in this deployment and a reviewer should see it.
for account in "${SITE_SA}" "${EMPLOYER_SA}"; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${account}" \
    --role="roles/aiplatform.user" \
    --condition=None >/dev/null
  echo "  granted roles/aiplatform.user to ${account} (project)"
done

#  The build identity, granted only what a build needs: push an image, write
#  logs.  Explicitly **not** a storage reader -- a build that could read the
#  evidence bucket would be a path around every binding the next script writes,
#  available to anybody who can start a build.
for role in roles/artifactregistry.writer roles/logging.logWriter; do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}"     --member="serviceAccount:${BUILD_SA}"     --role="${role}"     --condition=None >/dev/null
  echo "  granted ${role} to ${BUILD_SA} (project)"
done

cat <<'TABLE'

  principal              role                             resource   why
  --------------------------------------------------------------------------------
  muster-site-agent      roles/aiplatform.user            project    calls Gemini to
                                                                     read its own
                                                                     material
  muster-employer-agent  roles/aiplatform.user            project    the same, for
                                                                     payroll records
  muster-build           roles/artifactregistry.writer    project    pushes the agent
                         roles/logging.logWriter                     image
  muster-control-plane   (nothing here)                   --         it interprets
                                                                     nothing and reads
                                                                     no source
  muster-database-       (nothing here)                   --         DDL only, and
  migrator                                                           only against the
                                                                     control plane's
                                                                     own database

  The last row is the one to check.  The control plane is granted exactly two
  things, both later and both per resource: run.invoker on each agent service
  (60-invoker.sh), and nothing else anywhere.  If a later script fails because
  the control plane cannot reach something, the fix is almost never to grant it
  a role -- it is to ask whether a control plane should be able to reach that.

TABLE
