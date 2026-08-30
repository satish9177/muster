"""The one MUSTER image that may be public, checked for why that is safe.

Every other service here is deployed with `--no-allow-unauthenticated`, and the
reason is that each of them holds something: a signing key, a database DSN, a
read grant on a private bucket.  The judge-replay site is deployed
`--allow-unauthenticated`, and the reason *that* is safe is not a setting -- it
is that the image has nothing to hold.  A static bundle and a GET-only web
server cannot leak a credential it does not carry or mutate a record it cannot
reach.

Which makes "has nothing to hold" the property worth testing, because it is the
one a well-meaning edit destroys.  Adding a secret mount to make some feature
work, or a `proxy_pass` to reach an API "just for the demo", would each turn a
public page into a public door -- and neither would look like a security change
in review.  So the absences are asserted here, by name, next to the deployment
that relies on them.

The build flag is checked for the same reason in the other direction.  The UI
fails closed -- an ordinary production build is replay-only -- but the image
states it anyway, and a future default that flipped would be caught here rather
than by a judge finding an execute button on a hosted page.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.architecture

REPOSITORY = Path(__file__).resolve().parents[4]
DOCKERFILE = REPOSITORY / "infra/docker/judge-replay.Dockerfile"
NGINX = REPOSITORY / "infra/docker/judge-replay.nginx.conf.template"
CLOUDBUILD = REPOSITORY / "infra/cloudbuild-judge-replay.yaml"
DEPLOY = REPOSITORY / "infra/scripts/95-judge-replay.sh"
PROOF_ARTIFACT = REPOSITORY / "packages/muster-ui/public/cases/ravi-cloud-gate-proof.json"

#: Everything a MUSTER container has ever been given that this one must not be.
#: Named as the flags an operator would actually type, because that is the form
#: the mistake takes.
#:
#: ``--service-account`` is deliberately *not* in this list, and used to be.
#: Banning it did not produce a service with no identity -- it produced a
#: service whose identity nobody chose, because Cloud Run falls back to the
#: project's default compute account, which carries ``roles/editor`` unless an
#: organisation policy says otherwise. So the absence that was asserted here
#: was the absence of a *decision*, and the thing it was meant to guarantee --
#: a public container that can reach nothing -- was left to a default that
#: guarantees the opposite. The flag is required below instead, by name.
CREDENTIAL_FLAGS = (
    "--set-secrets",
    "--update-secrets",
    "--add-cloudsql-instances",
    "--vpc-connector",
    "--network",
    "--subnet",
)

#: The identity the public page runs as. An account of its own, created by the
#: same script, and granted nothing anywhere.
JUDGE_REPLAY_SA_ID = "muster-judge-replay"


def directives(path: Path) -> str:
    """The file with its commentary removed.

    These files explain themselves at length, and the explanations name the
    very things the file must not do -- "there is no ``proxy_pass`` here and
    there must never be one" is prose that would fail a naive substring check
    on the word it is warning about. What is asserted below is what the server
    and the builder are *told to do*, so the comments come out first.
    """
    return "\n".join(
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )


def test_the_image_installs_no_python_and_no_muster_distribution() -> None:
    image = directives(DOCKERFILE)
    #  A node build stage and a web server. Neither the kernel, the control
    #  plane nor the agent runtime has any business in a public page.
    assert "muster-kernel" not in image
    assert "muster-platform" not in image
    assert "muster-agents" not in image
    assert "python" not in image.lower().replace("packages/muster-ui", "")
    assert "pip install" not in image


def test_the_image_builds_the_replay_only_bundle() -> None:
    image = directives(DOCKERFILE)
    assert "ENV VITE_MUSTER_LOCAL_GATE=false" in image
    assert "npm run build" in image
    #  The bundle, not the source tree: a page that could be rebuilt at runtime
    #  would not be the page that was reviewed.
    assert "COPY --from=build /build/dist /usr/share/nginx/html" in image


def test_the_server_refuses_everything_that_is_not_a_read() -> None:
    nginx = directives(NGINX)
    assert re.search(r"limit_except\s+GET\s+HEAD\s*\{\s*deny all;\s*\}", nginx)
    assert "autoindex off;" in nginx
    #  Not one route, anywhere, that forwards a request onward. This is the
    #  single line that would turn the page into a way to reach something else.
    assert "proxy_pass" not in nginx
    #  A stale client asking for the demo API gets an honest 404 rather than
    #  the SPA fallback answering 200 with a page.
    assert re.search(r"location /api/ \{\s*return 404;", nginx)


def test_the_served_page_carries_no_credential_material() -> None:
    image = directives(DOCKERFILE)
    nginx = directives(NGINX)
    for forbidden in ("SECRET", "DSN", "PASSWORD", "PRIVATE_KEY", "signing", "credential"):
        assert forbidden.lower() not in nginx.lower(), forbidden
    for forbidden in ("--set-secrets", "SECRET_", "DATABASE_", "SIGNING_KEY"):
        assert forbidden not in image, forbidden


def test_the_deployment_is_public_and_grants_nothing() -> None:
    deploy = directives(DEPLOY)
    assert "--allow-unauthenticated" in deploy
    #  And no ingress flag. Cloud Run already defaults to `all`, while
    #  `test_no_deployment_script_broadens_the_agents_ingress` reads every
    #  script in this directory without exception -- and that rule is worth
    #  more unqualified than this line is worth explicit.
    assert "--ingress" not in deploy
    run_deploy = deploy.split("gcloud run deploy", 1)[1]
    for flag in CREDENTIAL_FLAGS:
        assert flag not in run_deploy, flag


def test_the_public_service_names_its_own_runtime_identity() -> None:
    """Because the alternative is not "no identity" -- it is the default one.

    A ``gcloud run deploy`` with no ``--service-account`` runs as the project's
    default compute service account, and that account carries ``roles/editor``
    in a project with no organisation policy saying otherwise. Left unnamed,
    the one service in this repository that is deployed to the public internet
    would be the one running as a project editor, and the script's own claim
    that it can reach nothing would be false by default.

    So the identity is named, and it is this one: an account whose only job is
    to be the principal of a static file server.
    """
    deploy = directives(DEPLOY)
    run_deploy = deploy.split("gcloud run deploy", 1)[1]
    assert '--service-account="${JUDGE_REPLAY_SA}"' in run_deploy
    assert f'JUDGE_REPLAY_SA_ID:={JUDGE_REPLAY_SA_ID}' in deploy
    assert 'JUDGE_REPLAY_SA="${JUDGE_REPLAY_SA_ID}@${PROJECT_ID}' in deploy
    #  Not one of the identities the proved deployment runs on. Reusing the
    #  control plane's or an agent's account would hand a public container
    #  every grant that was written for a private one.
    for proved in ("CONTROL_PLANE_SA", "SITE_SA", "EMPLOYER_SA", "MIGRATOR_SA"):
        assert proved not in run_deploy, proved


def test_the_public_services_identity_is_created_and_granted_nothing() -> None:
    """Created by the script that uses it, and given no role by anything.

    The account has to exist before the deploy names it, and it has to stay
    empty afterwards. Both halves are checked here rather than trusted, because
    a later edit that "just needs one read role" to make some feature work is
    exactly how a page with nothing to protect acquires something to protect.
    """
    deploy = directives(DEPLOY)
    assert 'gcloud iam service-accounts create "${JUDGE_REPLAY_SA_ID}"' in deploy
    #  No binding, anywhere in the file. Not a narrow one, not a read one.
    assert "add-iam-policy-binding" not in deploy
    assert "--role" not in deploy
    #  And no other script grants it either.
    scripts = (REPOSITORY / "infra" / "scripts").glob("*.sh")
    for path in sorted(scripts):
        if path.name == DEPLOY.name:
            continue
        assert JUDGE_REPLAY_SA_ID not in directives(path), path.name


def test_the_public_image_is_built_apart_from_the_proved_images() -> None:
    """The proof's provenance must not move when a page changes.

    ``infra/cloudbuild.yaml`` builds the agent and control-plane pair, and the
    digest of that control-plane image is written into the architecture
    document and the tracked proof record as the image the final GCP proof ran
    on.  A third image in that config would mean a CSS change could produce a
    new build of the images the proof names.
    """
    judge = directives(CLOUDBUILD)
    proved = directives(REPOSITORY / "infra/cloudbuild.yaml")
    assert "judge-replay.Dockerfile" in judge
    assert "judge-replay" not in proved
    assert "control-plane.Dockerfile" not in judge
    assert "agent.Dockerfile" not in judge


def test_the_hosted_bundle_serves_the_tracked_replay_artifacts() -> None:
    """The evidence is a file in the repository, not a call to anything."""
    nginx = directives(NGINX)
    assert "location /cases/" in nginx
    assert PROOF_ARTIFACT.is_file()
