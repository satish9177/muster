# Live model run — Gemini 3.7 Flash and Gemma 4

Recorded 2026-08-31, `demo/hero.py --live`, from a clean checkout of this
repository. Two Google AI models are called over the network in this run:

| Model | Access path | Role |
|---|---|---|
| `gemini-3.7-flash` | Vertex AI, `GOOGLE_CLOUD_LOCATION=global` | Institutional Employer and Site source agents — evidence interpretation |
| `gemma-4-26b-a4b-it` | Gemini Developer API (`generativelanguage.googleapis.com`) | Worker claim intake — unsigned, institutionally inert |

Reproduce it with the environment documented in the README's live-model
section:

```bash
./.venv/bin/python demo/hero.py --live
```

## Transcript

```
WORKER AGENT
  model      gemma-4-26b-a4b-it
  role       unverified claim intake
  claim      present_on_site(RAVI, SAT) = true
  by         RAVI as WORKER
  authority  NONE · unsigned claim
  effect     none: a claim is not a justification variant

ANALYSIS BEFORE ACQUISITION
  request    080f111e08e0bbea
  needs      scheduled(RAVI, SAT) from HR_PAYROLL_SYSTEM
  needs      present_on_site(RAVI, SAT) from SITE_ACCESS_CONTROL
  needs      on_site_duration(RAVI, SAT) from SITE_ACCESS_CONTROL

FLEET
  agent      agent-hr-payroll  at local://agent-hr-payroll
  attested   scheduled(RAVI, SAT)  admitted through Q-12
  agent      agent-site-a  at local://agent-site-a
  attested   present_on_site(RAVI, SAT)  admitted through Q-12
  attested   on_site_duration(RAVI, SAT)  admitted through Q-12

RESULT
  status     PROPOSED
  outcome    INVARIANT
  action     PAY  recipient=RAVI  amount=INR 5,100.00
  unresolved on_site_duration(RAVI, SAT), shift_payable_under_policy(RAVI, SAT)

  MUSTER has not decided that Ravi worked.  It has decided that his
  Saturday shift is payable under the pinned policy, on attested grounds.
```

Note what the transcript shows about the two models' *authority*, which is the
point of running both. Gemma's output is a claim with `authority NONE` and
`effect none`. Gemini's output arrives through Q-12 as an attested source
statement and is what the kernel is allowed to reason from. Swapping either
model changes which evidence is acquired; it cannot change what follows from
the evidence, because the deciding step is deterministic and reads only the
admitted attestations.

## The Gemma call is a real network call

A label in a transcript is not evidence that a model ran. The differential
below is: re-running the identical command with an invalid Gemini Developer API
key, and nothing else changed, fails at the Gemma call.

```
$ GEMINI_API_KEY=invalid-key-differential-check ./.venv/bin/python demo/hero.py --live

google.genai.errors.ClientError: 400 INVALID_ARGUMENT. {'error': {'code': 400,
'message': 'API key not valid. Please pass a valid API key.', 'status':
'INVALID_ARGUMENT', 'details': [{'@type':
'type.googleapis.com/google.rpc.ErrorInfo', 'reason': 'API_KEY_INVALID',
'domain': 'googleapis.com', 'metadata': {'service':
'generativelanguage.googleapis.com'}}, ...]}}

the worker agent produced no claim: ClaimRejection(
    failure=<ClaimFailure.MODEL_ERROR: 'MODEL_ERROR'>, detail='ClientError')

exit status 1
```

The rejecting service is `generativelanguage.googleapis.com` — the Gemini
Developer API endpoint that serves Gemma — so the successful run above did
reach that service. The failure is also handled the way the rest of the system
handles an unusable source: the worker claim becomes a `ClaimRejection` rather
than a fabricated claim.

## Where each model is configured

`packages/muster-agents/src/muster/agents/config.py`:

- `DEFAULT_MODEL = "gemini-3.7-flash"` with `DEFAULT_MODEL_LOCATION = "global"`
  — the pairing is chosen together, because a model is served in some locations
  and not others.
- `DEFAULT_CLAIM_MODEL = "gemma-4-26b-a4b-it"` — never a Cloud Run default,
  never granted source authority or a signing capability.

Both are configuration rather than literals, and both are recorded as telemetry
on the run rather than pinned as semantic inputs to it.
