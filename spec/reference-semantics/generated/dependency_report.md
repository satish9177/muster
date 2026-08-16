# MUSTER Phase 0.8 -- dependency report

NON-PRODUCTION SPECIFICATION MATERIAL.

`forbidden(M) = AllModules \ ({M} u allowed(M))`, computed -- never hand-listed.

| Module | May import | Forbidden |
|---|---|---|
| `core` | -- (nothing in muster) | `admissibility`, `application`, `domains.procurement`, `domains.workforce`, `evidence`, `hinge`, `policy`, `solve`, `solve.reference`, `solve.z3` |
| `policy` | `core` | `admissibility`, `application`, `domains.procurement`, `domains.workforce`, `evidence`, `hinge`, `solve`, `solve.reference`, `solve.z3` |
| `solve` | `core` | `admissibility`, `application`, `domains.procurement`, `domains.workforce`, `evidence`, `hinge`, `policy`, `solve.reference`, `solve.z3` |
| `solve.z3` | `core`, `solve` | `admissibility`, `application`, `domains.procurement`, `domains.workforce`, `evidence`, `hinge`, `policy`, `solve.reference` |
| `solve.reference` | `core`, `solve` | `admissibility`, `application`, `domains.procurement`, `domains.workforce`, `evidence`, `hinge`, `policy`, `solve.z3` |
| `admissibility` | `core`, `policy` | `application`, `domains.procurement`, `domains.workforce`, `evidence`, `hinge`, `solve`, `solve.reference`, `solve.z3` |
| `hinge` | `core`, `policy`, `solve` | `admissibility`, `application`, `domains.procurement`, `domains.workforce`, `evidence`, `solve.reference`, `solve.z3` |
| `evidence` | `core`, `hinge` | `admissibility`, `application`, `domains.procurement`, `domains.workforce`, `policy`, `solve`, `solve.reference`, `solve.z3` |
| `domains.workforce` | `core`, `policy` | `admissibility`, `application`, `domains.procurement`, `evidence`, `hinge`, `solve`, `solve.reference`, `solve.z3` |
| `domains.procurement` | `core`, `policy` | `admissibility`, `application`, `domains.workforce`, `evidence`, `hinge`, `solve`, `solve.reference`, `solve.z3` |
| `application` | `core`, `policy`, `solve`, `solve.z3`, `solve.reference`, `admissibility`, `hinge`, `evidence`, `domains.workforce`, `domains.procurement` |  |

All **11** modules have a row.  Phase 0.7 had ten rows for
eleven modules: `application` was missing, so its claimed coverage was false
and, read literally, nothing was permitted to construct `Z3Backend`.

- `hinge` may import `solve` but neither adapter.
- `solve` does not import its own adapters.
- `application` -- the composition root, and only it -- may see `solve.z3`.
- `evidence` may not import a domain; the domains are independent of each other.
