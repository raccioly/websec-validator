# Security constitution

> Invariants this app must uphold, derived from recon. The dynamic probes verify them; a dynamically-confirmed finding flips one to 🔴 VIOLATED. Treat ⬜ as a hypothesis to confirm.

**13 invariants · 0 VIOLATED · 13 to verify**

## Authentication
- ⬜ verify — Given no auth token, When `GET /`, Then 401/403 (no body, no mutation)  ·  _openapi_specs/openapi3.yml_
- ⬜ verify — Given no auth token, When `GET /books/v1`, Then 401/403 (no body, no mutation)  ·  _openapi_specs/openapi3.yml_
- ⬜ verify — Given no auth token, When `POST /books/v1`, Then 401/403 (no body, no mutation)  ·  _openapi_specs/openapi3.yml_
- ⬜ verify — Given no auth token, When `GET /books/v1/{book_title}`, Then 401/403 (no body, no mutation)  ·  _openapi_specs/openapi3.yml_
- ⬜ verify — Given no auth token, When `GET /createdb`, Then 401/403 (no body, no mutation)  ·  _openapi_specs/openapi3.yml_
- ⬜ verify — Given no auth token, When `GET /me`, Then 401/403 (no body, no mutation)  ·  _openapi_specs/openapi3.yml_
- ⬜ verify — Given no auth token, When `GET /users/v1`, Then 401/403 (no body, no mutation)  ·  _openapi_specs/openapi3.yml_
- ⬜ verify — Given no auth token, When `DELETE /users/v1/{username}`, Then 401/403 (no body, no mutation)  ·  _openapi_specs/openapi3.yml_
- ⬜ verify — Given no auth token, When `GET /users/v1/{username}`, Then 401/403 (no body, no mutation)  ·  _openapi_specs/openapi3.yml_
- ⬜ verify — Given no auth token, When `PUT /users/v1/{username}/email`, Then 401/403 (no body, no mutation)  ·  _openapi_specs/openapi3.yml_
- ⬜ verify — Given no auth token, When `PUT /users/v1/{username}/password`, Then 401/403 (no body, no mutation)  ·  _openapi_specs/openapi3.yml_
- ⬜ verify — Given no auth token, When `GET /users/v1/_debug`, Then 401/403 (no body, no mutation)  ·  _openapi_specs/openapi3.yml_

## Secret hygiene
- ⬜ verify — Given the repo + git history, Then no live credential is present and no secret reaches the client bundle  ·  _recon_
