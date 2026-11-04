# NurseCare Pro

A deployable starter full-stack nursing-management application based on the supplied specification.

## Stack
- React + Vite frontend
- Node.js + Express REST API
- PostgreSQL schema and migration
- JWT authentication, role checks, Argon2 password hashing
- AES-256-GCM application-layer encryption for selected sensitive patient fields
- TLS-ready deployment with Docker Compose / Nginx
- Append-only audit log table and audit helper

## Important clinical/security limitation
This is a **development starter**, not a clinically validated or production-certified EHR. Do not enter real patient data until your hospital's security, privacy, clinical governance, penetration testing, backup/restore, and regulatory reviews are complete.

"End-to-end encryption" has a specific meaning: only endpoints hold decryption keys and the server cannot read the data. That conflicts with server-side search, reporting, SBAR generation, and multi-user clinical workflows. This project therefore implements **TLS in transit + AES-256-GCM field encryption at the API layer + encrypted database/backup deployment guidance**, not strict E2EE. Use a managed KMS/HSM in production; do not store the encryption key in the database or source code.

## Quick start
1. Copy `.env.example` to `.env`.
2. Replace every secret with long random values. `FIELD_ENCRYPTION_KEY` must be exactly 32 bytes encoded as 64 hex characters.
3. Run:
   ```bash
   docker compose up --build
   ```
4. Open `http://localhost:8080`.
5. Register the first user through the API:
   ```bash
   curl -X POST http://localhost:8080/api/auth/register \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"ChangeThisLongPassword!","fullName":"Hospital Admin","role":"nurse_admin"}'
   ```
   For a real deployment, disable public registration and provision accounts through a controlled administrator process.

## Development without Docker
- PostgreSQL 16 required.
- API: `cd server && npm install && npm run dev`
- Web: `cd client && npm install && npm run dev`
- Set `DATABASE_URL`, `JWT_SECRET`, and `FIELD_ENCRYPTION_KEY` in `server/.env`.

## Included
- Login/register and role-protected API
- Patient list/create with encrypted contact/address/emergency contact fields
- SBAR report create/list/acknowledge
- Medication administration recording against existing authorized medication orders only
- Vital-sign recording
- Nursing task create/list/update
- Discharge plan creation, checklist updates, approval and guarded finalization
- PostgreSQL relational schema for the major entities in the supplied design
- Responsive dashboard UI
- TLS reverse-proxy configuration

## Not yet implemented as production services
Native Android/iOS apps, WebSocket real-time transport, PDF rendering service, MFA enrollment/recovery, KMS integration, automated backup scheduler/restore testing, hospital SSO, and formal clinical alert rules. The schema includes extension points for these. Do not represent the app as approved for clinical use.
