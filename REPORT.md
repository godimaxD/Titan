# Product Fixes & Enhancements Report

## Methods & Panel Safety
- Ensured admin-managed methods are tagged by layer in the database and validated per layer on panel launches (L4/L7).
- Hardened API attack submissions by enforcing method-layer matching against stored methods.

## Plans & UX
- Seeded a default Free plan (1 concurrent, 60s) and normalized users missing a plan to Free.
- Updated profile and market pages to surface plan limits and highlight the current plan (with a Free plan card).

## Referral Revenue Share
- Added a referral credits ledger to make earnings auditable and idempotent per purchase.
- Updated purchase flow to credit referrers 15% for each paid purchase while blocking self-referral credits.

## Tests
- Added coverage for method layer filtering, Free plan defaults, market current-plan rendering, and referral credit rules.
