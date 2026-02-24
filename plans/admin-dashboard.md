# Admin Dashboard Plan

## Scope

Admin dashboard covers users, equipment, categories, and stats only.  
`messages` is out of scope until there is a backend admin messages API.

## Auth Guard Contract

- Backend user-info endpoint remains `/api/auth/me`.
- Frontend admin guard fetches `/api/proxy/api/auth/me` (proxy to backend endpoint above).
- Backend admin routes stay under `/api/admin/*` and are protected by admin-only checks in `src/api/routes/admin.rs`.

## Endpoint Contract (Including Query Params)

| Method | Path | Query Params | Notes |
|------|------|------|------|
| `GET` | `/api/admin/stats` | none | counts only |
| `GET` | `/api/admin/users` | `page`, `per_page`, `search`, `role` | maps to `AdminListQuery` |
| `GET` | `/api/admin/users/{id}` | none | user detail |
| `PUT` | `/api/admin/users/{id}/role` | none | role mutation |
| `DELETE` | `/api/admin/users/{id}` | none | user deletion policy below |
| `GET` | `/api/admin/equipment` | `page`, `per_page`, `search` | `role` is ignored for equipment |
| `DELETE` | `/api/admin/equipment/{id}` | none | forced listing delete |
| `PUT` | `/api/admin/equipment/{id}/availability` | none | availability toggle |
| `GET` | `/api/admin/categories` | none | category list |
| `POST` | `/api/admin/categories` | none | create |
| `PUT` | `/api/admin/categories/{id}` | none | update |
| `DELETE` | `/api/admin/categories/{id}` | none | deletion policy below |

## Admin Safety Rules

- Keep existing self-protection:
  - admin cannot demote self away from `admin`
  - admin cannot delete self
- Add last-admin protection:
  - reject role change or deletion when target is the last remaining `admin` (`409 Conflict`)
- User deletion and equipment handling policy:
  - reject user deletion if target user still owns equipment (`409 Conflict`)
  - response includes equipment count so UI can instruct admin to transfer/delete equipment first

## Audit Logging (Privileged Operations)

Add immutable audit events for:
- `PUT /api/admin/users/{id}/role`
- `DELETE /api/admin/users/{id}`
- `DELETE /api/admin/equipment/{id}`
- `PUT /api/admin/equipment/{id}/availability`
- `POST|PUT|DELETE /api/admin/categories/*`

Required event fields:
- `actor_id`
- `action`
- `target_type`
- `target_id`
- `old_value` (when applicable)
- `new_value` (when applicable)
- `timestamp`
- `trace_id` (if available)

Emit from `AdminService` at mutation time (after validation, around state change).

## Categories: Reorder + Delete Policy

- Drag-reorder is not implemented by current API/schema and is not part of baseline delivery.
- Reorder can be added only after:
  - persistent `display_order` field
  - reorder endpoint (batch update)
  - deterministic sort in list endpoint
- Category deletion policy:
  - reject deletion when category is referenced by equipment (`409 Conflict`)
  - frontend confirmation text must match backend-enforced rule

## Layout and Heading Consistency

- Use one shared admin layout shell for all `/admin/*` pages (sidebar + header).
- Each admin page uses a static `<h1>` page title (no dynamic heading swaps).
- Breadcrumbs, if shown, are secondary and must not replace the static page heading.
