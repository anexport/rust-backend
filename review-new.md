Starting CodeRabbit review in plain text mode...

Connecting to review service
Setting up
Analyzing
Reviewing

============================================================================
File: frontend/src/components/admin/ConfirmDialog.tsx
Line: 53
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/components/admin/ConfirmDialog.tsx at line 53, The dialog can still be dismissed via ESC/overlay because onOpenChange={setOpen} doesn't respect the in-flight state; change the onOpenChange handler on Dialog to check isPending and ignore attempts to close the dialog while isPending is true (i.e., if nextOpen is false and isPending, do nothing), otherwise call setOpen(nextOpen); keep using the existing open and isPending variables and ensure Dialog, setOpen, open, and isPending are the symbols you modify.



============================================================================
File: frontend/src/components/admin/DataTable.tsx
Line: 28 to 33
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/components/admin/DataTable.tsx around lines 28 - 33, The TableCell in DataTable.tsx uses colSpan={headers.length}, which can be 0 when headers is empty and is invalid HTML; update the TableCell (in the empty-rows branch that renders emptyLabel) to guarantee colSpan is at least 1 (e.g., use Math.max(1, headers.length) or headers.length || 1) so the rendered colSpan never becomes 0; this change should be applied where rows, headers, emptyLabel and the TableCell are referenced.



============================================================================
File: src/api/dtos/admin_dto.rs
Line: 76 to 85
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/dtos/admin_dto.rs around lines 76 - 85, The AdminEquipmentRow struct currently has non-optional owner_email and category_name which will panic on NULL joins; verify the DB/query guarantees non-null, and if not change owner_email: String and category_name: String to owner_email: Option and category_name: Option in AdminEquipmentRow, update callers/serializers accordingly, and apply the same PII redaction approach used on AdminUserRow to owner_email (replace raw debug/serialize exposure with the redacted pattern used in AdminUserRow) so runtime NULLs are handled and email is not leaked by Debug.



============================================================================
File: src/api/dtos/admin_dto.rs
Line: 8 to 14
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/dtos/admin_dto.rs around lines 8 - 14, AdminListQuery currently allows negative pagination because page and per_page are plain i64; update the AdminListQuery struct to derive validation (e.g., add a Validate/validator derive) and annotate page and per_page with range constraints (e.g., minimum 1, and optionally a sensible max for per_page) so inputs like page = -1 or per_page = -100 are rejected early; specifically modify the AdminListQuery definition to include the validation derive and add #[validate(range(min = 1))] (and optionally max) on the page and per_page fields so request-level validation fails before hitting service/DB logic.



============================================================================
File: src/api/dtos/admin_dto.rs
Line: 95 to 98
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/dtos/admin_dto.rs around lines 95 - 98, The AdminUpdateAvailabilityRequest currently defines is_available as Option, which allows empty/no-op payloads; change it to a required bool or add validation to reject None so clients get an explicit error. Update the struct AdminUpdateAvailabilityRequest by making the field pub is_available: bool (preferred simple fix), or keep Option and derive/implement Validate and add a constraint that returns an error when is_available is None so the request handler never silently no-ops.



============================================================================
File: plans/admin-dashboard.md
Line: 41 to 52
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @plans/admin-dashboard.md around lines 41 - 52, The plan currently mixes a diagram for a dedicated middleware (AdminGuard) with a spec that uses inline per-handler checks (like the owner check in create_equipment), which is error-prone; replace the inline pattern by implementing an Actix extractor type (e.g., AdminUser wrapping Auth0UserContext) that enforces role == "admin" in its FromRequest impl and use that extractor as a required argument on all admin handlers in the new admin routes module so any handler signature requiring _admin: AdminUser is automatically protected; update the admin routes registration to require the AdminUser extractor instead of relying on per-handler inline checks.



============================================================================
File: plans/admin-dashboard.md
Line: 108 to 115
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @plans/admin-dashboard.md around lines 108 - 115, The role-change and deletion flows (update_user_role and delete_user) do not prevent removing the last remaining admin and do not define cascade behavior for a user's owned equipment; add a count_admins() -> AppResult check and call it at the start of update_user_role (when downgrading from admin) and delete_user (when deleting an admin) to block the operation if count == 1, and implement an explicit equipment strategy in delete_user for the user's owned listings (choose and implement one option consistently: soft-delete their Equipment rows, reassign owner_id to a dedicated system account, or refuse deletion while active listings exist) so FK constraints and orphaned owner_id are handled deterministically.



============================================================================
File: plans/admin-dashboard.md
Line: 59
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @plans/admin-dashboard.md at line 59, Update the endpoint documentation row(s) for GET /api/admin/users and GET /api/admin/equipment to list the supported query parameters used by the service and frontend (e.g., search_query/search, role, sort_by, sort_dir, page, per_page); reference the same parameter names used in the service (search_query) and the frontend descriptions (role-filter, sortable columns) so implementers know which keys to send and expected behavior for pagination, filtering and sorting. Ensure the table entries explicitly show parameter examples or a parenthetical list like (?search=, ?role=, ?sort_by=, ?sort_dir=, ?page=, ?per_page=) and keep naming consistent with the service code (search_query) or add a mapping note if you prefer a different query key.



============================================================================
File: plans/admin-dashboard.md
Line: 76 to 77
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @plans/admin-dashboard.md around lines 76 - 77, AdminStatsResponse currently only contains counts but the Stats page needs a recent-activity feed; either extend the AdminStatsResponse struct to include recent_users: Vec and recent_equipment: Vec (or appropriately named DTOs) and populate them from new repository helpers list_recent_users(limit) and list_recent_equipment(limit), or add a new endpoint /api/admin/activity that returns those two arrays and implement corresponding controller/handler and repo methods list_recent_users(limit) and list_recent_equipment(limit) so the front-end can request the last 5 users and last 5 listings.



============================================================================
File: plans/admin-dashboard.md
Line: 76 to 83
Type: refactor_suggestion

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @plans/admin-dashboard.md around lines 76 - 83, The AdminUpdateRoleRequest currently accepts role: String which lets invalid values slip through; change it to use a UserRole enum (or reuse the existing one) and derive serde::Deserialize (and Serialize if needed) with #[serde(rename_all = "lowercase")] so Serde rejects invalid role values at deserialization; update the AdminUpdateRoleRequest definition to reference UserRole instead of String and adjust any handlers, request parsing, and tests that construct AdminUpdateRoleRequest to use the enum variants or lowercase strings.



============================================================================
File: plans/admin-dashboard.md
Line: 58 to 69
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @plans/admin-dashboard.md around lines 58 - 69, The plan lacks audit logging for privileged operations (PUT /api/admin/users/{id}/role, DELETE /api/admin/users/{id}, DELETE /api/admin/equipment/{id} and similar Admin endpoints); add an audit trail by creating an admin_audit_log (or structured log sink) capturing actor_id, action, target_type, target_id, old_value, new_value, timestamp (and optional metadata like ip/trace_id), and emit a record from the corresponding AdminService methods (e.g., AdminService.changeUserRole, AdminService.deleteUser, AdminService.forceDeleteEquipment) immediately before/after the state change so the log contains both old_value and new_value and is durable/immutable for compliance.



============================================================================
File: plans/admin-dashboard.md
Line: 5
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @plans/admin-dashboard.md at line 5, The plan lists "messages" as a managed resource but nothing implements it; either remove "messages" from the admin dashboard scope or implement the full stack for messages: add a Messages DTO (e.g., MessageCreate/MessageDTO), repository methods (e.g., MessagesRepository::create, ::list, ::get, ::delete), service methods (e.g., MessagesService::create_message, ::list_messages), backend routes/handlers (e.g., GET/POST/DELETE /admin/messages guarded by map_auth0_role() admin check), and a frontend Messages page/component wired into the admin dashboard; pick one approach and update the plan and code to be consistent.



============================================================================
File: plans/admin-dashboard.md
Line: 182 to 185
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @plans/admin-dashboard.md around lines 182 - 185, The drag-to-reorder stretch goal requires adding an explicit sort field and repo/service support: add a display_order (or sort_order) attribute to the Category model and include it in AdminCategoryRequest, then implement reorder/update_order methods on CategoryRepository and corresponding service/controller handlers (e.g., CategoryService.reorderCategories or CategoryController.reorder) to accept and persist the new ordering; update frontend spec to send the new order payload. For deletion, decide and document the canonical behavior in the Categories page (block deletion if listings exist, nullify FK, or cascade-delete) and then implement it consistently by either checking CategoryRepository for listingCount and blocking with a validation error, or by configuring DB/ORM cascade rules and adding repository method (e.g., CategoryRepository.deleteWithCascade) and service-level confirmation behavior to match the chosen policy.



============================================================================
File: src/api/dtos/admin_dto.rs
Line: 57 to 68
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/dtos/admin_dto.rs around lines 57 - 68, AdminUserDetailResponse currently derives Debug and leaks PII (email, full_name, avatar_url); implement a custom fmt::Debug for AdminUserDetailResponse that mirrors AdminUserRow's redaction behaviour by formatting id, role, username, created_at, updated_at, equipment_count normally but replacing email, full_name and avatar_url with a redacted placeholder (e.g. "[redacted]"); keep Serialize derive intact and implement Debug by adding a fmt::Debug impl for the AdminUserDetailResponse type that emits the same field names as the struct but redacts those three sensitive fields.



============================================================================
File: plans/admin-dashboard.md
Line: 130 to 132
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @plans/admin-dashboard.md around lines 130 - 132, Step 1's proxy call uses the redundant path string "/api/proxy/api/auth/me" which likely double-includes "/api/"; update the spec to call the intended proxied endpoint (e.g. "/api/proxy/auth/me") in the guard that then checks user.role === "admin" and redirects to "/" with a toast if not admin, or clarify the proxy mounting behavior if the original double "/api/" was intentional.



============================================================================
File: frontend/src/app/admin/categories/page.tsx
Line: 36 to 55
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/app/admin/categories/page.tsx around lines 36 - 55, The createCategory handler (and the other mutation handlers referenced) lack a submitting guard, allowing duplicate requests; add an isSubmitting (or per-operation boolean) state in the component, set isSubmitting = true at the start of createCategory and reset to false in both success and error paths (also in finally if using try/catch), and update the corresponding buttons (the "Add Category" and the save/delete buttons referenced around those other handlers) to be disabled and show a spinner or loading text while isSubmitting is true; ensure you reference and update the state in createCategory and the other mutation functions so users cannot double-submit during in-flight requests.



============================================================================
File: src/infrastructure/repositories/category_repository.rs
Line: 85 to 94
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/infrastructure/repositories/category_repository.rs around lines 85 - 94, The delete method currently awaits the sqlx query and lets any DB errors propagate, so FK violations when deleting a parent category surface as raw sqlx errors; modify the async fn delete(&self, id: Uuid) to explicitly match the result of .execute(&self.pool).await: if it Errs, inspect the sqlx::Error (match Error::Database(db) or use db.is_foreign_key_violation() / ErrorKind::ForeignKeyViolation) and map FK violations to a clear AppError (e.g., AppError::Conflict or a new variant with message like "category has child categories"), otherwise propagate other DB errors; keep the existing rows_affected() == 0 check to return AppError::NotFound when no rows were deleted.



============================================================================
File: src/infrastructure/repositories/category_repository.rs
Line: 51 to 66
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/infrastructure/repositories/category_repository.rs around lines 51 - 66, The INSERT/UPDATE currently uses ? which propagates raw sqlx::Error for constraint violations; change the .await? on the fetch (in the create function and likewise in the update function) to .await.map_err(|e| { / map unique violations to AppError::Conflict / })? so you can inspect e for sqlx::Error::Database(db_err) and then use db_err.is_unique_violation() (or ErrorKind::UniqueViolation) to return a typed AppError (e.g., conflict/duplicate) and otherwise convert other errors into the existing AppError variant; update both create and update to use this mapping before returning the result.



============================================================================
File: src/application/admin_service.rs
Line: 131 to 132
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/application/admin_service.rs around lines 131 - 132, The update path currently calls self.user_repo.update_role(target_id, new_role).await? and then self.get_user_detail(target_id).await so a missing target_id can silently succeed on update and only fail on the subsequent read; change this by either (preferred) updating user_repo.update_role to return an error when zero rows were affected (e.g., Err(NotFound) from update_role) so callers get immediate feedback, or add an explicit pre-check in the service: call self.user_repo.find_by_id(target_id).await? and return NotFound before calling update_role; ensure references to update_role, get_user_detail, user_repo, target_id and new_role are updated accordingly so the service surfaces a NotFound when the target does not exist.



============================================================================
File: src/application/admin_service.rs
Line: 177 to 180
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/application/admin_service.rs around lines 177 - 180, The three admin methods (force_delete_equipment, toggle_equipment_availability, delete_category) currently discard the actor_id (let _ = actor_id) which removes any audit trail; update each method to record who performed the action before mutating state — either emit a structured tracing audit log (e.g. tracing::info!(actor = %actor_id, target = %id, action = "...")) or persist an AuditRecord via your audit store/repo, then proceed to call equipment_repo.delete or the relevant repo method; if you truly do not want caller identity, remove actor_id from the public API (function signature) to avoid misleading callers.



============================================================================
File: frontend/src/app/admin/categories/page.tsx
Line: 23 to 30
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/app/admin/categories/page.tsx around lines 23 - 30, The async functions load, createCategory, updateCategory, and deleteCategory call fetchClient without try/catch so network errors cause unhandled rejections; wrap each function body in a try/catch, await fetchClient inside the try, handle non-ok responses as now, and in the catch show a user-facing toast.error (and optionally processLogger.error) with the caught error message and return early so state updates (e.g., setCategories) are not attempted after a network failure; ensure the same pattern is applied to all four functions referenced above.



============================================================================
File: src/application/admin_service.rs
Line: 212 to 217
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/application/admin_service.rs around lines 212 - 217, Validate payload.parent_id before persisting in both create_category and update_category: if Some(parent_id) call the repository's find_by_id (or equivalent) to ensure the parent category exists, return a clear validation error if not found; in update_category also reject parent_id == id to prevent self-reference, and to prevent circular hierarchies walk the parent chain (repeatedly calling find_by_id on each parent_id) to ensure the updated parent is not a descendant of the current category before saving. Use the Category struct, payload.parent_id, create_category, update_category and the repo's find_by_id to locate and validate ancestors.



============================================================================
File: frontend/src/app/admin/layout.tsx
Line: 46 to 51
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/app/admin/layout.tsx around lines 46 - 51, The layout currently renders a hardcoded  "Admin Dashboard" in frontend/src/app/admin/layout.tsx which causes every admin sub-page to announce the same heading; remove that static  (keep or move the badge/span if desired) and either (A) add unique  elements inside each admin sub-page's page.tsx (Users, Equipment, Categories) or (B) make the layout accept a page title (e.g., a title prop or React context like AdminLayoutContext) and have each page provide its own title so the layout renders a dynamic  per route; update AdminLayout (the layout component) and the individual page.tsx files accordingly so each page has a unique, descriptive .



============================================================================
File: frontend/src/app/admin/categories/page.tsx
Line: 87 to 98
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/app/admin/categories/page.tsx around lines 87 - 98, The parent column currently prints the raw UUID via category.parent_id; instead look up the parent category name from the local categories array and render that (fall back to '-' when no parent or not found). In the rows construction in page.tsx (where categories.map is used and symbols include categories, category, rows), replace the parent cell value from category.parent_id || '-' to a resolved lookup like finding categories.find(p => p.id === category.parent_id)?.name || '-' so admins see the parent category name instead of the UUID.



============================================================================
File: src/application/admin_service.rs
Line: 189 to 199
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/application/admin_service.rs around lines 189 - 199, The current read-modify-write in toggle uses equipment_repo.find_by_id -> mutate equipment.is_available/updated_at -> equipment_repo.update which creates a TOCTOU race; change to either implement optimistic locking on the Equipment entity (add a version or use updated_at) and make equipment_repo.update accept the previous version/updated_at and perform UPDATE ... WHERE id = $id AND version = $old_version (or updated_at = $old_updated_at) returning success/failure, or replace the logic with a single atomic repository method (e.g. equipment_repo.toggle_availability(id, requested_state) or equipment_repo.update_availability(id, new_state)) that issues an UPDATE equipment SET is_available = $1, updated_at = $2 WHERE id = $2 and returns the final is_available, so concurrent updates cannot be lost; update call sites to handle conflict/failure accordingly.



============================================================================
File: frontend/src/app/admin/categories/page.tsx
Line: 99 to 117
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/app/admin/categories/page.tsx around lines 99 - 117, When editingId === category.id, prevent destructive or resetting actions: disable or hide the Edit Button (the onClick that calls setEditingId and setEditingName) so clicking it doesn't reset editingName, and change the ConfirmDialog trigger (deleteCategory) to be disabled or show a different flow while editing to avoid immediate delete prompts; also add a visible "Cancel" action that clears the edit state (call setEditingId(null) and keep editingName as needed) so users can explicitly abandon edits. Update the JSX around Button, ConfirmDialog, and the handlers (setEditingId, setEditingName, deleteCategory) to check editingId === category.id and conditionally render/disable Edit, render a Cancel button, and disable the ConfirmDialog trigger while editing.



============================================================================
File: src/application/admin_service.rs
Line: 73 to 85
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/application/admin_service.rs around lines 73 - 85, The loop in admin_service.rs is causing an N+1 by calling self.equipment_repo.find_by_owner(user.id) for each user; add a new repository method EquipmentRepository::count_by_owner(owner_id: Uuid) -> AppResult and replace the per-user find_by_owner(...) calls with count_by_owner(...) to return only the count; for a better fix implement a bulk method like EquipmentRepository::count_by_owners(owner_ids: &[Uuid]) -> AppResult> that issues a single GROUP BY query (SELECT owner_id, COUNT(*) ... WHERE owner_id = ANY($1) GROUP BY owner_id) and use that in admin_service.rs to populate equipment_count for each AdminUserRow.



============================================================================
File: src/application/admin_service.rs
Line: 48
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/application/admin_service.rs at line 48, The code is doing a full-table fetch with self.category_repo.find_all().await?.len() to compute total_categories; add a count_all method to the CategoryRepository trait and its concrete implementation (following the existing count_all pattern from UserRepository/EquipmentRepository), implement it to run a COUNT(*) query returning i64, and change admin_service.rs to call self.category_repo.count_all().await? (or the appropriate Result-wrapped return) instead of fetching all rows and using len().



============================================================================
File: frontend/src/app/admin/layout.tsx
Line: 19
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/app/admin/layout.tsx at line 19, The nested admin layout currently renders a  landmark which can create duplicate main elements; update the Admin layout component in frontend/src/app/admin/layout.tsx to replace the  with a neutral wrapper element (e.g., ) while preserving the same className and children/props so visual styling and composition remain unchanged; keep the single  landmark in the root app/layout.tsx and do not introduce any new landmark roles here.



============================================================================
File: src/api/routes/admin.rs
Line: 129 to 141
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/routes/admin.rs around lines 129 - 141, The handler toggle_equipment_availability is misnamed (it doesn't flip state) and uses an untyped serde_json::json! response; rename the handler to set_equipment_availability, update the route segment and calls to admin_service.toggle_equipment_availability to a new admin_service.set_equipment_availability(actor_id, equipment_id, is_available) method (keeping AdminUpdateAvailabilityRequest as the request type), and replace the ad-hoc JSON response with a small typed response struct (e.g., AvailabilityResponse deriving Serialize with field is_available) and return that typed struct from the handler.



============================================================================
File: src/api/routes/admin.rs
Line: 11 to 30
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/routes/admin.rs around lines 11 - 30, The admin role check is currently done per-handler via require_admin which is error-prone; update the configure function to wrap the entire web::scope("/admin") with a scope-level middleware using wrap_fn that runs require_admin (or equivalent auth logic) and rejects non-admins, so all routes (get_stats, list_users, get_user, update_user_role, delete_user, list_equipment, force_delete_equipment, toggle_equipment_availability, list_categories, create_category, update_category, delete_category) are protected automatically; once scope-level middleware is added, remove the individual let _ = require_admin(&auth)?; calls from the handlers and adjust any actor_id extraction to use auth.0.user_id directly.



============================================================================
File: src/api/routes/admin.rs
Line: 152 to 177
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/routes/admin.rs around lines 152 - 177, The handlers create_category and update_category currently discard the admin identity by using let _ = require_admin(&auth)?; — change them to capture the returned admin/actor (e.g., let actor = require_admin(&auth)?;) and pass the actor's id into admin_service.create_category(...) and admin_service.update_category(...); also verify whether admin_service.create_category and admin_service.update_category accept an actor_id parameter and update their signatures/implementations if necessary to ensure the actor id is recorded (mirror how delete_category forwards actor_id).



============================================================================
File: src/api/routes/admin.rs
Line: 86 to 97
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/api/routes/admin.rs around lines 86 - 97, The delete_user handler allows an admin to delete their own account; verify whether admin_service.delete_user enforces a self-deletion block first, and if it does not, add a handler-level guard in the delete_user function that compares actor_id (from require_admin) with the target id (path.into_inner()) and return an appropriate error response (e.g., Forbidden/BadRequest via AppResult) when they are equal instead of calling admin_service.delete_user; reference delete_user, require_admin, actor_id, path.into_inner(), and admin_service.delete_user when making this change.



============================================================================
File: frontend/src/app/admin/users/page.tsx
Line: 31 to 36
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/app/admin/users/page.tsx around lines 31 - 36, The page currently initializes state and will fetch admin data immediately; add a client-side auth/role guard at the top of AdminUsersPage so no admin fetching or actions run until the current session is verified as authenticated and role === 'admin'. Use your app's auth/session hook (e.g., useAuth or useSession) to get loading and user info, render a loading/unauthorized fallback (or navigate away) while auth is loading or the user is not admin, and only initialize/fetch the UsersResponse state (data, setData) or call any fetchUsers/roleChange/delete handlers after the admin check passes; ensure any effects that call APIs check the isAdmin flag before running.



============================================================================
File: frontend/src/app/admin/users/page.tsx
Line: 134 to 137
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/app/admin/users/page.tsx around lines 134 - 137, The onClick handler currently discards the promise from navigator.clipboard.writeText and always shows toast.success; change the handler (the onClick arrow function) to await or attach .then/.catch to navigator.clipboard.writeText(user.id) so you only call toast.success when the promise resolves and call toast.error (or a fallback) when it rejects; ensure errors are caught and optionally log them so clipboard permission/secure-context failures are handled gracefully.



============================================================================
File: frontend/src/app/admin/users/page.tsx
Line: 57 to 70
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/app/admin/users/page.tsx around lines 57 - 70, The current effects cause a double-fetch when filters change while page > 1: the useEffect that calls load (function load) runs with the old page, then another effect resets page via setPage(1) causing load to run again; fix by making the reset-and-fetch atomic — either (A) combine the two separate useEffect blocks into one effect that watches [search, perPage, roleFilter, load] and sets page to 1 then calls load(1) (or calls load with the resolved page), or (B) remove page from load’s useCallback deps and change load to accept a page parameter so the filter effect sets page to 1 and immediately calls load(1); update references to load, setPage, search, perPage, roleFilter, and page accordingly so only one API call happens per filter change.



============================================================================
File: frontend/src/app/admin/users/page.tsx
Line: 74 to 77
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @frontend/src/app/admin/users/page.tsx around lines 74 - 77, The PUT request in page.tsx uses JSON.stringify(body) but doesn't set Content-Type, so either confirm that fetchClient (from "@/lib/api") automatically adds "Content-Type: application/json" when a body is present or explicitly add the header to the call; update the fetchClient invocation in the users role update (the const res = await fetchClient(/api/admin/users/${id}/role, { method: 'PUT', body: JSON.stringify({ role }) }) line) to include headers: { 'Content-Type': 'application/json' } if fetchClient doesn't already handle it, or alternatively implement the header injection inside fetchClient so all callers benefit. Ensure the header is only set for JSON bodies to avoid breaking other content types.



============================================================================
File: src/infrastructure/repositories/user_repository.rs
Line: 111
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/infrastructure/repositories/user_repository.rs at line 111, The SQL WHERE clauses in user_repository.rs include a redundant and fragile "ESCAPE '\' " on the ILIKE patterns; remove the "ESCAPE '\' " fragment from the query strings used in the methods that build these WHERE clauses (the queries referenced in the list/count methods around the ILIKE filter and the count_all query), relying on the escape_like_pattern helper to produce escaped patterns instead; update both occurrences so the WHERE reads "email ILIKE '%' || $3 || '%' OR username ILIKE '%' || $3 || '%'" (keeping the existing parameterization and helper usage intact).



============================================================================
File: src/infrastructure/repositories/user_repository.rs
Line: 99 to 105
Type: potential_issue

Prompt for AI Agent:
Verify each finding against the current code and only fix it if needed.

In @src/infrastructure/repositories/user_repository.rs around lines 99 - 105, The list_all function accepts limit and offset and currently passes them unguarded to PostgreSQL; add a validation guard at the start of async fn list_all(&self, limit: i64, offset: i64, ...) -> AppResult> to reject negative values (for example return an Err(AppError::BadRequest("limit/offset must be non-negative")) or map to your project’s equivalent error type) before any DB call, validating both limit and offset and documenting the behavior so callers get a structured AppError instead of a raw DB error.



Review completed: 39 findings ✔
