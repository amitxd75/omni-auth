//! Organization membership, workspace creation, and member role management handlers.
//! Implements Role-Based Access Control (RBAC) permissions (owner, admin, member) for multi-tenant teams.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::middleware::{AppState, AuthenticatedUser};
use omni_auth_core::orgs::{
    add_organization_member, create_organization, get_organization_member_role,
    get_organization_members, get_user_organizations, remove_organization_member,
    update_organization_member_role,
};

#[derive(Debug, Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub email: String,
    pub role: String, // 'admin', 'member'
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberRequest {
    pub role: String,
}

/// HTTP POST handler to create a new organization.
/// The caller is automatically assigned as the "owner" in a transactional DB lock.
pub async fn create_org_handler(
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
    Json(payload): Json<CreateOrgRequest>,
) -> impl IntoResponse {
    match create_organization(
        &state.db,
        user_ctx.project.id,
        user_ctx.user_id,
        &payload.name,
    )
    .await
    {
        Ok(org) => (StatusCode::CREATED, Json(org)).into_response(),
        Err(e) => {
            tracing::error!("Failed to create organization: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response()
        }
    }
}

/// HTTP GET handler listing all organizations of the authenticated user.
pub async fn list_orgs_handler(
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
) -> impl IntoResponse {
    match get_user_organizations(&state.db, user_ctx.user_id).await {
        Ok(orgs) => (StatusCode::OK, Json(orgs)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list organizations: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response()
        }
    }
}

/// HTTP GET handler that lists all members belonging to an organization.
/// Verifies that the requester is a member of that organization.
pub async fn list_members_handler(
    Path(org_id): Path<Uuid>,
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
) -> impl IntoResponse {
    // 1. Check if requester is a member of the organization
    let role = match get_organization_member_role(&state.db, org_id, user_ctx.user_id).await {
        Ok(Some(r)) => r,
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Access denied" })),
            )
                .into_response();
        }
    };

    tracing::info!(
        "User {} with role {} listing members of org {}",
        user_ctx.user_id,
        role,
        org_id
    );

    match get_organization_members(&state.db, org_id).await {
        Ok(members) => (StatusCode::OK, Json(members)).into_response(),
        Err(e) => {
            tracing::error!("Failed to list org members: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response()
        }
    }
}

/// HTTP POST handler to invite/add a new member user to an organization.
/// Validates that the caller holds 'owner' or 'admin' status.
pub async fn add_member_handler(
    Path(org_id): Path<Uuid>,
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
    Json(payload): Json<AddMemberRequest>,
) -> impl IntoResponse {
    // 1. Perform RBAC validation: Requester must be 'owner' or 'admin'
    let requester_role =
        match get_organization_member_role(&state.db, org_id, user_ctx.user_id).await {
            Ok(Some(r)) => r,
            _ => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "Access denied" })),
                )
                    .into_response();
            }
        };

    if requester_role != "owner" && requester_role != "admin" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Insufficient permissions" })),
        )
            .into_response();
    }

    // Role check: cannot add owners directly
    if payload.role != "admin" && payload.role != "member" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid role type" })),
        )
            .into_response();
    }

    // 2. Resolve invited user by email normalized
    let email_normalized = payload.email.trim().to_lowercase();
    let target_user_id = match sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users WHERE project_id = $1 AND email = $2",
    )
    .bind(user_ctx.project.id)
    .bind(&email_normalized)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "User with this email not registered" })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Database error fetching user: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response();
        }
    };

    // Check if target is already a member
    if let Ok(Some(_)) = get_organization_member_role(&state.db, org_id, target_user_id).await {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "User is already a member" })),
        )
            .into_response();
    }

    // 3. Insert membership
    match add_organization_member(&state.db, org_id, target_user_id, &payload.role).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "message": "Member added successfully" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to add member: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response()
        }
    }
}

/// HTTP PUT handler to modify the role of an organization member.
/// Protects system owners from demotion and prevents admins from editing other admins.
pub async fn update_member_handler(
    Path((org_id, target_user_id)): Path<(Uuid, Uuid)>,
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
    Json(payload): Json<UpdateMemberRequest>,
) -> impl IntoResponse {
    // 1. Perform RBAC validation: Requester must be 'owner' or 'admin'
    let requester_role =
        match get_organization_member_role(&state.db, org_id, user_ctx.user_id).await {
            Ok(Some(r)) => r,
            _ => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "Access denied" })),
                )
                    .into_response();
            }
        };

    if requester_role != "owner" && requester_role != "admin" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Insufficient permissions" })),
        )
            .into_response();
    }

    // 2. Fetch target's current role
    let target_role = match get_organization_member_role(&state.db, org_id, target_user_id).await {
        Ok(Some(r)) => r,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Member not found in organization" })),
            )
                .into_response();
        }
    };

    // Owner protection: only owners can demote/promote other high-tier roles
    if target_role == "owner" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Cannot change organization owner's role" })),
        )
            .into_response();
    }

    if requester_role == "admin" && target_role == "admin" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Admins cannot modify other admins" })),
        )
            .into_response();
    }

    if payload.role != "admin" && payload.role != "member" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid target role" })),
        )
            .into_response();
    }

    // 3. Update
    match update_organization_member_role(&state.db, org_id, target_user_id, &payload.role).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "message": "Member role updated successfully" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to update role: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response()
        }
    }
}

/// HTTP DELETE handler to remove a member from an organization.
/// Allows self-removal (leaving) but blocks owner-removal unless ownership is transferred first.
pub async fn remove_member_handler(
    Path((org_id, target_user_id)): Path<(Uuid, Uuid)>,
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
) -> impl IntoResponse {
    // 1. Fetch requester role
    let requester_role =
        match get_organization_member_role(&state.db, org_id, user_ctx.user_id).await {
            Ok(Some(r)) => r,
            _ => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "Access denied" })),
                )
                    .into_response();
            }
        };

    // 2. Fetch target role
    let target_role = match get_organization_member_role(&state.db, org_id, target_user_id).await {
        Ok(Some(r)) => r,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Member not found" })),
            )
                .into_response();
        }
    };

    // Permission checks:
    // Users can always remove themselves (leave)
    let is_self = user_ctx.user_id == target_user_id;

    if !is_self {
        // If not self, requester must be owner or admin
        if requester_role != "owner" && requester_role != "admin" {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Insufficient permissions" })),
            )
                .into_response();
        }

        // Owner protection
        if target_role == "owner" {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Cannot remove organization owner" })),
            )
                .into_response();
        }

        // Admin protection
        if requester_role == "admin" && target_role == "admin" {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Admins cannot remove other admins" })),
            )
                .into_response();
        }
    } else {
        // If self is owner, cannot leave organization unless ownership is transferred first
        if target_role == "owner" {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Owner cannot leave organization without transferring ownership" }))).into_response();
        }
    }

    // 3. Remove
    match remove_organization_member(&state.db, org_id, target_user_id).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "message": "Member removed successfully" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to remove member: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response()
        }
    }
}
