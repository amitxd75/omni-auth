//! Multi-tenant Organization (Org) membership and role management.
//! Handles tenant workspaces, membership registrations, user linking, and role updates.

use crate::error::Result;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct Organization {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct UserOrg {
    pub id: Uuid,
    pub name: String,
    pub role: String,
}

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct OrgMember {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Creates a new organization workspace and sets the creator user as the 'owner' role.
/// Executes both inserts in a single PostgreSQL database transaction.
///
/// # Parameters
/// - `pool`: PostgreSQL database connection pool.
/// - `project_id`: ID of the tenant project.
/// - `owner_id`: User ID of the creator.
/// - `name`: Display name of the new organization workspace.
///
/// # Returns
/// The fully populated `Organization` struct.
pub async fn create_organization(
    pool: &sqlx::PgPool,
    project_id: Uuid,
    owner_id: Uuid,
    name: &str,
) -> Result<Organization> {
    let mut tx = pool.begin().await?;
    let org_id = Uuid::now_v7();

    // 1. Insert organization
    let org = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (id, project_id, name)
         VALUES ($1, $2, $3)
         RETURNING id, project_id, name, created_at, updated_at",
    )
    .bind(org_id)
    .bind(project_id)
    .bind(name)
    .fetch_one(&mut *tx)
    .await?;

    // 2. Add owner as member
    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role)
         VALUES ($1, $2, $3)",
    )
    .bind(org.id)
    .bind(owner_id)
    .bind("owner")
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(org)
}

/// Retrieves a list of all organization workspaces a specific user belongs to.
/// Returns the organization details along with the user's role in each.
pub async fn get_user_organizations(pool: &sqlx::PgPool, user_id: Uuid) -> Result<Vec<UserOrg>> {
    let orgs = sqlx::query_as::<_, UserOrg>(
        "SELECT o.id, o.name, m.role
         FROM organizations o
         JOIN organization_members m ON o.id = m.organization_id
         WHERE m.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(orgs)
}

/// Retrieves a list of all member users inside a specific organization.
/// Maps the user database tables to fetch member emails.
pub async fn get_organization_members(pool: &sqlx::PgPool, org_id: Uuid) -> Result<Vec<OrgMember>> {
    let members = sqlx::query_as::<_, OrgMember>(
        "SELECT m.user_id, u.email, m.role, m.created_at
         FROM organization_members m
         JOIN users u ON m.user_id = u.id
         WHERE m.organization_id = $1",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await?;

    Ok(members)
}

/// Resolves the specific membership role of a user in an organization.
/// Returns `None` if the user is not a member of the organization.
pub async fn get_organization_member_role(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<Option<String>> {
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role
         FROM organization_members
         WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(role)
}

/// Adds a new user member to an organization with a specific role assignment.
pub async fn add_organization_member(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    user_id: Uuid,
    role: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role)
         VALUES ($1, $2, $3)",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(role)
    .execute(pool)
    .await?;

    Ok(())
}

/// Updates the membership role of an existing user in an organization.
pub async fn update_organization_member_role(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    user_id: Uuid,
    role: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE organization_members
         SET role = $1
         WHERE organization_id = $2 AND user_id = $3",
    )
    .bind(role)
    .bind(org_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Removes a user from an organization membership.
pub async fn remove_organization_member(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM organization_members
         WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}
