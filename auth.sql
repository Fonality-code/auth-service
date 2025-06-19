-- Create database (uncomment if needed)
-- CREATE DATABASE auth_db;
-- USE auth_db;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(36) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    dob TIMESTAMP NULL,
    avatar_url VARCHAR(255) NULL,
    hashed_password VARCHAR(128) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(36) UNIQUE NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    refresh_token VARCHAR(512) NOT NULL,
    user_agent VARCHAR(255) NULL,
    ip_address VARCHAR(45) NULL, -- IPv6 can be up to 45 chars
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    role_id VARCHAR(36) UNIQUE NOT NULL,
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT NULL,
    is_system_role BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(36) NULL
);

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    permission_id VARCHAR(36) UNIQUE NOT NULL,
    name VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT NULL,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    is_system_permission BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User Role Assignments table (detailed tracking)
CREATE TABLE IF NOT EXISTS user_role_assignments (
    id SERIAL PRIMARY KEY,
    assignment_id VARCHAR(36) UNIQUE NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    role_id VARCHAR(36) NOT NULL,
    assigned_by VARCHAR(36) NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    reason TEXT NULL,
    revoked_at TIMESTAMP NULL,
    revoked_by VARCHAR(36) NULL,
    revoke_reason TEXT NULL
);

-- User-Roles association table (many-to-many)
CREATE TABLE IF NOT EXISTS user_roles (
    user_id VARCHAR(36) NOT NULL,
    role_id VARCHAR(36) NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    PRIMARY KEY (user_id, role_id)
);

-- Role-Permissions association table (many-to-many)
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id VARCHAR(36) NOT NULL,
    permission_id VARCHAR(36) NOT NULL,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

-- Add foreign key constraints
ALTER TABLE sessions
ADD CONSTRAINT fk_sessions_user_id
FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE;

ALTER TABLE roles
ADD CONSTRAINT fk_roles_created_by
FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL;

ALTER TABLE user_role_assignments
ADD CONSTRAINT fk_user_role_assignments_user_id
FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE;

ALTER TABLE user_role_assignments
ADD CONSTRAINT fk_user_role_assignments_role_id
FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE;

ALTER TABLE user_role_assignments
ADD CONSTRAINT fk_user_role_assignments_assigned_by
FOREIGN KEY (assigned_by) REFERENCES users(user_id) ON DELETE SET NULL;

ALTER TABLE user_role_assignments
ADD CONSTRAINT fk_user_role_assignments_revoked_by
FOREIGN KEY (revoked_by) REFERENCES users(user_id) ON DELETE SET NULL;

ALTER TABLE user_roles
ADD CONSTRAINT fk_user_roles_user_id
FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE;

ALTER TABLE user_roles
ADD CONSTRAINT fk_user_roles_role_id
FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE;

ALTER TABLE role_permissions
ADD CONSTRAINT fk_role_permissions_role_id
FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE;

ALTER TABLE role_permissions
ADD CONSTRAINT fk_role_permissions_permission_id
FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);

CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token);
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_roles_role_id ON roles(role_id);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_roles_is_active ON roles(is_active);
CREATE INDEX IF NOT EXISTS idx_roles_is_system_role ON roles(is_system_role);
CREATE INDEX IF NOT EXISTS idx_roles_created_by ON roles(created_by);

CREATE INDEX IF NOT EXISTS idx_permissions_permission_id ON permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);
CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action);
CREATE INDEX IF NOT EXISTS idx_permissions_is_active ON permissions(is_active);
CREATE INDEX IF NOT EXISTS idx_permissions_resource_action ON permissions(resource, action);

CREATE INDEX IF NOT EXISTS idx_user_role_assignments_assignment_id ON user_role_assignments(assignment_id);
CREATE INDEX IF NOT EXISTS idx_user_role_assignments_user_id ON user_role_assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_user_role_assignments_role_id ON user_role_assignments(role_id);
CREATE INDEX IF NOT EXISTS idx_user_role_assignments_is_active ON user_role_assignments(is_active);
CREATE INDEX IF NOT EXISTS idx_user_role_assignments_assigned_at ON user_role_assignments(assigned_at);
CREATE INDEX IF NOT EXISTS idx_user_role_assignments_expires_at ON user_role_assignments(expires_at);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_is_active ON user_roles(is_active);
CREATE INDEX IF NOT EXISTS idx_user_roles_expires_at ON user_roles(expires_at);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);

-- Create trigger for updating updated_at timestamp (PostgreSQL)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sessions_updated_at
    BEFORE UPDATE ON sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_permissions_updated_at
    BEFORE UPDATE ON permissions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default permissions
INSERT INTO permissions (permission_id, name, display_name, description, resource, action, is_system_permission, is_active) VALUES
-- User management permissions
(gen_random_uuid(), 'user.create', 'Create Users', 'Create new user accounts', 'user', 'create', TRUE, TRUE),
(gen_random_uuid(), 'user.read', 'Read Users', 'View user information', 'user', 'read', TRUE, TRUE),
(gen_random_uuid(), 'user.update', 'Update Users', 'Update user information', 'user', 'update', TRUE, TRUE),
(gen_random_uuid(), 'user.delete', 'Delete Users', 'Delete user accounts', 'user', 'delete', TRUE, TRUE),
(gen_random_uuid(), 'user.manage', 'Manage Users', 'Full user management access', 'user', 'manage', TRUE, TRUE),

-- Role management permissions
(gen_random_uuid(), 'role.create', 'Create Roles', 'Create new roles', 'role', 'create', TRUE, TRUE),
(gen_random_uuid(), 'role.read', 'Read Roles', 'View role information', 'role', 'read', TRUE, TRUE),
(gen_random_uuid(), 'role.update', 'Update Roles', 'Update role information', 'role', 'update', TRUE, TRUE),
(gen_random_uuid(), 'role.delete', 'Delete Roles', 'Delete roles', 'role', 'delete', TRUE, TRUE),
(gen_random_uuid(), 'role.manage', 'Manage Roles', 'Full role management access', 'role', 'manage', TRUE, TRUE),

-- Permission management permissions
(gen_random_uuid(), 'permission.create', 'Create Permissions', 'Create new permissions', 'permission', 'create', TRUE, TRUE),
(gen_random_uuid(), 'permission.read', 'Read Permissions', 'View permission information', 'permission', 'read', TRUE, TRUE),
(gen_random_uuid(), 'permission.update', 'Update Permissions', 'Update permission information', 'permission', 'update', TRUE, TRUE),
(gen_random_uuid(), 'permission.delete', 'Delete Permissions', 'Delete permissions', 'permission', 'delete', TRUE, TRUE),
(gen_random_uuid(), 'permission.manage', 'Manage Permissions', 'Full permission management access', 'permission', 'manage', TRUE, TRUE),

-- Session management permissions
(gen_random_uuid(), 'session.read', 'Read Sessions', 'View session information', 'session', 'read', TRUE, TRUE),
(gen_random_uuid(), 'session.manage', 'Manage Sessions', 'Manage user sessions', 'session', 'manage', TRUE, TRUE),
(gen_random_uuid(), 'session.revoke', 'Revoke Sessions', 'Revoke user sessions', 'session', 'revoke', TRUE, TRUE),

-- System administration permissions
(gen_random_uuid(), 'system.admin', 'System Administration', 'Full system administration access', 'system', 'admin', TRUE, TRUE),
(gen_random_uuid(), 'system.audit', 'System Audit', 'View system audit logs', 'system', 'audit', TRUE, TRUE),
(gen_random_uuid(), 'system.maintenance', 'System Maintenance', 'Perform system maintenance tasks', 'system', 'maintenance', TRUE, TRUE),

-- Profile management permissions
(gen_random_uuid(), 'profile.read', 'Read Profile', 'View own profile', 'profile', 'read', TRUE, TRUE),
(gen_random_uuid(), 'profile.update', 'Update Profile', 'Update own profile', 'profile', 'update', TRUE, TRUE),

-- Authentication permissions
(gen_random_uuid(), 'auth.login', 'Login', 'Login to the system', 'auth', 'login', TRUE, TRUE),
(gen_random_uuid(), 'auth.logout', 'Logout', 'Logout from the system', 'auth', 'logout', TRUE, TRUE),
(gen_random_uuid(), 'auth.password_reset', 'Password Reset', 'Reset password', 'auth', 'password_reset', TRUE, TRUE)
ON CONFLICT (name) DO NOTHING;

-- Insert default roles
INSERT INTO roles (role_id, name, display_name, description, is_system_role, is_active) VALUES
(gen_random_uuid(), 'super_admin', 'Super Administrator', 'Full system access with all permissions', TRUE, TRUE),
(gen_random_uuid(), 'admin', 'Administrator', 'Administrative access for user and role management', TRUE, TRUE),
(gen_random_uuid(), 'moderator', 'Moderator', 'Limited administrative access for user management', TRUE, TRUE),
(gen_random_uuid(), 'user', 'Regular User', 'Basic user access for own profile and authentication', TRUE, TRUE),
(gen_random_uuid(), 'guest', 'Guest User', 'Limited access for unauthenticated operations', TRUE, TRUE)
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to super_admin role (all permissions)
INSERT INTO role_permissions (role_id, permission_id, granted_at)
SELECT r.role_id, p.permission_id, CURRENT_TIMESTAMP
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'super_admin' AND p.is_active = TRUE
ON CONFLICT DO NOTHING;

-- Assign permissions to admin role
INSERT INTO role_permissions (role_id, permission_id, granted_at)
SELECT r.role_id, p.permission_id, CURRENT_TIMESTAMP
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin'
AND p.name IN (
    'user.create', 'user.read', 'user.update', 'user.delete', 'user.manage',
    'role.create', 'role.read', 'role.update', 'role.delete', 'role.manage',
    'session.read', 'session.manage', 'session.revoke',
    'system.audit', 'system.maintenance',
    'profile.read', 'profile.update',
    'auth.login', 'auth.logout', 'auth.password_reset'
)
ON CONFLICT DO NOTHING;

-- Assign permissions to moderator role
INSERT INTO role_permissions (role_id, permission_id, granted_at)
SELECT r.role_id, p.permission_id, CURRENT_TIMESTAMP
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'moderator'
AND p.name IN (
    'user.read', 'user.update',
    'role.read',
    'session.read',
    'profile.read', 'profile.update',
    'auth.login', 'auth.logout', 'auth.password_reset'
)
ON CONFLICT DO NOTHING;

-- Assign permissions to user role
INSERT INTO role_permissions (role_id, permission_id, granted_at)
SELECT r.role_id, p.permission_id, CURRENT_TIMESTAMP
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'user'
AND p.name IN (
    'profile.read', 'profile.update',
    'auth.login', 'auth.logout', 'auth.password_reset'
)
ON CONFLICT DO NOTHING;

-- Assign permissions to guest role
INSERT INTO role_permissions (role_id, permission_id, granted_at)
SELECT r.role_id, p.permission_id, CURRENT_TIMESTAMP
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'guest'
AND p.name IN (
    'auth.login', 'auth.password_reset'
)
ON CONFLICT DO NOTHING;

-- Useful views for role-based access control

-- View to see user roles with details
CREATE OR REPLACE VIEW user_roles_view AS
SELECT
    u.user_id,
    u.email,
    u.first_name,
    u.last_name,
    r.role_id,
    r.name AS role_name,
    r.display_name AS role_display_name,
    ur.assigned_at,
    ur.expires_at,
    ur.is_active AS assignment_active,
    CASE
        WHEN ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP THEN TRUE
        ELSE FALSE
    END AS assignment_valid
FROM users u
JOIN user_roles ur ON u.user_id = ur.user_id
JOIN roles r ON ur.role_id = r.role_id
WHERE u.is_active = TRUE AND r.is_active = TRUE;

-- View to see user permissions through roles
CREATE OR REPLACE VIEW user_permissions_view AS
SELECT DISTINCT
    u.user_id,
    u.email,
    p.permission_id,
    p.name AS permission_name,
    p.display_name AS permission_display_name,
    p.resource,
    p.action,
    r.name AS granted_through_role
FROM users u
JOIN user_roles ur ON u.user_id = ur.user_id
JOIN roles r ON ur.role_id = r.role_id
JOIN role_permissions rp ON r.role_id = rp.role_id
JOIN permissions p ON rp.permission_id = p.permission_id
WHERE u.is_active = TRUE
    AND r.is_active = TRUE
    AND p.is_active = TRUE
    AND ur.is_active = TRUE
    AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP);

-- View for role summary with permission counts
CREATE OR REPLACE VIEW role_summary_view AS
SELECT
    r.role_id,
    r.name,
    r.display_name,
    r.description,
    r.is_system_role,
    r.is_active,
    COUNT(DISTINCT rp.permission_id) AS permission_count,
    COUNT(DISTINCT ur.user_id) AS user_count,
    r.created_at,
    r.updated_at
FROM roles r
LEFT JOIN role_permissions rp ON r.role_id = rp.role_id
LEFT JOIN user_roles ur ON r.role_id = ur.role_id AND ur.is_active = TRUE
GROUP BY r.role_id, r.name, r.display_name, r.description, r.is_system_role, r.is_active, r.created_at, r.updated_at;

-- Function to check if a user has a specific permission
CREATE OR REPLACE FUNCTION user_has_permission(
    p_user_id VARCHAR(36),
    p_permission_name VARCHAR(100)
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM user_permissions_view upv
        WHERE upv.user_id = p_user_id
        AND upv.permission_name = p_permission_name
    );
END;
$$ LANGUAGE plpgsql;

-- Function to check if a user has a specific role
CREATE OR REPLACE FUNCTION user_has_role(
    p_user_id VARCHAR(36),
    p_role_name VARCHAR(100)
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM user_roles_view urv
        WHERE urv.user_id = p_user_id
        AND urv.role_name = p_role_name
        AND urv.assignment_active = TRUE
        AND urv.assignment_valid = TRUE
    );
END;
$$ LANGUAGE plpgsql;

-- Function to get active sessions count for cleanup monitoring
CREATE OR REPLACE FUNCTION get_session_stats()
RETURNS TABLE(
    total_sessions BIGINT,
    active_sessions BIGINT,
    expired_sessions BIGINT,
    sessions_expiring_soon BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        COUNT(*) as total_sessions,
        COUNT(*) FILTER (WHERE is_active = TRUE) as active_sessions,
        COUNT(*) FILTER (WHERE expires_at < CURRENT_TIMESTAMP) as expired_sessions,
        COUNT(*) FILTER (WHERE expires_at < CURRENT_TIMESTAMP + INTERVAL '1 hour' AND expires_at > CURRENT_TIMESTAMP) as sessions_expiring_soon
    FROM sessions;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Update expired sessions to inactive
    UPDATE sessions
    SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
    WHERE expires_at < CURRENT_TIMESTAMP AND is_active = TRUE;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;

    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup expired role assignments
CREATE OR REPLACE FUNCTION cleanup_expired_role_assignments()
RETURNS INTEGER AS $$
DECLARE
    updated_count INTEGER;
BEGIN
    -- Update expired role assignments to inactive
    UPDATE user_roles
    SET is_active = FALSE
    WHERE expires_at IS NOT NULL
    AND expires_at < CURRENT_TIMESTAMP
    AND is_active = TRUE;

    GET DIAGNOSTICS updated_count = ROW_COUNT;

    -- Also update detailed assignments table
    UPDATE user_role_assignments
    SET is_active = FALSE,
        revoked_at = CURRENT_TIMESTAMP,
        revoke_reason = 'Automatically expired'
    WHERE expires_at IS NOT NULL
    AND expires_at < CURRENT_TIMESTAMP
    AND is_active = TRUE;

    RETURN updated_count;
END;
$$ LANGUAGE plpgsql;

-- Additional utility functions for role management

-- Function to assign a role to a user
CREATE OR REPLACE FUNCTION assign_user_role(
    p_user_id VARCHAR(36),
    p_role_name VARCHAR(100),
    p_assigned_by VARCHAR(36) DEFAULT NULL,
    p_expires_at TIMESTAMP DEFAULT NULL,
    p_reason TEXT DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_role_id VARCHAR(36);
    v_assignment_id VARCHAR(36);
BEGIN
    -- Get role_id from role name
    SELECT role_id INTO v_role_id
    FROM roles
    WHERE name = p_role_name AND is_active = TRUE;

    IF v_role_id IS NULL THEN
        RETURN FALSE;
    END IF;

    -- Check if assignment already exists
    IF EXISTS (
        SELECT 1 FROM user_roles
        WHERE user_id = p_user_id AND role_id = v_role_id AND is_active = TRUE
    ) THEN
        RETURN TRUE; -- Already assigned
    END IF;

    -- Generate assignment ID
    v_assignment_id := gen_random_uuid();

    -- Insert into user_roles
    INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by, expires_at, is_active)
    VALUES (p_user_id, v_role_id, CURRENT_TIMESTAMP, p_assigned_by, p_expires_at, TRUE);

    -- Insert into detailed tracking table
    INSERT INTO user_role_assignments (
        assignment_id, user_id, role_id, assigned_by, assigned_at,
        expires_at, is_active, reason
    )
    VALUES (
        v_assignment_id, p_user_id, v_role_id, p_assigned_by, CURRENT_TIMESTAMP,
        p_expires_at, TRUE, p_reason
    );

    RETURN TRUE;
EXCEPTION
    WHEN OTHERS THEN
        RETURN FALSE;
END;
$$ LANGUAGE plpgsql;

-- Function to revoke a role from a user
CREATE OR REPLACE FUNCTION revoke_user_role(
    p_user_id VARCHAR(36),
    p_role_name VARCHAR(100),
    p_revoked_by VARCHAR(36) DEFAULT NULL,
    p_revoke_reason TEXT DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    v_role_id VARCHAR(36);
BEGIN
    -- Get role_id from role name
    SELECT role_id INTO v_role_id
    FROM roles
    WHERE name = p_role_name AND is_active = TRUE;

    IF v_role_id IS NULL THEN
        RETURN FALSE;
    END IF;

    -- Update user_roles
    UPDATE user_roles
    SET is_active = FALSE
    WHERE user_id = p_user_id AND role_id = v_role_id AND is_active = TRUE;

    -- Update detailed tracking
    UPDATE user_role_assignments
    SET is_active = FALSE,
        revoked_at = CURRENT_TIMESTAMP,
        revoked_by = p_revoked_by,
        revoke_reason = p_revoke_reason
    WHERE user_id = p_user_id AND role_id = v_role_id AND is_active = TRUE;

    RETURN TRUE;
EXCEPTION
    WHEN OTHERS THEN
        RETURN FALSE;
END;
$$ LANGUAGE plpgsql;

-- Function to get user's effective permissions
CREATE OR REPLACE FUNCTION get_user_permissions(p_user_id VARCHAR(36))
RETURNS TABLE(
    permission_name VARCHAR(100),
    resource VARCHAR(100),
    action VARCHAR(50),
    granted_through_role VARCHAR(100)
) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT
        p.name as permission_name,
        p.resource,
        p.action,
        r.name as granted_through_role
    FROM user_permissions_view upv
    JOIN permissions p ON upv.permission_id = p.permission_id
    JOIN roles r ON upv.granted_through_role = r.name
    WHERE upv.user_id = p_user_id
    ORDER BY p.resource, p.action;
END;
$$ LANGUAGE plpgsql;

-- Function to check resource-action permission
CREATE OR REPLACE FUNCTION user_has_resource_permission(
    p_user_id VARCHAR(36),
    p_resource VARCHAR(100),
    p_action VARCHAR(50)
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM user_permissions_view upv
        WHERE upv.user_id = p_user_id
        AND upv.resource = p_resource
        AND upv.action = p_action
    );
END;
$$ LANGUAGE plpgsql;

-- Create a comprehensive audit view
CREATE OR REPLACE VIEW audit_log_view AS
SELECT
    'role_assignment' as event_type,
    ura.assignment_id as event_id,
    ura.user_id,
    u.email as user_email,
    ura.assigned_by as actor_id,
    assigner.email as actor_email,
    'Role ' || r.name || ' assigned to user' as description,
    ura.assigned_at as event_timestamp,
    ura.reason as details
FROM user_role_assignments ura
JOIN users u ON ura.user_id = u.user_id
JOIN roles r ON ura.role_id = r.role_id
LEFT JOIN users assigner ON ura.assigned_by = assigner.user_id
WHERE ura.is_active = TRUE

UNION ALL

SELECT
    'role_revocation' as event_type,
    ura.assignment_id as event_id,
    ura.user_id,
    u.email as user_email,
    ura.revoked_by as actor_id,
    revoker.email as actor_email,
    'Role ' || r.name || ' revoked from user' as description,
    ura.revoked_at as event_timestamp,
    ura.revoke_reason as details
FROM user_role_assignments ura
JOIN users u ON ura.user_id = u.user_id
JOIN roles r ON ura.role_id = r.role_id
LEFT JOIN users revoker ON ura.revoked_by = revoker.user_id
WHERE ura.is_active = FALSE AND ura.revoked_at IS NOT NULL

ORDER BY event_timestamp DESC;

-- Helpful maintenance queries (commented for reference)

/*
-- Query to find users without any roles:
SELECT u.user_id, u.email, u.first_name, u.last_name
FROM users u
LEFT JOIN user_roles ur ON u.user_id = ur.user_id AND ur.is_active = TRUE
WHERE ur.user_id IS NULL AND u.is_active = TRUE;

-- Query to find roles with no users:
SELECT r.role_id, r.name, r.display_name
FROM roles r
LEFT JOIN user_roles ur ON r.role_id = ur.role_id AND ur.is_active = TRUE
WHERE ur.role_id IS NULL AND r.is_active = TRUE;

-- Query to find permissions not assigned to any role:
SELECT p.permission_id, p.name, p.resource, p.action
FROM permissions p
LEFT JOIN role_permissions rp ON p.permission_id = rp.permission_id
WHERE rp.permission_id IS NULL AND p.is_active = TRUE;

-- Example usage of utility functions:
-- SELECT assign_user_role('user-id-here', 'admin', 'assigner-user-id', NULL, 'Initial admin assignment');
-- SELECT revoke_user_role('user-id-here', 'admin', 'revoker-user-id', 'Role no longer needed');
-- SELECT user_has_permission('user-id-here', 'user.create');
-- SELECT user_has_role('user-id-here', 'admin');
-- SELECT user_has_resource_permission('user-id-here', 'user', 'create');
-- SELECT * FROM get_user_permissions('user-id-here');
-- SELECT * FROM get_session_stats();
-- SELECT cleanup_expired_sessions();
-- SELECT cleanup_expired_role_assignments();
*/

-- Final commit
COMMIT;
