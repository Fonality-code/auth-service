# Role-Based Access Control (RBAC) Authentication System

A comprehensive FastAPI-based authentication and authorization microservice with role-based access control, session management, and comprehensive security features.

## 🚀 Features

### Authentication & Authorization
- **JWT-based Authentication** with access and refresh tokens
- **Role-Based Access Control (RBAC)** with fine-grained permissions
- **Session Management** with secure token handling
- **OTP Verification** for account registration and password reset
- **Email Integration** for account verification and notifications
- **Password Security** with bcrypt hashing and validation

### Role & Permission System
- **Hierarchical Roles**: Super Admin, Admin, Moderator, User, Guest
- **Granular Permissions**: Resource-action based permission system
- **Dynamic Role Assignment** with expiration and audit tracking
- **Permission Inheritance** through role assignments
- **System Roles Protection** preventing deletion of core roles

### Security Features
- **HTTP-Only Cookies** for token storage
- **CORS Protection** with configurable origins
- **Request Rate Limiting** (configurable)
- **Session Expiration** with automatic cleanup
- **Audit Logging** for role assignments and security events
- **Database Constraints** ensuring data integrity

## 📋 Default Roles & Permissions

### Roles Hierarchy

| Role | Description | Users | Permissions |
|------|-------------|-------|-------------|
| `super_admin` | Full system access | System administrators | ALL permissions |
| `admin` | Administrative access | Department managers | User/Role management, System maintenance |
| `moderator` | Limited admin access | Team leads | User viewing/editing, Basic operations |
| `user` | Standard user access | Regular users | Profile management, Authentication |
| `guest` | Minimal access | Unauthenticated users | Login, Password reset only |

### Permission Categories

#### User Management
- `user.create` - Create new user accounts
- `user.read` - View user information
- `user.update` - Update user information
- `user.delete` - Delete user accounts
- `user.manage` - Full user management access

#### Role Management
- `role.create` - Create new roles
- `role.read` - View role information
- `role.update` - Update role information
- `role.delete` - Delete roles
- `role.manage` - Full role management access

#### System Administration
- `system.admin` - Full system administration
- `system.audit` - View system audit logs
- `system.maintenance` - Perform maintenance tasks

#### Profile & Authentication
- `profile.read` - View own profile
- `profile.update` - Update own profile
- `auth.login` - Login to system
- `auth.logout` - Logout from system
- `auth.password_reset` - Reset password

## 🛠 Installation & Setup

### Prerequisites
- Python 3.9+
- PostgreSQL 12+
- Redis (optional, for caching)
- SMTP server (for email features)

### 1. Clone & Install
```bash
git clone <repository-url>
cd wayfinder/apps/auth
pip install -r requirements.txt
```

### 2. Database Setup
```bash
# Create PostgreSQL database
createdb auth_db

# Run the initialization SQL
psql auth_db -f auth.sql
```

### 3. Environment Configuration
Create a `.env` file:
```env
# Database
DATABASE_URL=postgresql://username:password@localhost:5432/auth_db

# Security
SECRET_KEY=your-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=30

# Email Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_FROM=your-email@gmail.com
MAIL_TLS=True
MAIL_SSL=False

# Environment
ENVIRONMENT=development
```

### 4. Initialize System
```bash
# Start the service
python src/main.py

# Initialize roles and permissions
python scripts/init_system.py

# Run tests
python scripts/test_rbac.py
```

## 🔧 API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/v1/register` | Register new user | No |
| POST | `/api/v1/verify-user` | Verify user with OTP | No |
| POST | `/api/v1/login` | User login | No |
| POST | `/api/v1/logout` | User logout | Yes |
| POST | `/api/v1/refresh` | Refresh access token | Yes |
| GET | `/api/v1/me` | Get current user info | Yes |
| POST | `/api/v1/change-password` | Change password | Yes |
| POST | `/api/v1/forgot-password` | Request password reset | No |
| POST | `/api/v1/reset-password` | Reset password with OTP | No |

### Role Management Endpoints

| Method | Endpoint | Description | Required Permission |
|--------|----------|-------------|-------------------|
| GET | `/api/v1/roles` | List all roles | Any authenticated user |
| POST | `/api/v1/roles` | Create new role | `role.manage` |
| GET | `/api/v1/roles/{role_id}` | Get role details | Any authenticated user |
| PUT | `/api/v1/roles/{role_id}` | Update role | `role.manage` |
| DELETE | `/api/v1/roles/{role_id}` | Delete role | `role.manage` |
| GET | `/api/v1/permissions` | List permissions | Any authenticated user |
| POST | `/api/v1/permissions` | Create permission | `system.admin` |

### User Role Management

| Method | Endpoint | Description | Required Permission |
|--------|----------|-------------|-------------------|
| POST | `/api/v1/users/{user_id}/roles` | Assign role to user | `user.manage` |
| DELETE | `/api/v1/users/{user_id}/roles/{role_id}` | Revoke role from user | `user.manage` |
| GET | `/api/v1/users/{user_id}/roles` | Get user roles | Self or `user.manage` |
| GET | `/api/v1/users/{user_id}/permissions` | Get user permissions | Self or `user.manage` |
| GET | `/api/v1/users/{user_id}/access-check` | Check user access | Self or `user.manage` |

### Session Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/sessions` | List user sessions | Yes |
| DELETE | `/api/v1/sessions/{session_id}` | Revoke specific session | Yes |
| DELETE | `/api/v1/sessions` | Revoke all sessions | Yes |

### Admin Endpoints

| Method | Endpoint | Description | Required Role |
|--------|----------|-------------|---------------|
| POST | `/api/v1/admin/init-system` | Initialize system | `super_admin` |
| POST | `/api/v1/admin/migrate-users` | Migrate existing users | `super_admin` |
| POST | `/api/v1/maintenance/cleanup-expired-assignments` | Cleanup expired roles | `admin` |

## 🔒 Access Control Usage

### Decorators
```python
from src.core.access_control import require_admin, require_roles, require_permissions

# Require admin role
@require_admin
def admin_only_function():
    pass

# Require specific roles (any of them)
@require_roles(["admin", "moderator"])
def moderator_or_admin_function():
    pass

# Require specific permissions
@require_permissions("user.create")
def create_user_function():
    pass

# Require resource-action permission
@require_resource_permission("user", "create")
def create_user_endpoint():
    pass

# Self or admin access
@require_self_or_admin("user_id")
def access_user_data(user_id: str):
    pass
```

### Manual Access Checks
```python
# Check user roles
if current_user.has_role("admin"):
    # User is admin

# Check user permissions
if current_user.has_permission("user.create"):
    # User can create users

# Check resource permissions
if current_user.has_resource_permission("user", "delete"):
    # User can delete users
```

## 📊 Database Schema

### Core Tables
- **users** - User account information
- **sessions** - User session tracking
- **roles** - Role definitions
- **permissions** - Permission definitions
- **user_roles** - User-role assignments (many-to-many)
- **role_permissions** - Role-permission assignments (many-to-many)
- **user_role_assignments** - Detailed role assignment tracking

### Useful Views
- **user_roles_view** - User roles with validity checks
- **user_permissions_view** - User effective permissions
- **role_summary_view** - Role statistics
- **audit_log_view** - Security audit trail

### Utility Functions
```sql
-- Check user permissions
SELECT user_has_permission('user-id', 'user.create');

-- Check user roles
SELECT user_has_role('user-id', 'admin');

-- Assign role to user
SELECT assign_user_role('user-id', 'admin', 'assigner-id', NULL, 'Promotion');

-- Revoke role from user
SELECT revoke_user_role('user-id', 'admin', 'revoker-id', 'Role no longer needed');

-- Get user permissions
SELECT * FROM get_user_permissions('user-id');

-- System maintenance
SELECT cleanup_expired_sessions();
SELECT cleanup_expired_role_assignments();
```

## 🧪 Testing

### Run Tests
```bash
# Start the auth service
python src/main.py

# Run RBAC tests
python scripts/test_rbac.py

# Check test results
cat rbac_test_results.json
```

### Test Coverage
- ✅ System initialization
- ✅ Role and permission management
- ✅ User registration and authentication
- ✅ Access control enforcement
- ✅ Unauthorized access blocking
- ✅ Session management
- ✅ Role assignment and revocation

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `SECRET_KEY` | JWT signing secret | Required |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token lifetime | 30 |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token lifetime | 30 |
| `ENVIRONMENT` | Application environment | development |
| `MAIL_SERVER` | SMTP server | Required for email |
| `MAIL_USERNAME` | SMTP username | Required for email |
| `MAIL_PASSWORD` | SMTP password | Required for email |

### Security Settings
- **Secure Cookies** - Enabled in production
- **CORS Origins** - Configure allowed origins
- **Rate Limiting** - Configurable request limits
- **Session Timeout** - Automatic session cleanup

## 📚 Advanced Usage

### Creating Custom Roles
```python
# Create role with specific permissions
role_data = {
    "name": "content_moderator",
    "display_name": "Content Moderator",
    "description": "Can moderate user content",
    "permission_ids": ["user.read", "user.update"]
}

response = requests.post("/api/v1/roles", json=role_data)
```

### Bulk Role Assignment
```python
# Assign role to multiple users
bulk_data = {
    "user_ids": ["user1", "user2", "user3"],
    "role_id": "role-id-here",
    "reason": "Department promotion"
}

response = requests.post("/api/v1/roles/{role_id}/users/bulk-assign", json=bulk_data)
```

### Temporary Role Assignment
```python
# Assign role with expiration
assignment_data = {
    "user_id": "user-id",
    "role_id": "admin-role-id",
    "expires_at": "2024-12-31T23:59:59Z",
    "reason": "Temporary admin access"
}

response = requests.post("/api/v1/users/{user_id}/roles", json=assignment_data)
```

## 🛡️ Security Best Practices

### Authentication
- Use strong passwords (enforced by validation)
- Enable 2FA/OTP verification
- Implement rate limiting on auth endpoints
- Use secure password reset flows

### Authorization
- Follow principle of least privilege
- Regularly audit role assignments
- Use temporary roles when possible
- Monitor permission usage

### Session Management
- Implement session timeout
- Secure cookie settings
- Regular session cleanup
- Monitor active sessions

### Database Security
- Use connection pooling
- Implement proper indexing
- Regular backup schedules
- Monitor query performance

## 🚨 Troubleshooting

### Common Issues

**1. Database Connection Issues**
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Test connection
psql -h localhost -U username -d auth_db
```

**2. Permission Denied Errors**
```bash
# Check user roles
SELECT * FROM user_roles_view WHERE user_id = 'your-user-id';

# Check user permissions
SELECT * FROM get_user_permissions('your-user-id');
```

**3. Token Issues**
```bash
# Clear browser cookies
# Check token expiration
# Verify SECRET_KEY configuration
```

**4. Email Issues**
```bash
# Test SMTP settings
# Check email configuration
# Verify firewall rules
```

### Logs & Monitoring
- Check application logs for errors
- Monitor database performance
- Track authentication failures
- Audit role changes

## 📈 Performance Optimization

### Database Optimization
- Proper indexing on user_id, role_id, permission_id
- Regular VACUUM and ANALYZE
- Connection pooling
- Query optimization

### Caching
- Redis for session storage
- Permission caching
- Role hierarchy caching

### API Optimization
- Request pagination
- Response compression
- Async processing
- Background tasks

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Update documentation
5. Submit pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the test cases for examples
