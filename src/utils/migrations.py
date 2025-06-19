"""
Database migration utilities for role-based access control
"""
from sqlalchemy.orm import Session
from sqlalchemy import text, inspect
from src.core.database import engine, SessionLocal
from src.models.role import Role, Permission, UserRoleAssignment
from src.models.user import User
from src.models.session import Session as SessionModel
from src.core.init_roles import init_default_roles_and_permissions
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class DatabaseMigration:
    def __init__(self):
        self.engine = engine

    def check_table_exists(self, table_name: str) -> bool:
        """Check if a table exists in the database"""
        inspector = inspect(self.engine)
        return table_name in inspector.get_table_names()

    def check_column_exists(self, table_name: str, column_name: str) -> bool:
        """Check if a column exists in a table"""
        inspector = inspect(self.engine)
        if not self.check_table_exists(table_name):
            return False

        columns = inspector.get_columns(table_name)
        return any(col['name'] == column_name for col in columns)

    def create_role_tables(self) -> bool:
        """Create role-related tables if they don't exist"""
        try:
            # Create all tables
            Role.__table__.create(bind=self.engine, checkfirst=True)
            Permission.__table__.create(bind=self.engine, checkfirst=True)
            UserRoleAssignment.__table__.create(bind=self.engine, checkfirst=True)

            # Create association tables
            from src.models.role import user_roles, role_permissions
            user_roles.create(bind=self.engine, checkfirst=True)
            role_permissions.create(bind=self.engine, checkfirst=True)

            logger.info("Role tables created successfully")
            return True
        except Exception as e:
            logger.error(f"Error creating role tables: {e}")
            return False

    def migrate_database(self) -> Dict[str, Any]:
        """Run complete database migration"""
        results = {
            "success": False,
            "tables_created": [],
            "tables_existed": [],
            "errors": []
        }

        try:
            # Check and create base tables
            tables_to_check = [
                ("users", User.__table__),
                ("sessions", SessionModel.__table__),
                ("roles", Role.__table__),
                ("permissions", Permission.__table__),
                ("user_role_assignments", UserRoleAssignment.__table__),
            ]

            for table_name, table_obj in tables_to_check:
                if self.check_table_exists(table_name):
                    results["tables_existed"].append(table_name)
                    logger.info(f"Table '{table_name}' already exists")
                else:
                    try:
                        table_obj.create(bind=self.engine, checkfirst=True)
                        results["tables_created"].append(table_name)
                        logger.info(f"Table '{table_name}' created successfully")
                    except Exception as e:
                        error_msg = f"Error creating table '{table_name}': {e}"
                        results["errors"].append(error_msg)
                        logger.error(error_msg)

            # Create association tables
            from src.models.role import user_roles, role_permissions

            association_tables = [
                ("user_roles", user_roles),
                ("role_permissions", role_permissions)
            ]

            for table_name, table_obj in association_tables:
                if self.check_table_exists(table_name):
                    results["tables_existed"].append(table_name)
                    logger.info(f"Association table '{table_name}' already exists")
                else:
                    try:
                        table_obj.create(bind=self.engine, checkfirst=True)
                        results["tables_created"].append(table_name)
                        logger.info(f"Association table '{table_name}' created successfully")
                    except Exception as e:
                        error_msg = f"Error creating association table '{table_name}': {e}"
                        results["errors"].append(error_msg)
                        logger.error(error_msg)

            # Initialize default roles and permissions if no errors
            if not results["errors"]:
                try:
                    db = SessionLocal()
                    try:
                        role_init_result = init_default_roles_and_permissions(db)
                        results["role_initialization"] = role_init_result
                        logger.info("Default roles and permissions initialized")
                    finally:
                        db.close()
                except Exception as e:
                    error_msg = f"Error initializing roles and permissions: {e}"
                    results["errors"].append(error_msg)
                    logger.error(error_msg)

            results["success"] = len(results["errors"]) == 0

        except Exception as e:
            error_msg = f"Error during database migration: {e}"
            results["errors"].append(error_msg)
            logger.error(error_msg)

        return results

    def add_role_columns_to_user_response(self) -> bool:
        """Migration helper to ensure user responses include role information"""
        # This is handled in the schema updates, no SQL migration needed
        return True

    def cleanup_orphaned_assignments(self, db: Session) -> int:
        """Clean up orphaned role assignments"""
        try:
            # Remove assignments where user doesn't exist
            orphaned_count = db.execute(text("""
                DELETE FROM user_role_assignments
                WHERE user_id NOT IN (SELECT user_id FROM users)
            """)).rowcount

            # Remove assignments where role doesn't exist
            orphaned_count += db.execute(text("""
                DELETE FROM user_role_assignments
                WHERE role_id NOT IN (SELECT role_id FROM roles)
            """)).rowcount

            db.commit()
            logger.info(f"Cleaned up {orphaned_count} orphaned role assignments")
            return orphaned_count

        except Exception as e:
            db.rollback()
            logger.error(f"Error cleaning up orphaned assignments: {e}")
            return 0

    def update_existing_users_with_default_role(self, db: Session) -> int:
        """Assign default 'user' role to existing users who don't have any roles"""
        try:
            from src.services.role import get_role_service
            from src.core.init_roles import get_role_initializer

            role_service = get_role_service()
            role_initializer = get_role_initializer()

            # Get all users
            users = db.query(User).all()
            updated_count = 0

            for user in users:
                # Check if user has any roles
                user_roles = role_service.get_user_roles(db, user.user_id)

                if not user_roles:
                    # Assign default user role
                    success = role_initializer.assign_default_user_role(db, user.user_id, "user")
                    if success:
                        updated_count += 1
                        logger.info(f"Assigned default role to user: {user.email}")

            logger.info(f"Updated {updated_count} users with default roles")
            return updated_count

        except Exception as e:
            logger.error(f"Error updating existing users with default roles: {e}")
            return 0

def run_migration() -> Dict[str, Any]:
    """Run the complete database migration"""
    migration = DatabaseMigration()
    return migration.migrate_database()

def run_user_role_migration() -> Dict[str, Any]:
    """Run migration to add roles to existing users"""
    results = {"success": False, "users_updated": 0, "errors": []}

    try:
        migration = DatabaseMigration()
        db = SessionLocal()
        try:
            # Clean up orphaned assignments first
            orphaned_count = migration.cleanup_orphaned_assignments(db)
            results["orphaned_cleaned"] = orphaned_count

            # Update existing users with default roles
            updated_count = migration.update_existing_users_with_default_role(db)
            results["users_updated"] = updated_count

            results["success"] = True

        finally:
            db.close()

    except Exception as e:
        error_msg = f"Error during user role migration: {e}"
        results["errors"].append(error_msg)
        logger.error(error_msg)

    return results

if __name__ == "__main__":
    # Run migration when script is executed directly
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) > 1 and sys.argv[1] == "user-roles":
        print("Running user role migration...")
        result = run_user_role_migration()
    else:
        print("Running database migration...")
        result = run_migration()

    print("Migration completed:")
    print(f"Success: {result['success']}")
    if 'tables_created' in result:
        print(f"Tables created: {result['tables_created']}")
    if 'tables_existed' in result:
        print(f"Tables existed: {result['tables_existed']}")
    if 'users_updated' in result:
        print(f"Users updated: {result['users_updated']}")
    if result.get('errors'):
        print(f"Errors: {result['errors']}")
