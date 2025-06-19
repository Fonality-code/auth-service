from sqlalchemy.orm import Session
from src.models.user import User
from src.schemas.user import UserData
from src.core.security import verify_password, get_password_hash
from src.core.init_roles import get_role_initializer
from typing import Optional, Dict, Any, List



def get_user(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()

def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
    return db.query(User).filter(User.user_id == user_id).first()

def create_user(db: Session, user_data: UserData, initial_roles: Optional[List[str]] = None) -> User:
    """Create a new user with optional role assignment"""
    hashed_password = get_password_hash(user_data.password)
    db_user = User(
        email=user_data.email,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    # Assign roles to the new user
    role_initializer = get_role_initializer()

    if initial_roles:
        # Assign specified roles
        for role_name in initial_roles:
            role_initializer.assign_default_user_role(db, db_user.user_id, role_name)
    else:
        # Assign default user role
        role_initializer.assign_default_user_role(db, db_user.user_id, "user")

    # Refresh user to get the roles
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    user = get_user(db, email)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def update_password(db: Session, user: User, hashed_password: str) -> User:
    """Update a user's password with the provided hashed password"""
    user.hashed_password = hashed_password
    db.commit()
    db.refresh(user)
    return user

def update_user_profile(db: Session, user: User, update_data: Dict[str, Any]) -> User:
    """Update user profile data"""
    for key, value in update_data.items():
        if hasattr(user, key) and key not in ['id', 'user_id', 'email', 'hashed_password', 'created_at', 'updated_at']:
            setattr(user, key, value)

    db.commit()
    db.refresh(user)
    return user
