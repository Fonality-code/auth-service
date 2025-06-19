from sqlalchemy.orm import Session as DbSession
from src.models.session import Session
from datetime import datetime, timedelta
from typing import Optional, List
from src.core.config import get_settings

settings = get_settings()

def create_session(
    db: DbSession,
    user_id: str,
    refresh_token: str,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None
) -> Session:
    """Create a new session for a user"""
    # Calculate expiry time
    expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    # Create session record
    db_session = Session(
        user_id=user_id,
        refresh_token=refresh_token,
        user_agent=user_agent,
        ip_address=ip_address,
        expires_at=expires_at
    )

    db.add(db_session)
    db.commit()
    db.refresh(db_session)

    return db_session

def get_session_by_refresh_token(db: DbSession, refresh_token: str) -> Optional[Session]:
    """Get a session by its refresh token"""
    return db.query(Session).filter(
        Session.refresh_token == refresh_token,
        Session.is_active == True,
        Session.expires_at > datetime.utcnow()
    ).first()

def get_user_active_sessions(db: DbSession, user_id: str) -> List[Session]:
    """Get all active sessions for a user"""
    return db.query(Session).filter(
        Session.user_id == user_id,
        Session.is_active == True,
        Session.expires_at > datetime.utcnow()
    ).all()

def invalidate_session(db: DbSession, session_id: str) -> bool:
    """Invalidate a single session"""
    db_session = db.query(Session).filter(Session.session_id == session_id).first()
    if not db_session:
        return False

    db_session.is_active = False
    db.commit()
    return True

def invalidate_user_sessions(db: DbSession, user_id: str, exclude_session_id: Optional[str] = None) -> int:
    """Invalidate all sessions for a user, optionally excluding a specific session"""
    query = db.query(Session).filter(Session.user_id == user_id, Session.is_active == True)

    if exclude_session_id:
        query = query.filter(Session.session_id != exclude_session_id)

    sessions = query.all()
    count = 0

    for session in sessions:
        session.is_active = False
        count += 1

    db.commit()
    return count

def update_session_refresh_token(db: DbSession, session: Session, new_refresh_token: str) -> Session:
    """Update a session's refresh token"""
    session.refresh_token = new_refresh_token
    session.updated_at = datetime.now()
    db.commit()
    db.refresh(session)
    return session

def cleanup_expired_sessions(db: DbSession) -> int:
    """Cleanup expired sessions"""
    sessions = db.query(Session).filter(
        Session.expires_at < datetime.utcnow(),
        Session.is_active == True
    ).all()

    count = 0
    for session in sessions:
        session.is_active = False
        count += 1

    db.commit()
    return count
