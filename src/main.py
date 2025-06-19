from fastapi import FastAPI, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from src.api.v1.endpoints import auth
from src.api.v1.endpoints import roles
from src.core.database import engine, get_db
from src.models import user as user_model
from src.models import session as session_model
from src.models import role as role_model
from src.services.session import cleanup_expired_sessions
from src.core.init_roles import init_default_roles_and_permissions
from sqlalchemy.orm import Session
import asyncio
from contextlib import asynccontextmanager
from src.core.middleware import AuthMiddleware, TokenValidationMiddleware

# Setup startup event to create a background task for session cleanup
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables
    user_model.Base.metadata.create_all(bind=engine)
    session_model.Base.metadata.create_all(bind=engine)
    role_model.Base.metadata.create_all(bind=engine)

    # Initialize default roles and permissions
    try:
        from src.core.database import SessionLocal
        db = SessionLocal()
        try:
            result = init_default_roles_and_permissions(db)
            print("Role system initialization result:", result)
        finally:
            db.close()
    except Exception as e:
        print(f"Error initializing roles: {e}")

    # Start background task for session cleanup
    task = asyncio.create_task(periodic_cleanup_sessions())
    yield
    # Cancel the task when shutting down
    task.cancel()

# Create the app with lifespan manager
app = FastAPI(title="Auth Microservice", lifespan=lifespan)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Add authentication middleware
app.add_middleware(AuthMiddleware)
app.add_middleware(TokenValidationMiddleware)

# Include API routes
app.include_router(auth.router, prefix="/api/v1", tags=["auth"])
app.include_router(roles.router, prefix="/api/v1", tags=["roles"])

# Periodic task for session cleanup
async def periodic_cleanup_sessions():
    while True:
        try:
            # Create a new database session for this task
            from src.core.database import SessionLocal
            db = SessionLocal()
            try:
                count = cleanup_expired_sessions(db)
                print(f"Cleaned up {count} expired sessions")
            finally:
                db.close()
        except Exception as e:
            print(f"Error cleaning up sessions: {str(e)}")

        # Sleep for 1 hour
        await asyncio.sleep(60 * 60)

@app.get("/")
async def root():
    return {"message": "Auth Microservice is running"}

@app.get("/health")
async def health():
    return {"message": "Auth Microservice is healthy"}

# Add a manual cleanup endpoint for testing
@app.post("/api/v1/admin/cleanup-sessions")
async def manual_cleanup(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Manually trigger session cleanup (for testing)"""
    background_tasks.add_task(cleanup_expired_sessions, db)
    return {"message": "Session cleanup triggered"}
