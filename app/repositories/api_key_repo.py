from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.api_key import ApiKey


class ApiKeyRepository:

    def get_by_key_id(self, db: Session, key_id: str) -> ApiKey | None:
        """Look up an ApiKey by its public key_id prefix."""
        return db.query(ApiKey).filter(ApiKey.key_id == key_id).first()

    def revoke(self, db: Session, key_id: str) -> ApiKey | None:
        """Revoke an API key by setting revoked_at to the current timestamp."""
        api_key = self.get_by_key_id(db, key_id)
        if api_key:
            api_key.revoked_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(api_key)
        return api_key

    def list_all(self, db: Session) -> list[ApiKey]:
        """List all API keys in the system."""
        return db.query(ApiKey).all()

    def update_last_used(self, db: Session, key_id: str) -> None:
        """Update the last_used_at timestamp for a given key_id."""
        from sqlalchemy import update as _update
        db.execute(
            _update(ApiKey)
            .where(ApiKey.key_id == key_id)
            .values(last_used_at=datetime.now(timezone.utc))
        )
        db.commit()

    def _insert(self, db: Session, api_key_data: dict) -> ApiKey:
        """
        Internal insert method for out-of-band provisioning.
        api_key_data should contain: key_id, hashed_key, name, expires_at (optional), scopes (optional)
        """
        api_key = ApiKey(**api_key_data)
        db.add(api_key)
        db.commit()
        db.refresh(api_key)
        return api_key
