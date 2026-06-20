from sqlalchemy.orm import Session
from app.models.client import Client

class ClientRepository:

    def get_all(self, db: Session):
        return db.query(Client).all()

    def get_by_id(self, db: Session, client_id: str):
        return db.query(Client).filter(
            Client.id == client_id
        ).first()

    def get_by_identifier(self, db: Session, client_identifier: str):
        # Used by the gateway during handshake: client connects and
        # announces its identifier, we look up its keys by that.
        return db.query(Client).filter(
            Client.client_identifier == client_identifier
        ).first()

    def create(self, db: Session, client_data: dict):
        client = Client(**client_data)

        db.add(client)
        db.commit()
        db.refresh(client)

        return client

    def update(self, db: Session, client_id: str, update_data: dict):
        client = self.get_by_id(db, client_id)

        if not client:
            return None

        for key, value in update_data.items():
            setattr(client, key, value)

        db.commit()
        db.refresh(client)

        return client

    def delete(self, db: Session, client_id: str):
        client = self.get_by_id(db, client_id)

        if not client:
            return None

        db.delete(client)
        db.commit()

        return client