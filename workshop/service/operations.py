from typing import List, Optional

from workshop.models.operations import (
    Operation,
    OperationCreate,
    OperationKind,
    OperationUpdate
)

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from ..database import get_session
from .. import tables


class OperationsService:
    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def _get(
        self,
        user_id: int,
        operation_id: int = None,
    ) -> Operation:
        operation = (
            self.session
            .query(tables.Operation)
            .filter_by(
                id=operation_id,
                user_id=user_id,
            )
            .first()
        )
        if not operation:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        return operation

    def get(
        self,
        user_id: int,
        operation_id: int = None,
    ) -> Operation:
        return self._get(user_id, operation_id)

    def get_list(
        self,
        user_id: int,
        kind: Optional[OperationKind] = None,
    ) -> List[tables.Operation]:
        query = (
            self.session
            .query(tables.Operation)
            .filter_by(user_id=user_id)
        )
        if kind:
            query = query.filter_by(kind=kind)
        operations = query.all()
        return operations

    def create(
        self,
        user_id: int,
        operation_data: OperationCreate,
    ) -> tables.Operation:
        operation = tables.Operation(
            user_id=user_id,
            **operation_data.dict(),
        )
        self.session.add(operation)
        self.session.commit()
        return operation

    def update(
        self,
        user_id: int,
        operation_id: int,
        operation_data: OperationUpdate,
    ) -> tables.Operation:
        operation = self._get(user_id, operation_id)
        for field, value in operation_data:
            setattr(operation, field, value)
        self.session.commit()
        return operation

    def delete(
        self,
        user_id: int,
        operation_id: int,
    ):
        operation = self._get(user_id, operation_id)
        self.session.delete(operation)
        self.session.commit()
