from abc import ABC, abstractmethod

from deltadb.model.schema import SchemaModel


class BaseLoader(ABC):
    @abstractmethod
    def load(self) -> SchemaModel:
        raise NotImplementedError
