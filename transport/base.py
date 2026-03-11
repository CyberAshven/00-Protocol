from abc import ABC, abstractmethod
from typing import Callable, List


class Transport(ABC):
    @abstractmethod
    def send_packets(self, dest: str, packets: List[bytes], meta: dict) -> None:
        pass

    @abstractmethod
    def start_listener(self, on_packets: Callable[[List[bytes], dict], None]) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass