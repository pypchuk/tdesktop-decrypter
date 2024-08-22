from dataclasses import dataclass
from io import BytesIO
from pathlib import Path


@dataclass
class BufferedTData:
    files: dict[Path, BytesIO]

    def get_file(self, path: Path | str) -> BytesIO:
        if isinstance(path, str):
            path = Path(path)

        try:
            return self.files[path]
        except KeyError as exc:
            raise FileNotFoundError from exc
