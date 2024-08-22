from io import BytesIO
from typing import Any, Tuple, List
from dataclasses import dataclass
import hashlib

from tdesktop_decrypter.qt import read_qt_int32, read_qt_uint64
from tdesktop_decrypter.file_io import read_tdf_file_from_buffered_tdata, read_encrypted_file_from_buffered_tdata
from tdesktop_decrypter.settings import SettingsBlocks, read_settings_blocks
from tdesktop_decrypter.storage import decrypt_key_data_tdf, read_key_data_accounts, decrypt_settings_tdf
from tdesktop_decrypter.buffered_tdata import BufferedTData


def file_to_to_str(filekey: bytes):
    return ''.join(f'{b:X}'[::-1] for b in filekey)


def compute_data_name_key(dataname: str):
    filekey = hashlib.md5(dataname.encode('utf8')).digest()[:8]
    return file_to_to_str(filekey)


def compose_account_name(dataname: str, index: int):
    if index > 0:
        return f'{dataname}#{index+1}'
    else:
        return dataname


@dataclass
class MtpData:
    user_id: int
    current_dc_id: int
    keys: dict[int, bytes]
    keys_to_destroy: dict[int, bytes]

    def __repr__(self):
        return f'MtpData(user_id={self.user_id})'


@dataclass
class Account:
    index: int
    mtp_data: MtpData

    def __repr__(self):
        return f'ParsedAccount(index={self.index})'


@dataclass
class DecryptedTData:
    settings: dict[SettingsBlocks, Any]
    accounts: dict[int, Account]


class BufferedAccountReader:
    def __init__(self, index: int, dataname: str = None):
        self._index = index
        self._account_name = compose_account_name(dataname, index)
        self._dataname_key = compute_data_name_key(self._account_name)
        print(self._account_name, self._dataname_key)

    def read(self, tdata: BufferedTData, local_key: bytes) -> Account:
        index = self._index
        mtp_data = self._read_mtp_data(tdata, local_key)
        return Account(
            index,
            mtp_data,
        )

    @staticmethod
    def _read_mtp_authorization(data: BytesIO) -> MtpData:
        legacy_user_id = read_qt_int32(data)
        legacy_main_dc_id = read_qt_int32(data)

        if legacy_user_id == -1 and legacy_main_dc_id == -1:
            user_id = read_qt_uint64(data)
            main_dc_id = read_qt_int32(data)
        else:
            user_id = legacy_user_id
            main_dc_id = legacy_main_dc_id

        def read_keys():
            count = read_qt_int32(data)

            return {
                read_qt_int32(data): data.read(256)
                for _ in range(count)
            }

        return MtpData(
            user_id=user_id,
            current_dc_id=main_dc_id,
            keys=read_keys(),
            keys_to_destroy=read_keys(),
        )

    def _read_mtp_data(self, tdata: BufferedTData, local_key: bytes) -> MtpData:
        version, mtp_data_settings = read_encrypted_file_from_buffered_tdata(tdata, self._dataname_key, local_key)
        blocks = read_settings_blocks(version, BytesIO(mtp_data_settings))
        mtp_authorization = blocks[SettingsBlocks.dbiMtpAuthorization]
        return self._read_mtp_authorization(BytesIO(mtp_authorization))


class BufferedTDataDecrypter:
    SETTINGS = "settings"
    DATANAME = "data"

    def __init__(self):
        pass

    @property
    def key_data(self) -> str:
        return "key_" + self.DATANAME

    def decrypt(self, tdata: BufferedTData, passcode: str = ""):
        settings = self._read_settings(tdata)

        local_key, account_indexes = self._read_key_data(tdata, passcode)

        accounts = {}

        for account_index in account_indexes:
            account_reader = BufferedAccountReader(
                account_index,
                self.DATANAME,
            )
            accounts[account_index] = account_reader.read(tdata, local_key)

        return DecryptedTData(
            settings=settings,
            accounts=accounts,
        )

    def _read_settings(self, tdata: BufferedTData) -> dict[SettingsBlocks, Any]:
        settings_tdf = read_tdf_file_from_buffered_tdata(tdata, self.SETTINGS)
        settings_decrypted = decrypt_settings_tdf(settings_tdf)
        return read_settings_blocks(settings_tdf.version, BytesIO(settings_decrypted))

    def _read_key_data(self, tdata: BufferedTData, passcode: str) -> Tuple[bytes, List[int]]:
        key_data_tdf = read_tdf_file_from_buffered_tdata(tdata, self.key_data)
        local_key, account_indexes_data = decrypt_key_data_tdf(passcode.encode(), key_data_tdf)
        account_indexes, _ = read_key_data_accounts(BytesIO(account_indexes_data))

        return local_key, account_indexes
