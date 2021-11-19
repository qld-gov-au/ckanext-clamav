from __future__ import annotations
import logging
from typing import Optional, Any

import clamd
from clamd import (
    ClamdUnixSocket,
    ConnectionError as ClamConnectionError,
    BufferTooLongError,
)
from werkzeug.datastructures import FileStorage

import ckan.logic as logic


log = logging.getLogger(__name__)

CLAMAV_STATUS_FOUND: str = "FOUND"
CLAMAV_STATUS_ERR_FILELIMIT: str = "ERR_FILELIMIT"
CLAMAV_STATUS_ERR_DISABLED: str = "ERR_DISABLED"


def scan_file_for_viruses(data_dict: dict[str, Any]):
    """
    Scans upload file for malwares with `clamav` open-source anti-virus toolkit

    Args:
        data_dict (dict[str, Any]): upload resource data_dict

    Raises:
        logic.ValidationError: returns a validation error to the user
        upload form
    """
    file: FileStorage = data_dict["upload"]
    status: str
    signature: Optional[str]
    status, signature = _scan_filestream(file)

    if status == CLAMAV_STATUS_ERR_DISABLED:
        return
    elif status in (CLAMAV_STATUS_ERR_FILELIMIT,):
        raise logic.ValidationError({"Virus checker": [signature]})
    elif status == CLAMAV_STATUS_FOUND:
        raise logic.ValidationError(
            {
                "Virus checker": [
                    "malware has been found. "
                    f"Filename: {file.filename}, signature: {signature}."
                ]
            }
        )


def _scan_filestream(file: FileStorage) -> tuple[str, Optional[str]]:
    """

    Args:
        file (FileStorage): werkzeug FileStorage object

    Returns:
        tuple[str, Optional[str]]: contains a status_code and a malware signature if found
        if status is returned error code, then instead of the signature there will
        be an error message.
    """
    cd: ClamdUnixSocket = clamd.ClamdUnixSocket()

    try:
        scan_result: dict[str, tuple[str, Optional[str]]] = cd.instream(file.stream)
    except BufferTooLongError:
        error_msg: str = (
            "the uploaded file exceeds the filesize limit "
            "The file will not be scanned"
        )
        log.error(error_msg)
        return (CLAMAV_STATUS_ERR_FILELIMIT, error_msg)
    except ClamConnectionError:
        error_msg: str = "clamav-daemon daemon is not accessible, check its status."
        log.critical(error_msg)
        return (CLAMAV_STATUS_ERR_DISABLED, error_msg)

    return scan_result["stream"]
