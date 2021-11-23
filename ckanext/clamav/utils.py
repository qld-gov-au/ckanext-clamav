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
import ckan.plugins.toolkit as tk


log = logging.getLogger(__name__)

CLAMAV_STATUS_FOUND: str = "FOUND"
CLAMAV_STATUS_ERR_FILELIMIT: str = "ERR_FILELIMIT"
CLAMAV_STATUS_ERR_DISABLED: str = "ERR_DISABLED"
CLAMAV_CONF_SOCKET_PATH: str = "ckanext.clamav.socket_path"
CLAMAV_CONF_SOCKET_PATH_DF: str = "/var/run/clamav/clamd.ctl"
CLAMAV_CONF_UPLOAD_UNSCANNED: str = "ckanext.clamav.upload_unscanned"
CLAMAV_CONF_UPLOAD_UNSCANNED_DF: bool = True


def scan_file_for_viruses(data_dict: dict[str, Any]):
    """
    Scans upload file for malwares with `clamav` open-source anti-virus toolkit

    Args:
        data_dict (dict[str, Any]): upload resource data_dict

    Raises:
        logic.ValidationError: returns a validation error to the user
        upload form
    """
    upload_unscanned: bool = tk.asbool(tk.config.get(
        CLAMAV_CONF_UPLOAD_UNSCANNED, CLAMAV_CONF_UPLOAD_UNSCANNED_DF
    ))

    file: FileStorage = data_dict["upload"]
    status: str
    signature: Optional[str]
    status, signature = _scan_filestream(file)

    if status == CLAMAV_STATUS_ERR_DISABLED:
        log.info("Unable to connect to clamav. Can't scan the file")
        if upload_unscanned:
            log.info(_get_unscanned_file_message(file, data_dict['package_id']))
        else:
            raise logic.ValidationError({"Virus checker": [
                "The clamav is disabled. Can't uploade the file. Contact administrator"
            ]})
    elif status in (CLAMAV_STATUS_ERR_FILELIMIT,):
        log.warning(signature)
        if upload_unscanned:
            log.info(_get_unscanned_file_message(file, data_dict['package_id']))
        else:
            raise logic.ValidationError({"Virus checker": [signature]})
    elif status == CLAMAV_STATUS_FOUND:
        error_msg: str = (
            "malware has been found. "
            f"Filename: {file.filename}, signature: {signature}."
        )
        log.warning(error_msg)
        raise logic.ValidationError({"Virus checker": [error_msg]})


def _scan_filestream(file: FileStorage) -> tuple[str, Optional[str]]:
    """

    Args:
        file (FileStorage): werkzeug FileStorage object

    Returns:
        tuple[str, Optional[str]]: contains a status_code and a malware signature if found
        if status is returned error code, then instead of the signature there will
        be an error message.
    """
    socket_path: str = tk.config.get(
        CLAMAV_CONF_SOCKET_PATH, CLAMAV_CONF_SOCKET_PATH_DF
    )
    cd: ClamdUnixSocket = clamd.ClamdUnixSocket(socket_path)

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
        error_msg: str = "clamav is not accessible, check its status."
        log.critical(error_msg)
        return (CLAMAV_STATUS_ERR_DISABLED, error_msg)

    return scan_result["stream"]


def _get_unscanned_file_message(file: FileStorage, pkg_id: str) ->  str:
    return (
        "The unscanned file will be uploaded because unscanned fileupload is enabled. "
        f"Filename: {file.filename}, package_id: {pkg_id}, name: {file.filename or None}"
    )