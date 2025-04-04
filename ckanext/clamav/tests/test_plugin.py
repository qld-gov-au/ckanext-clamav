from io import BytesIO

import pytest
import ckantoolkit as tk
from ckan.tests import helpers, factories
from werkzeug.datastructures import FileStorage as FlaskFileStorage

eicar_string = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
clean_string = b"safe file content"


def create_file(data, filename):
    test_file = BytesIO()
    if isinstance(data, str):
        data = bytes(data, encoding="utf-8")
    test_file.write(data)
    test_file.seek(0)
    return FlaskFileStorage(test_file, filename)


@pytest.mark.ckan_config("ckan.plugins", "my_clamav_plugin")
def test_clamav_allows_clean_file():
    user = factories.User()
    # normally creating a resource causes xloader_submit to be called,
    # but we avoid that by setting an invalid format
    dataset = factories.Dataset(user=user)

    """Test that ClamAV allows clean files."""
    res = helpers.call_action(
        "resource_create",
        context={"user": user["name"]},
        package_id=dataset["id"],
        url="",
        upload=create_file(clean_string, 'safe.txt'),
        name="Clean File",
    )

    # Check if the resource was created
    assert "id" in res, "Resource was not created successfully:" + res


@pytest.mark.ckan_config("ckan.plugins", "clamav")
def test_clamav_blocks_infected_file():
    user = factories.User()
    # normally creating a resource causes xloader_submit to be called,
    # but we avoid that by setting an invalid format
    dataset = factories.Dataset(user=user)

    """Test that ClamAV blocks infected files."""
    with pytest.raises(tk.ValidationError) as excinfo:
        res = helpers.call_action(
            "resource_create",
            context={"user": user["name"]},
            package_id=dataset["id"],
            url="",
            upload=create_file(eicar_string, 'infected.txt'),
            name="Infected File",
        )
        pytest.fail("Was not tagged as infected:{}".format(res))  # provide nice message if we did not throw exception

    # Verify ClamAV blocked the file
    assert "infected file" in str(excinfo.value).lower(), str(excinfo.value).lower()


@pytest.mark.ckan_config("ckan.plugins", "clamav")
@pytest.mark.ckan_config("ckanext.clamav.socket_path", "")
@pytest.mark.ckan_config("ckanext.clamav.socket_type", "tcp")
@pytest.mark.ckan_config("ckanext.clamav.tcp.host", "127.0.0.1")
@pytest.mark.ckan_config("ckanext.clamav.tcp.port", "3310")
def test_clamav_allows_clean_file_via_tcp_calmd():
    user = factories.User()
    # normally creating a resource causes xloader_submit to be called,
    # but we avoid that by setting an invalid format
    dataset = factories.Dataset(user=user)

    """Test that ClamAV allows clean files."""
    res = helpers.call_action(
        "resource_create",
        context={"user": user["name"]},
        package_id=dataset["id"],
        url="",
        upload=create_file(clean_string, 'safe.txt'),
        name="Clean File",
    )

    # Check if the resource was created
    assert "id" in res, "Resource was not created successfully:" + res


@pytest.mark.ckan_config("ckan.plugins", "clamav")
@pytest.mark.ckan_config("ckanext.clamav.socket_path", "")
@pytest.mark.ckan_config("ckanext.clamav.socket_type", "tcp")
@pytest.mark.ckan_config("ckanext.clamav.tcp.host", "127.0.0.1")
@pytest.mark.ckan_config("ckanext.clamav.tcp.port", "3310")
def test_clamav_blocks_infected_file_via_tcp_calmd():
    user = factories.User()
    # normally creating a resource causes xloader_submit to be called,
    # but we avoid that by setting an invalid format
    dataset = factories.Dataset(user=user)

    """Test that ClamAV blocks infected files."""
    with pytest.raises(tk.ValidationError) as excinfo:
        res = helpers.call_action(
            "resource_create",
            context={"user": user["name"]},
            package_id=dataset["id"],
            url="",
            upload=create_file(eicar_string, 'infected.txt'),
            name="Infected File",
        )
        pytest.fail("Was not tagged as infected:{}".format(res))  # provide nice message if we did not throw exception

    # Verify ClamAV blocked the file
    assert "infected file" in str(excinfo.value).lower(), str(excinfo.value).lower()
