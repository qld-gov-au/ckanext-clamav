from io import BytesIO

import pytest
import ckantoolkit as tk
from ckan.tests import helpers, factories

eicar_string = b"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"  # noqa: W605 invalid escape sequence '\P'
clean_string = b"safe file content"


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
        upload={'upload': (BytesIO(clean_string), 'safe.txt')},
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
        helpers.call_action(
            "resource_create",
            context={"user": user["name"]},
            package_id=dataset["id"],
            url="",
            upload={'upload': (BytesIO(eicar_string), 'infected.txt')},
            name="Infected File",
        )

    # Verify ClamAV blocked the file
    assert "infected file" in str(excinfo.value).lower(), str(excinfo.value).lower()
