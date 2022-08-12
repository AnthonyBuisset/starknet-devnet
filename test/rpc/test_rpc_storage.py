"""
Tests RPC storage
"""

import pytest
from starkware.starknet.public.abi import get_storage_var_address

from .rpc_utils import rpc_call, get_block_with_transaction, pad_zero


@pytest.mark.usefixtures("run_devnet_in_background")
def test_get_storage_at(deploy_info):
    """
    Get storage at address
    """
    contract_address: str = deploy_info["address"]
    key: str = hex(get_storage_var_address("balance"))
    block_id: str = "latest"

    resp = rpc_call(
        "starknet_getStorageAt", params={
            "contract_address": pad_zero(contract_address),
            "key": key,
            "block_id": block_id,
        }
    )
    storage = resp["result"]

    assert storage == "0x00"


# pylint: disable=unused-argument
@pytest.mark.usefixtures("run_devnet_in_background")
def test_get_storage_at_raises_on_incorrect_contract(deploy_info):
    """
    Get storage at incorrect contract
    """
    key: str = hex(get_storage_var_address("balance"))
    block_id: str = "latest"

    ex = rpc_call(
        "starknet_getStorageAt", params={
            "contract_address": "0x00",
            "key": key,
            "block_id": block_id,
        }
    )

    assert ex["error"] == {
        "code": 20,
        "message": "Contract not found"
    }


# internal workings of get_storage_at would have to be changed for this to work
# since currently it will (correctly) return 0x0 for any incorrect key
@pytest.mark.xfail
@pytest.mark.usefixtures("run_devnet_in_background")
def test_get_storage_at_raises_on_incorrect_key(deploy_info):
    """
    Get storage at incorrect key
    """
    block = get_block_with_transaction(deploy_info["transaction_hash"])

    contract_address: str = deploy_info["address"]
    block_id = {"block_number": block["block_number"]}

    ex = rpc_call(
        "starknet_getStorageAt", params={
            "contract_address": pad_zero(contract_address),
            "key": "0x00",
            "block_id": block_id,
        }
    )

    assert ex["error"] == {
        "code": 23,
        "message": "Invalid storage key"
    }


# This will fail as get_storage_at only supports "latest" as block_id
# and will fail with custom exception if other is provided
@pytest.mark.xfail
@pytest.mark.usefixtures("run_devnet_in_background")
def test_get_storage_at_raises_on_incorrect_block_id(deploy_info):
    """
    Get storage at incorrect block id
    """

    contract_address: str = deploy_info["address"]
    key: str = hex(get_storage_var_address("balance"))

    ex = rpc_call(
        "starknet_getStorageAt", params={
            "contract_address": pad_zero(contract_address),
            "key": key,
            "block_id": "0x0",
        }
    )

    assert ex["error"] == {
        "code": 24,
        "message": "Invalid block id"
    }
