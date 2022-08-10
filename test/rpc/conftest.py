"""
Fixtures for RPC tests
"""

from __future__ import annotations

import json
import typing

from test.util import load_file_content
from test.test_endpoints import send_transaction

import pytest
from starkware.starknet.services.api.contract_class import ContractClass
from starkware.starknet.services.api.gateway.transaction import Transaction, Deploy

from starknet_devnet.blueprints.rpc_utils import BlockNumberDict, BlockHashDict
from .rpc_utils import gateway_call, get_block_with_transaction, pad_zero

DEPLOY_CONTENT = load_file_content("deploy_rpc.json")
INVOKE_CONTENT = load_file_content("invoke_rpc.json")
DECLARE_CONTENT = load_file_content("declare.json")


@pytest.fixture(name="contract_class")
def fixture_contract_class() -> ContractClass:
    """
    Make ContractDefinition from deployment transaction used in tests
    """
    transaction: Deploy = typing.cast(Deploy, Transaction.loads(DEPLOY_CONTENT))
    return transaction.contract_definition


@pytest.fixture(name="class_hash")
def fixture_class_hash(deploy_info) -> str:
    """
    Class hash of deployed contract
    """
    class_hash = gateway_call("get_class_hash_at", contractAddress=deploy_info["address"])
    return pad_zero(class_hash)


@pytest.fixture(name="deploy_info", scope="module")
def fixture_deploy_info() -> dict:
    """
    Deploy a contract on devnet and return deployment info dict
    """
    resp = send_transaction(json.loads(DEPLOY_CONTENT))
    deploy_info = json.loads(resp.data.decode("utf-8"))
    return deploy_info


@pytest.fixture(name="invoke_info", scope="module")
def fixture_invoke_info() -> dict:
    """
    Make an invoke transaction on devnet and return invoke info dict
    """
    invoke_tx = json.loads(INVOKE_CONTENT)
    invoke_tx["calldata"] = ["0"]
    resp = send_transaction(invoke_tx)
    invoke_info = json.loads(resp.data.decode("utf-8"))
    return {**invoke_info, **invoke_tx}


@pytest.fixture(name="declare_info", scope="module")
def fixture_declare_info() -> dict:
    """
    Make a declare transaction on devnet and return declare info dict
    """
    declare_tx = json.loads(DECLARE_CONTENT)
    resp = send_transaction(declare_tx)
    declare_info = json.loads(resp.data.decode("utf-8"))
    return {**declare_info, **declare_tx}


@pytest.fixture(name="invoke_content", scope="module")
def fixture_invoke_content() -> dict:
    """
    Invoke content JSON object
    """
    return json.loads(INVOKE_CONTENT)


@pytest.fixture(name="deploy_content", scope="module")
def fixture_deploy_content() -> dict:
    """
    Deploy content JSON object
    """
    return json.loads(DEPLOY_CONTENT)


@pytest.fixture(name="declare_content", scope="module")
def fixture_declare_content() -> dict:
    """
    Declare content JSON object
    """
    return json.loads(DECLARE_CONTENT)


@pytest.fixture(name="gateway_block", scope="module")
def fixture_gateway_block(deploy_info) -> dict:
    """
    Block with Deploy transaction
    """
    return get_block_with_transaction(deploy_info["transaction_hash"])


@pytest.fixture(name="block_id", scope="module")
def fixture_block_id(gateway_block, request) -> dict:
    """
    BlockId of gateway_block depending on type in request
    """
    block_id_map = {
        "hash": BlockNumberDict(block_number=gateway_block["block_number"]),
        "number": BlockHashDict(block_hash=pad_zero(gateway_block["block_hash"])),
        "tag": "latest",
    }
    return block_id_map[request.param]
