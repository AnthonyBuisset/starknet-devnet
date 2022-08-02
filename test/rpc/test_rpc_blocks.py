"""
Tests RPC blocks
"""
import pytest

from starknet_devnet.blueprints.rpc import BlockNumberDict, BlockHashDict
from starknet_devnet.general_config import DEFAULT_GENERAL_CONFIG

from .rpc_utils import rpc_call, get_block_with_transaction, pad_zero, gateway_call


@pytest.mark.parametrize("block_id", ["hash", "number", "tag"])
def test_get_block_with_tx_hashes(deploy_info, block_id):
    """
    Get block with tx hashes
    """
    gateway_block: dict = get_block_with_transaction(
        deploy_info["transaction_hash"])
    block_hash: str = gateway_block["block_hash"]
    block_number: int = gateway_block["block_number"]
    new_root: str = gateway_block["state_root"]

    block_id_map = {
        "hash": BlockNumberDict(block_number=block_number),
        "number": BlockHashDict(block_hash=block_hash),
        "tag": "latest",
    }

    resp = rpc_call(
        "starknet_getBlockWithTxHashes", params={"block_id": block_id_map[block_id]}
    )
    block = resp["result"]
    transaction_hash: str = pad_zero(deploy_info["transaction_hash"])

    assert block["block_hash"] == pad_zero(block_hash)
    assert block["parent_hash"] == pad_zero(gateway_block["parent_block_hash"])
    assert block["block_number"] == block_number
    assert block["status"] == "ACCEPTED_ON_L2"
    assert block["sequencer_address"] == hex(
        DEFAULT_GENERAL_CONFIG.sequencer_address)
    assert block["new_root"] == pad_zero(new_root)
    assert block["transactions"] == [transaction_hash]


# pylint: disable=unused-argument
@pytest.mark.parametrize("block_id", [BlockNumberDict(block_number=1234), BlockHashDict(block_hash="0x0")])
def test_get_block_with_tx_hashes_raises_on_incorrect_block_id(deploy_info, block_id):
    """
    Get block with tx hashes by incorrect block_id
    """
    ex = rpc_call(
        "starknet_getBlockWithTxHashes", params={"block_id": block_id}
    )

    assert ex["error"] == {
        "code": 24,
        "message": "Invalid block id"
    }


@pytest.mark.parametrize("block_id", ["hash", "number", "tag"])
def test_get_block_with_txs(deploy_info, block_id):
    """
    Get block with txs by block id
    """
    gateway_block: dict = get_block_with_transaction(
        deploy_info["transaction_hash"])
    block_hash: str = gateway_block["block_hash"]
    block_number: int = gateway_block["block_number"]
    new_root: str = gateway_block["state_root"]

    block_id_map = {
        "hash": BlockNumberDict(block_number=block_number),
        "number": BlockHashDict(block_hash=block_hash),
        "tag": "latest",
    }

    resp = rpc_call(
        "starknet_getBlockWithTxs", params={"block_id": block_id_map[block_id]}
    )
    block = resp["result"]

    assert block["block_hash"] == pad_zero(block_hash)
    assert block["parent_hash"] == pad_zero(gateway_block["parent_block_hash"])
    assert block["block_number"] == block_number
    assert block["status"] == "ACCEPTED_ON_L2"
    assert block["sequencer_address"] == hex(
        DEFAULT_GENERAL_CONFIG.sequencer_address)
    assert block["new_root"] == pad_zero(new_root)
    # assert block["transactions"] == [rpc_transaction(tx) for tx in gateway_block["transactions"]] #TODO


# pylint: disable=unused-argument
@pytest.mark.parametrize("block_id", [BlockNumberDict(block_number=1234), BlockHashDict(block_hash="0x0")])
def test_get_block_with_txs_raises_on_incorrect_block_id(deploy_info, block_id):
    """
    Get block with txs by incorrect block_id
    """
    ex = rpc_call(
        "starknet_getBlockWithTxHashes", params={"block_id": block_id}
    )

    assert ex["error"] == {
        "code": 24,
        "message": "Invalid block id"
    }


def test_get_block_by_hash(deploy_info):
    """
    Get block by hash
    """
    gateway_block: dict = get_block_with_transaction(
        deploy_info["transaction_hash"])
    block_hash: str = gateway_block["block_hash"]
    new_root: str = gateway_block["state_root"]
    transaction_hash: str = pad_zero(deploy_info["transaction_hash"])

    resp = rpc_call(
        "starknet_getBlockByHash", params={"block_hash": block_hash}
    )
    block = resp["result"]

    assert block["block_hash"] == pad_zero(block_hash)
    assert block["parent_hash"] == pad_zero(gateway_block["parent_block_hash"])
    assert block["block_number"] == gateway_block["block_number"]
    assert block["status"] == "ACCEPTED_ON_L2"
    assert block["sequencer_address"] == hex(
        DEFAULT_GENERAL_CONFIG.sequencer_address)
    assert block["new_root"] == pad_zero(new_root)
    assert block["transactions"] == [transaction_hash]


def test_get_block_by_hash_full_txn_scope(deploy_info):
    """
    Get block by hash with scope FULL_TXNS
    """
    block_hash: str = get_block_with_transaction(
        deploy_info["transaction_hash"])["block_hash"]
    transaction_hash: str = pad_zero(deploy_info["transaction_hash"])
    contract_address: str = pad_zero(deploy_info["address"])

    resp = rpc_call(
        "starknet_getBlockByHash",
        params={
            "block_hash": block_hash,
            "requested_scope": "FULL_TXNS"
        }
    )
    block = resp["result"]

    assert block["transactions"] == [{
        "txn_hash": transaction_hash,
        "max_fee": "0x0",
        "contract_address": contract_address,
        "calldata": [],
        "entry_point_selector": None,
        "signature": [],
        "version": "0x0"
    }]


def test_get_block_by_hash_full_txn_and_receipts_scope(deploy_info):
    """
    Get block by hash with scope FULL_TXN_AND_RECEIPTS
    """
    block_hash: str = get_block_with_transaction(
        deploy_info["transaction_hash"])["block_hash"]
    transaction_hash: str = pad_zero(deploy_info["transaction_hash"])
    contract_address: str = pad_zero(deploy_info["address"])

    resp = rpc_call(
        "starknet_getBlockByHash",
        params={
            "block_hash": block_hash,
            "requested_scope": "FULL_TXN_AND_RECEIPTS"
        }
    )
    block = resp["result"]

    assert block["transactions"] == [{
        "txn_hash": transaction_hash,
        "max_fee": "0x0",
        "contract_address": contract_address,
        "calldata": [],
        "entry_point_selector": None,
        "signature": [],
        "version": "0x0",
        "actual_fee": "0x0",
        "status": "ACCEPTED_ON_L2",
        "statusData": None,
    }]


def test_get_block_by_hash_raises_on_incorrect_hash(deploy_info):
    """
    Get block by incorrect hash
    """
    ex = rpc_call(
        "starknet_getBlockByHash", params={"block_hash": "0x0"}
    )

    assert ex["error"] == {
        "code": 24,
        "message": "Invalid block hash"
    }


@pytest.mark.parametrize("block_id", ["hash", "number", "tag"])
def test_get_block_transaction_count(deploy_info, block_id):
    """
    Get count of transactions in block by block id
    """
    block = get_block_with_transaction(deploy_info["transaction_hash"])
    block_hash: str = block["block_hash"]
    block_number: str = block["block_number"]

    block_id_map = {
        "hash": BlockNumberDict(block_number=block_number),
        "number": BlockHashDict(block_hash=block_hash),
        "tag": "latest",
    }

    resp = rpc_call(
        "starknet_getBlockTransactionCount", params={"block_id": block_id_map[block_id]}
    )
    count = resp["result"]

    assert count == 1


# pylint: disable=unused-argument
@pytest.mark.parametrize("block_id", [BlockNumberDict(block_number=99999), BlockHashDict(block_hash="0x0")])
def test_get_block_transaction_count_raises_on_incorrect_block_id(deploy_info, block_id):
    """
    Get count of transactions in block by incorrect block id
    """
    ex = rpc_call(
        "starknet_getBlockTransactionCount", params={"block_id": block_id}
    )

    assert ex["error"] == {
        "code": 24,
        "message": "Invalid block id"
    }


def test_get_block_number(deploy_info):
    """
    Get the number of the latest accepted block
    """

    latest_block = gateway_call("get_block", blockNumber="latest")
    latest_block_number: int = latest_block["block_number"]

    resp = rpc_call(
        "starknet_blockNumber", params={}
    )
    block_number: int = resp["result"]

    assert latest_block_number == block_number
