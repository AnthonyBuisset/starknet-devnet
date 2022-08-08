"""
RPC routes
API Specification v0.1.0
https://github.com/starkware-libs/starknet-specs/releases/tag/v0.1.0
"""

from __future__ import annotations

from typing import Callable, Union, List, Tuple

from flask import Blueprint
from flask import request

from starknet_devnet.blueprints import rpc_endpoints
from starknet_devnet.blueprints.rpc_utils import RpcError, rpc_response, rpc_error

rpc = Blueprint("rpc", __name__, url_prefix="/rpc")


@rpc.route("", methods=["POST"])
async def base_route():
    """
    Base route for RPC calls
    """
    method, args, message_id = parse_body(request.json)

    try:
        result = await method(*args) if isinstance(args, list) else await method(**args)
    except NotImplementedError:
        return rpc_error(message_id=message_id, code=-2, message="Method not implemented")
    except RpcError as error:
        return rpc_error(message_id=message_id, code=error.code, message=error.message)

    return rpc_response(message_id=message_id, content=result)


def parse_body(body: dict) -> Tuple[Callable, Union[List, dict], int]:
    """
    Parse rpc call body to function name and params
    """
    methods = {
        "getBlockWithTxHashes": rpc_endpoints.get_block_with_tx_hashes,
        "getBlockWithTxs": rpc_endpoints.get_block_with_txs,
        "getStateUpdate": rpc_endpoints.get_state_update,
        "getStorageAt": rpc_endpoints.get_storage_at,
        "getTransactionByHash": rpc_endpoints.get_transaction_by_hash,
        "getTransactionByBlockIdAndIndex": rpc_endpoints.get_transaction_by_block_id_and_index,
        "getTransactionReceipt": rpc_endpoints.get_transaction_receipt,
        "getClass": rpc_endpoints.get_class,
        "getClassHashAt": rpc_endpoints.get_class_hash_at,
        "getClassAt": rpc_endpoints.get_class_at,
        "getBlockTransactionCount": rpc_endpoints.get_block_transaction_count,
        "call": rpc_endpoints.call,
        "estimateFee": rpc_endpoints.estimate_fee,
        "blockNumber": rpc_endpoints.block_number,
        "blockHashAndNumber": rpc_endpoints.block_hash_and_number,
        "chainId": rpc_endpoints.chain_id,
        "pendingTransactions": rpc_endpoints.pending_transactions,
        "syncing": rpc_endpoints.syncing,
        "getEvents": rpc_endpoints.get_events,
        "getNonce": rpc_endpoints.get_nonce,
        "addInvokeTransaction": rpc_endpoints.add_invoke_transaction,
        "addDeclareTransaction": rpc_endpoints.add_declare_transaction,
        "addDeployTransaction": rpc_endpoints.add_deploy_transaction,
    }
    method_name = body["method"].replace("starknet_", "")
    args: Union[List, dict] = body["params"]
    message_id = body["id"]

    if method_name not in methods:
        raise RpcError(code=-1, message="Method not found")

    return methods[method_name], args, message_id
