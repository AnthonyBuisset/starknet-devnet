"""
Utilities for RPC tests
"""

from __future__ import annotations

import json
from typing import Union

import requests

from starknet_devnet.server import app
from test.settings import APP_URL


def make_rpc_payload(method: str, params: Union[dict, list]):
    return {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 0
    }


def rpc_call_background_devnet(method: str, params: Union[dict, list]):
    payload = make_rpc_payload(method, params)
    return requests.post(f"{APP_URL}/rpc", json=payload).json()


def rpc_call(method: str, params: Union[dict, list]) -> dict:
    """
    Make a call to the RPC endpoint
    """
    return app.test_client().post("/rpc", json=make_rpc_payload(method, params)).json


def gateway_call(method: str, **kwargs):
    """
    Make a call to the gateway
    """
    resp = app.test_client().get(
        f"/feeder_gateway/{method}?{'&'.join(f'{key}={value}&' for key, value in kwargs.items())}"
    )
    return json.loads(resp.data.decode("utf-8"))


def get_block_with_transaction(transaction_hash: str) -> dict:
    """
    Retrieve block for given transaction
    """
    transaction = gateway_call("get_transaction", transactionHash=transaction_hash)
    block_number: int = transaction["block_number"]
    block = gateway_call("get_block", blockNumber=block_number)
    return block


def pad_zero(felt: str) -> str:
    """
    Convert felt with format `0xValue` to format `0x0Value`
    """
    if felt == "0x0":
        return "0x00"
    return "0x0" + felt.lstrip("0x")
