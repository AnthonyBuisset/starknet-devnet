from __future__ import annotations

from starkware.starknet.definitions import constants
from starkware.starknet.public.abi import get_selector_from_name

from starknet_devnet.blueprints.rpc.structures.payloads import RpcInvokeTransaction
from starknet_devnet.constants import DEFAULT_GAS_PRICE
from test.rpc.rpc_utils import rpc_call_background_devnet
from test.shared import CONTRACT_PATH
from test.util import devnet_in_background, deploy


@devnet_in_background("--gas-price", str(DEFAULT_GAS_PRICE))
def test_estimate_happy_path():
    deploy_info = deploy(CONTRACT_PATH, ["0"])

    tx: RpcInvokeTransaction = {
        "contract_address": deploy_info["address"],
        "entry_point_selector": hex(get_selector_from_name("sum_point_array")),
        "calldata": ["0x02", "0x01", "0x02", "0x03", "0x04"],
        # It is not verified and might be removed in next RPC version
        "transaction_hash": "0x00",
        "max_fee": "0x00",
        "version": hex(constants.TRANSACTION_VERSION),
        "signature": [],
        "nonce": "0x00",
        "type": "INVOKE",
    }
    res = rpc_call_background_devnet(
        "starknet_estimateFee", {"request": tx, "block_id": "latest"}
    )


    print("RESULT", res)