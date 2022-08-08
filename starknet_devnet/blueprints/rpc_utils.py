"""
RPC utilities
API Specification v0.1.0
https://github.com/starkware-libs/starknet-specs/releases/tag/v0.1.0
"""

from __future__ import annotations

from typing import Callable, Union, List, Optional

from starkware.starknet.services.api.contract_class import ContractClass
from starkware.starknet.services.api.feeder_gateway.response_objects import (
    BlockStatus,
    StarknetBlock,
    InvokeSpecificInfo,
    DeploySpecificInfo,
    TransactionReceipt,
    TransactionStatus,
    TransactionSpecificInfo,
    TransactionType,
    BlockStateUpdate,
    DeclareSpecificInfo
)
from starkware.starknet.services.api.gateway.transaction import InvokeFunction
from starkware.starknet.services.api.gateway.transaction_utils import compress_program
from typing_extensions import TypedDict, Literal

from starknet_devnet.state import state
from ..util import StarknetDevnetException

Felt = str

BlockHash = Felt
BlockNumber = int
BlockTag = Literal["latest", "pending"]


class BlockHashDict(TypedDict):
    """
    TypedDict class for BlockId with block hash
    """
    block_hash: BlockHash


class BlockNumberDict(TypedDict):
    """
    TypedDict class for BlockId with block number
    """
    block_number: BlockNumber


BlockId = Union[BlockHashDict, BlockNumberDict, BlockTag]

TxnStatus = Literal["PENDING", "ACCEPTED_ON_L2", "ACCEPTED_ON_L1", "REJECTED"]
RpcBlockStatus = Literal["PENDING", "ACCEPTED_ON_L2", "ACCEPTED_ON_L1", "REJECTED"]

TxnHash = Felt
Address = Felt
NumAsHex = str
# Pending transactions will not be supported since it
# doesn't make much sense with the current implementation of devnet
TxnType = Literal["DECLARE", "DEPLOY", "INVOKE"]


def rpc_txn_type(transaction_type: str) -> TxnType:
    """
    Convert gateway transaction type to RPC TxnType
    """
    txn_type_map = {
        "DEPLOY": "DEPLOY",
        "DECLARE": "DECLARE",
        "INVOKE_FUNCTION": "INVOKE",
    }
    return txn_type_map[transaction_type]


class RpcBlock(TypedDict):
    """
    TypeDict for rpc block
    """
    status: RpcBlockStatus
    block_hash: BlockHash
    parent_hash: BlockHash
    block_number: BlockNumber
    new_root: Felt
    timestamp: int
    sequencer_address: Felt
    transactions: Union[List[str], List[RpcTransaction]]


class RpcInvokeTransaction(TypedDict):
    """
    TypedDict for rpc invoke transaction
    """
    contract_address: Address
    entry_point_selector: Felt
    calldata: List[Felt]
    # Common
    transaction_hash: TxnHash
    max_fee: Felt
    version: NumAsHex
    signature: List[Felt]
    nonce: Felt
    type: TxnType


class RpcDeclareTransaction(TypedDict):
    """
    TypedDict for rpc declare transaction
    """
    class_hash: Felt
    sender_address: Address
    # Common
    transaction_hash: TxnHash
    max_fee: Felt
    version: NumAsHex
    signature: List[Felt]
    nonce: Felt
    type: TxnType


class RpcDeployTransaction(TypedDict):
    """
    TypedDict for rpc deploy transaction
    """
    transaction_hash: TxnHash
    class_hash: Felt
    version: NumAsHex
    type: TxnType
    contract_address: Felt
    contract_address_salt: Felt
    constructor_calldata: List[Felt]


RpcTransaction = Union[RpcInvokeTransaction, RpcDeclareTransaction, RpcDeployTransaction]


class FunctionCall(TypedDict):
    """
    TypedDict for rpc function call
    """
    contract_address: Address
    entry_point_selector: Felt
    calldata: List[Felt]


def rpc_invoke_transaction(transaction: InvokeSpecificInfo) -> RpcInvokeTransaction:
    """
    Convert gateway invoke transaction to rpc format
    """
    txn: RpcInvokeTransaction = {
        "contract_address": rpc_felt(transaction.contract_address),
        "entry_point_selector": rpc_felt(transaction.entry_point_selector),
        "calldata": [rpc_felt(data) for data in transaction.calldata],
        "transaction_hash": rpc_felt(transaction.transaction_hash),
        "max_fee": rpc_felt(transaction.max_fee),
        "version": hex(0x0),
        "signature": [rpc_felt(value) for value in transaction.signature],
        "nonce": rpc_felt(0),
        "type": rpc_txn_type(transaction.tx_type.name),
    }
    return txn


def rpc_declare_transaction(transaction: DeclareSpecificInfo) -> RpcDeclareTransaction:
    """
    Convert gateway declare transaction to rpc format
    """
    txn: RpcDeclareTransaction = {
        "class_hash": rpc_felt(transaction.class_hash),
        "sender_address": rpc_felt(transaction.sender_address),
        "transaction_hash": rpc_felt(transaction.transaction_hash),
        "max_fee": rpc_felt(transaction.max_fee),
        "version": hex(transaction.version),
        "signature": [rpc_felt(value) for value in transaction.signature],
        "nonce": rpc_felt(transaction.nonce),
        "type": rpc_txn_type(transaction.tx_type.name),
    }
    return txn


def rpc_deploy_transaction(transaction: DeploySpecificInfo) -> RpcDeployTransaction:
    """
    Convert gateway deploy transaction to rpc format
    """
    txn: RpcDeployTransaction = {
        "transaction_hash": rpc_felt(transaction.transaction_hash),
        "class_hash": rpc_felt(transaction.class_hash),
        "version": hex(0x0),
        "type": rpc_txn_type(transaction.tx_type.name),
        "contract_address": rpc_felt(transaction.contract_address),
        "contract_address_salt": rpc_felt(transaction.contract_address_salt),
        "constructor_calldata": [rpc_felt(data) for data in transaction.constructor_calldata],
    }
    return txn


def block_tag_to_block_number(block_id: BlockId) -> BlockId:
    """
    Changes block_id from tag to dict with "block_number" field
    """
    if isinstance(block_id, str):
        if block_id == "latest":
            return {"block_number": state.starknet_wrapper.blocks.get_number_of_blocks() - 1}

        if block_id == "pending":
            raise RpcError(code=-1, message="Calls with block_hash == 'pending' are not supported currently.")

        raise RpcError(code=24, message="Invalid block id")

    return block_id


def get_block_by_block_id(block_id: BlockId) -> dict:
    """
    Get block using different method depending on block_id type
    """
    block_id = block_tag_to_block_number(block_id)

    try:
        if "block_hash" in block_id:
            return state.starknet_wrapper.blocks.get_by_hash(block_hash=block_id["block_hash"])
        return state.starknet_wrapper.blocks.get_by_number(block_number=block_id["block_number"])
    except StarknetDevnetException as ex:
        raise RpcError(code=24, message="Invalid block id") from ex


def assert_block_id_is_latest(block_id: BlockId) -> None:
    """
    Assert block_id is "latest" and throw RpcError otherwise
    """
    if block_id != "latest":
        raise RpcError(code=-1, message="Calls with block_id != 'latest' are not supported currently.")


def rpc_block_status(block_status: BlockStatus) -> RpcBlockStatus:
    """
    Convert gateway BlockStatus to RpcBlockStatus
    """
    block_status_map = {
        "PENDING": "PENDING",
        "ABORTED": "REJECTED",
        "REVERTED": "REJECTED",
        "ACCEPTED_ON_L2": "ACCEPTED_ON_L2",
        "ACCEPTED_ON_L1": "ACCEPTED_ON_L1"
    }
    return block_status_map[block_status]


class RpcFeeEstimate(TypedDict):
    """
    Fee estimate TypedDict for rpc
    """
    gas_consumed: NumAsHex
    gas_price: NumAsHex
    overall_fee: NumAsHex


def rpc_fee_estimate(fee_estimate: dict) -> dict:
    """
    Convert gateway estimate_fee response to rpc_fee_estimate
    """
    result: RpcFeeEstimate = {
        "gas_consumed": hex(fee_estimate["gas_usage"]),
        "gas_price": hex(fee_estimate["gas_price"]),
        "overall_fee": hex(fee_estimate["overall_fee"]),
    }
    return result


def make_invoke_function(request_body: dict) -> InvokeFunction:
    """
    Convert RPC request to internal InvokeFunction
    """
    return InvokeFunction(
        contract_address=int(request_body["contract_address"], 16),
        entry_point_selector=int(request_body["entry_point_selector"], 16),
        calldata=[int(data, 16) for data in request_body["calldata"]],
        max_fee=int(request_body["max_fee"], 16) if "max_fee" in request_body else 0,
        version=int(request_body["version"], 16) if "version" in request_body else 0,
        signature=[int(data, 16) for data in request_body["signature"]] if "signature" in request_body else [],
    )


class EntryPoint(TypedDict):
    """
    TypedDict for rpc contract class entry point
    """
    offset: NumAsHex
    selector: Felt


class EntryPoints(TypedDict):
    """
    TypedDict for rpc contract class entry points
    """
    CONSTRUCTOR: List[EntryPoint]
    EXTERNAL: List[EntryPoint]
    L1_HANDLER: List[EntryPoint]


class RpcContractClass(TypedDict):
    """
    TypedDict for rpc contract class
    """
    program: str
    entry_points_by_type: EntryPoints


def rpc_contract_class(contract_class: ContractClass) -> RpcContractClass:
    """
    Convert gateway contract class to rpc contract class
    """
    def program() -> str:
        _program = contract_class.program.Schema().dump(contract_class.program)
        return compress_program(_program)

    def entry_points_by_type() -> EntryPoints:
        _entry_points: EntryPoints = {
            "CONSTRUCTOR": [],
            "EXTERNAL": [],
            "L1_HANDLER": [],
        }
        for typ, entry_points in contract_class.entry_points_by_type.items():
            for entry_point in entry_points:
                _entry_point: EntryPoint = {
                    "selector": rpc_felt(entry_point.selector),
                    "offset": rpc_felt(entry_point.offset)
                }
                _entry_points[typ.name].append(_entry_point)
        return _entry_points

    _contract_class: RpcContractClass = {
        "program": program(),
        "entry_points_by_type": entry_points_by_type()
    }
    return _contract_class


async def rpc_block(block: StarknetBlock, requested_scope: Optional[str] = "TXN_HASH") -> RpcBlock:
    """
    Convert gateway block to rpc block
    """
    async def transactions() -> List[RpcTransaction]:
        # pylint: disable=no-member
        return [rpc_transaction(tx) for tx in block.transactions]

    async def transaction_hashes() -> List[str]:
        return [tx["transaction_hash"] for tx in await transactions()]

    def new_root() -> str:
        # pylint: disable=no-member
        return rpc_root(block.state_root.hex())

    mapping: dict[str, Callable] = {
        "TXN_HASH": transaction_hashes,
        "FULL_TXNS": transactions,
    }
    transactions: list = await mapping[requested_scope]()

    devnet_state = state.starknet_wrapper.get_state()
    config = devnet_state.general_config

    block: RpcBlock = {
        "status": rpc_block_status(block.status.name),
        "block_hash": rpc_felt(block.block_hash),
        "parent_hash": rpc_felt(block.parent_block_hash or 0),
        "block_number": block.block_number if block.block_number is not None else 0,
        "new_root": new_root(),
        "timestamp": block.timestamp,
        "sequencer_address": hex(config.sequencer_address),
        "transactions": transactions,
    }
    return block


class RpcStorageDiff(TypedDict):
    """
    TypedDict for rpc storage diff
    """
    address: Felt
    key: Felt
    value: Felt


class RpcDeclaredContractDiff(TypedDict):
    """
    TypedDict for rpc declared contract diff
    """
    class_hash: Felt


class RpcDeployedContractDiff(TypedDict):
    """
    TypedDict for rpc deployed contract diff
    """
    address: Felt
    class_hash: Felt


class RpcNonceDiff(TypedDict):
    """
    TypedDict for rpc nonce diff
    """
    contract_address: Address
    nonce: Felt


class RpcStateDiff(TypedDict):
    """
    TypedDict for rpc state diff
    """
    storage_diffs: List[RpcStorageDiff]
    declared_contracts: List[RpcDeclaredContractDiff]
    deployed_contracts: List[RpcDeployedContractDiff]
    nonces: List[RpcNonceDiff]


class RpcStateUpdate(TypedDict):
    """
    TypedDict for rpc state update
    """
    block_hash: BlockHash
    new_root: Felt
    old_root: Felt
    state_diff: RpcStateDiff


def rpc_state_update(state_update: BlockStateUpdate) -> RpcStateUpdate:
    """
    Convert gateway state update to rpc state update
    """
    def storage_diffs() -> List[RpcStorageDiff]:
        _storage_diffs = []
        for address, diffs in state_update.state_diff.storage_diffs.items():
            for diff in diffs:
                _diff: RpcStorageDiff = {
                    "address": rpc_felt(address),
                    "key": rpc_felt(diff.key),
                    "value": rpc_felt(diff.value),
                }
                _storage_diffs.append(_diff)
        return _storage_diffs

    def declared_contracts() -> List[RpcDeclaredContractDiff]:
        _contracts = []
        for contract in state_update.state_diff.declared_contracts:
            diff: RpcDeclaredContractDiff = {
                "class_hash": rpc_felt(contract)
            }
            _contracts.append(diff)
        return _contracts

    def deployed_contracts() -> List[RpcDeployedContractDiff]:
        _contracts = []
        for contract in state_update.state_diff.deployed_contracts:
            diff: RpcDeployedContractDiff = {
                "address": rpc_felt(contract.address),
                "class_hash": rpc_felt(contract.class_hash)
            }
            _contracts.append(diff)
        return _contracts

    rpc_state: RpcStateUpdate = {
        "block_hash": rpc_felt(state_update.block_hash),
        "new_root": rpc_root(state_update.new_root.hex()),
        "old_root": rpc_root(state_update.old_root.hex()),
        "state_diff": {
            "storage_diffs": storage_diffs(),
            "declared_contracts": declared_contracts(),
            "deployed_contracts": deployed_contracts(),
            "nonces": [],
        }
    }
    return rpc_state


class RpcInvokeTransactionResult(TypedDict):
    """
    TypedDict for rpc invoke transaction result
    """
    transaction_hash: TxnHash


class RpcDeclareTransactionResult(TypedDict):
    """
    TypedDict for rpc declare transaction result
    """
    transaction_hash: TxnHash
    class_hash: Felt


class RpcDeployTransactionResult(TypedDict):
    """
    TypedDict for rpc deploy transaction result
    """
    transaction_hash: TxnHash
    contract_address: Felt


def rpc_transaction(transaction: TransactionSpecificInfo) -> RpcTransaction:
    """
    Convert gateway transaction to rpc transaction
    """
    tx_mapping = {
        TransactionType.DEPLOY: rpc_deploy_transaction,
        TransactionType.INVOKE_FUNCTION: rpc_invoke_transaction,
        TransactionType.DECLARE: rpc_declare_transaction,
    }
    return tx_mapping[transaction.tx_type](transaction)


class MessageToL1(TypedDict):
    """
    TypedDict for rpc message from l2 to l1
    """
    to_address: Felt
    payload: List[Felt]


class MessageToL2(TypedDict):
    """
    TypedDict for rpc message from l1 to l2
    """
    from_address: str
    payload: List[Felt]


class Event(TypedDict):
    """
    TypedDict for rpc event
    """
    from_address: Address
    keys: List[Felt]
    data: List[Felt]


class RpcBaseTransactionReceipt(TypedDict):
    """
    TypedDict for rpc transaction receipt
    """
    # Common
    transaction_hash: TxnHash
    actual_fee: Felt
    status: TxnStatus
    status_data: Optional[str]
    block_hash: BlockHash
    block_number: BlockNumber


class RpcInvokeReceipt(TypedDict):
    """
    TypedDict for rpc invoke transaction receipt
    """
    messages_sent: List[MessageToL1]
    l1_origin_message: Optional[MessageToL2]
    events: List[Event]
    # Common
    transaction_hash: TxnHash
    actual_fee: Felt
    status: TxnStatus
    status_data: Optional[str]
    block_hash: BlockHash
    block_number: BlockNumber


class RpcDeclareReceipt(TypedDict):
    """
    TypedDict for rpc declare transaction receipt
    """
    # Common
    transaction_hash: TxnHash
    actual_fee: Felt
    status: TxnStatus
    status_data: Optional[str]
    block_hash: BlockHash
    block_number: BlockNumber


class RpcDeployReceipt(TypedDict):
    """
    TypedDict for rpc declare transaction receipt
    """
    # Common
    transaction_hash: TxnHash
    actual_fee: Felt
    status: TxnStatus
    status_data: Optional[str]
    block_hash: BlockHash
    block_number: BlockNumber


def rpc_invoke_receipt(txr: TransactionReceipt) -> RpcInvokeReceipt:
    """
    Convert rpc invoke transaction receipt to rpc format
    """
    def l2_to_l1_messages() -> List[MessageToL1]:
        messages = []
        for message in txr.l2_to_l1_messages:
            msg: MessageToL1 = {
                "to_address": message.to_address,
                "payload": [rpc_felt(p) for p in message.payload]
            }
            messages.append(msg)
        return messages

    def l1_to_l2_message() -> Optional[MessageToL2]:
        if txr.l1_to_l2_consumed_message is None:
            return None

        msg: MessageToL2 = {
            "from_address": txr.l1_to_l2_consumed_message.from_address,
            "payload": [rpc_felt(p) for p in txr.l1_to_l2_consumed_message.payload]
        }
        return msg

    def events() -> List[Event]:
        _events = []
        for event in txr.events:
            event: Event = {
                "from_address": rpc_felt(event.from_address),
                "keys": [rpc_felt(e) for e in event.keys],
                "data": [rpc_felt(d) for d in event.data],
            }
            _events.append(event)
        return _events

    base_receipt = rpc_base_transaction_receipt(txr)
    receipt: RpcInvokeReceipt = {
        "messages_sent": l2_to_l1_messages(),
        "l1_origin_message": l1_to_l2_message(),
        "events": events(),
        "transaction_hash": base_receipt["transaction_hash"],
        "status": base_receipt["status"],
        "status_data": base_receipt["status_data"],
        "actual_fee": base_receipt["actual_fee"],
        "block_hash": base_receipt["block_hash"],
        "block_number": base_receipt["block_number"],
    }
    return receipt


def rpc_declare_receipt(txr) -> RpcDeclareReceipt:
    """
    Convert rpc declare transaction receipt to rpc format
    """
    return rpc_base_transaction_receipt(txr)


def rpc_deploy_receipt(txr) -> RpcDeployReceipt:
    """
    Convert rpc deploy transaction receipt to rpc format
    """
    return rpc_base_transaction_receipt(txr)


def rpc_base_transaction_receipt(txr: TransactionReceipt) -> RpcBaseTransactionReceipt:
    """
    Convert gateway transaction receipt to rpc transaction receipt
    """
    def status() -> str:
        if txr.status is None:
            return "UNKNOWN"

        mapping = {
            TransactionStatus.NOT_RECEIVED: "UNKNOWN",
            TransactionStatus.ACCEPTED_ON_L2: "ACCEPTED_ON_L2",
            TransactionStatus.ACCEPTED_ON_L1: "ACCEPTED_ON_L1",
            TransactionStatus.RECEIVED: "RECEIVED",
            TransactionStatus.PENDING: "PENDING",
            TransactionStatus.REJECTED: "REJECTED",
        }
        return mapping[txr.status]

    def status_data() -> Union[str, None]:
        if txr.transaction_failure_reason is not None:
            if txr.transaction_failure_reason.error_message is not None:
                return txr.transaction_failure_reason.error_message
        return None

    receipt: RpcBaseTransactionReceipt = {
        "transaction_hash": rpc_felt(txr.transaction_hash),
        "actual_fee": rpc_felt(txr.actual_fee or 0),
        "status": status(),
        "status_data": status_data(),
        "block_hash": rpc_felt(txr.block_hash) if txr.block_hash is not None else txr.block_hash,
        "block_number": txr.block_number,
    }
    return receipt


def rpc_transaction_receipt(txr: TransactionReceipt) -> dict:
    """
    Convert gateway transaction receipt to rpc format
    """
    tx_mapping = {
        TransactionType.DEPLOY: rpc_deploy_receipt,
        TransactionType.INVOKE_FUNCTION: rpc_invoke_receipt,
        TransactionType.DECLARE: rpc_declare_receipt,
    }
    transaction = state.starknet_wrapper.transactions.get_transaction(hex(txr.transaction_hash)).transaction
    tx_type = transaction.tx_type
    return tx_mapping[tx_type](txr)


def rpc_felt(value: int) -> str:
    """
    Convert integer to 0x0 prefixed felt
    """
    if value == 0:
        return "0x00"
    return "0x0" + hex(value).lstrip("0x")


def rpc_root(root: str) -> str:
    """
    Convert 0 prefixed root to 0x prefixed root
    """
    root = root[1:]
    return "0x0" + root


def rpc_response(message_id: int, content: dict) -> dict:
    """
    Wrap response content in rpc format
    """
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "result": content
    }


class RpcError(Exception):
    """
    Error message returned by rpc
    """

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def rpc_error(message_id: int, code: int, message: str) -> dict:
    """
    Wrap error in rpc format
    """
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {
            "code": code,
            "message": message
        }
    }
