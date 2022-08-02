"""
RPC routes
API Specification v0.1.0
"""
# pylint: disable=too-many-lines

from __future__ import annotations
import dataclasses
import json

from typing import Callable, Union, List, Tuple, Optional, Any
from typing_extensions import TypedDict, Literal
from flask import Blueprint, request
from marshmallow.exceptions import MarshmallowError

from starkware.starknet.services.api.contract_class import ContractClass
from starkware.starkware_utils.error_handling import StarkException
from starkware.starknet.definitions import constants
from starkware.starknet.services.api.gateway.transaction import (
    DECLARE_SENDER_ADDRESS,
    Declare,
    Deploy,
    InvokeFunction,
)
from starkware.starknet.services.api.gateway.transaction_utils import compress_program, decompress_program
from starkware.starknet.services.api.feeder_gateway.response_objects import (
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

from starknet_devnet.state import state
from ..util import StarknetDevnetException

rpc = Blueprint("rpc", __name__, url_prefix="/rpc")

PROTOCOL_VERSION = "0.31.0" #TODO

Felt = str

BlockHash = Felt
BlockNumber = int
BlockTag = Literal["latest", "pending"]

class BlockHashDict(TypedDict):
    block_hash: Felt

class BlockNumberDict(TypedDict):
    block_number: int

BlockId = Union[BlockHashDict, BlockNumberDict, BlockTag]

TxnStatus = BlockStatus = Literal["PENDING", "ACCEPTED_ON_L2", "ACCEPTED_ON_L1", "REJECTED"]

TxnHash = Felt
Address = Felt
NumAsHex = str
TxnType = Literal["DECLARE", "DEPLOY", "INVOKE"]


class RpcBlock(TypedDict):
    """
    TypeDict for rpc block
    """
    status: BlockStatus
    block_hash: BlockHash
    parent_hash: BlockHash
    block_number: BlockNumber
    new_root: Felt
    timestamp: int
    sequencer_address: Felt
    transactions: Union[List[str], List[dict]]


class RpcInvokeTransaction(TypedDict):
    """
    TypedDict for rpc invoke transaction
    """
    contract_address: Address
    entry_point_selector: Optional[Felt] #TODO why optional
    calldata: Optional[List[Felt]] #TODO why optional
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


def rpc_invoke_transaction(transaction: InvokeSpecificInfo) -> RpcInvokeTransaction:
    """
    Convert gateway invoke transaction to rpc format
    """
    transaction: RpcInvokeTransaction = {
        "contract_address": rpc_felt(transaction.contract_address),
        "entry_point_selector": rpc_felt(transaction.entry_point_selector),
        "calldata": [rpc_felt(data) for data in transaction.calldata],
        "transaction_hash": rpc_felt(transaction.transaction_hash),
        "max_fee": rpc_felt(transaction.max_fee),
        "version": hex(0x0),
        "signature": [rpc_felt(value) for value in transaction.signature],
        "nonce": rpc_felt(0), #TODO ?
        "type": json.dumps(transaction.tx_type, default=lambda x: x.name),
    }
    return transaction


def rpc_declare_transaction(transaction: DeclareSpecificInfo) -> RpcDeclareTransaction:
    """
    Convert gateway declare transaction to rpc format
    """
    transaction: RpcDeclareTransaction = {
        "class_hash": rpc_felt(transaction.class_hash),
        "sender_address": rpc_felt(transaction.sender_address),
        "transaction_hash": rpc_felt(transaction.transaction_hash),
        "max_fee": rpc_felt(transaction.max_fee),
        "version": hex(transaction.version),
        "signature": [rpc_felt(value) for value in transaction.signature],
        "nonce": rpc_felt(transaction.nonce),
        "type": json.dumps(transaction.tx_type, default=lambda x: x.name),
    }
    return transaction


def rpc_deploy_transaction(transaction: DeploySpecificInfo) -> RpcDeployTransaction:
    """
    Convert gateway deploy transaction to rpc format
    """
    transaction: RpcDeployTransaction = {
        "transaction_hash": rpc_felt(transaction.transaction_hash),
        "class_hash": rpc_felt(transaction.contract_address),
        "version": hex(0x0),
        "type": json.dumps(transaction.tx_type, default=lambda x: x.name),
        "contract_address": rpc_felt(transaction.contract_address),
        "contract_address_salt": rpc_felt(transaction.contract_address_salt),
        "constructor_calldata": [rpc_felt(data) for data in transaction.constructor_calldata],
    }
    return transaction


def block_tag_to_block_number(block_id: BlockId) -> BlockId:
    """
    Changes block_id from tag to dict with "block_number" field
    """
    if isinstance(block_id, str):
        if block_id == "pending":
            raise RpcError(code=-1, message="Calls with block_hash == 'pending' are not supported currently.")
        return {"block_number": state.starknet_wrapper.blocks.get_number_of_blocks() - 1}

    return block_id


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


async def get_block_with_tx_hashes(block_id: BlockId) -> dict:
    """
    Get block information with transaction hashes given the block id
    """
    block_id = block_tag_to_block_number(block_id)

    try:
        if "block_hash" in block_id:
            result = state.starknet_wrapper.blocks.get_by_hash(block_hash=block_id["block_hash"])
        else:
            result = state.starknet_wrapper.blocks.get_by_number(block_number=block_id["block_number"])
    except StarknetDevnetException as ex:
        raise RpcError(code=24, message="Invalid block id") from ex

    return await rpc_block(block=result)


async def get_block_with_txs(block_id: BlockId) -> dict:
    """
    Get block information with full transactions given the block id
    """
    block_id = block_tag_to_block_number(block_id)

    try:
        if "block_hash" in block_id:
            result = state.starknet_wrapper.blocks.get_by_hash(block_hash=block_id["block_hash"])
        else:
            result = state.starknet_wrapper.blocks.get_by_number(block_number=block_id["block_number"])
    except StarknetDevnetException as ex:
        raise RpcError(code=24, message="Invalid block id") from ex

    return await rpc_block(block=result, requested_scope="FULL_TXNS")


async def get_state_update(block_id: BlockId) -> dict:
    """
    Get the information about the result of executing the requested block
    """
    block_id = block_tag_to_block_number(block_id)

    try:
        if "block_hash" in block_id:
            result = state.starknet_wrapper.blocks.get_state_update(block_hash=block_id["block_hash"])
        else:
            result = state.starknet_wrapper.blocks.get_state_update(block_number=block_id["block_number"])
    except StarknetDevnetException as ex:
        raise RpcError(code=24, message="Invalid block id") from ex

    return rpc_state_update(result)


async def get_storage_at(contract_address: Address, key: str, block_id: BlockId) -> Felt:
    """
    Get the value of the storage at the given address and key
    """
    if block_id != "latest":
        # By RPC here we should return `24 invalid block hash` but in this case I believe it's more
        # descriptive to the user to use a custom error
        raise RpcError(code=-1, message="Calls with block_hash != 'latest' are not supported currently.")

    if not state.starknet_wrapper.contracts.is_deployed(int(contract_address, 16)):
        raise RpcError(code=20, message="Contract not found")

    return await state.starknet_wrapper.get_storage_at(
        contract_address=int(contract_address, 16),
        key=int(key, 16)
    )


async def get_transaction_by_hash(transaction_hash: TxnHash) -> dict:
    """
    Get the details and status of a submitted transaction
    """
    try:
        result = state.starknet_wrapper.transactions.get_transaction(transaction_hash)
    except StarknetDevnetException as ex:
        raise RpcError(code=25, message="Invalid transaction hash") from ex

    if result.status == TransactionStatus.NOT_RECEIVED:
        raise RpcError(code=25, message="Invalid transaction hash")

    return rpc_transaction(result.transaction)


async def get_transaction_by_block_id_and_index(block_id: BlockId, index: int) -> dict:
    """
    Get the details of a transaction by a given block id and index
    """
    block_id = block_tag_to_block_number(block_id)

    try:
        if "block_hash" in block_id:
            block = state.starknet_wrapper.blocks.get_by_hash(block_hash=block_id["block_hash"])
        else:
            block = state.starknet_wrapper.blocks.get_by_number(block_number=block_id["block_number"])
    except StarknetDevnetException as ex:
        raise RpcError(code=24, message="Invalid block id") from ex

    try:
        transaction_hash: int = block.transactions[index].transaction_hash
    except IndexError as ex:
        raise RpcError(code=27, message="Invalid transaction index in a block") from ex

    return await get_transaction_by_hash(transaction_hash=rpc_felt(transaction_hash))


async def get_transaction_receipt(transaction_hash: TxnHash) -> dict:
    """
    Get the transaction receipt by the transaction hash
    """
    try:
        result = state.starknet_wrapper.transactions.get_transaction_receipt(tx_hash=transaction_hash)
    except StarknetDevnetException as ex:
        raise RpcError(code=25, message="Invalid transaction hash") from ex

    if result.status == TransactionStatus.NOT_RECEIVED:
        raise RpcError(code=25, message="Invalid transaction hash")

    return rpc_transaction_receipt(result)


# async def get_code(contract_address: str) -> dict:
#     """
#     Get the code of a specific contract
#     """
#     try:
#         result = state.starknet_wrapper.contracts.get_code(address=int(contract_address, 16))
#     except StarknetDevnetException as ex:
#         raise RpcError(code=20, message="Contract not found") from ex
#
#     if len(result["bytecode"]) == 0:
#         raise RpcError(code=20, message="Contract not found")
#
#     return {
#         "bytecode": result["bytecode"],
#         "abi": json.dumps(result["abi"])
#     }


async def get_class(class_hash: Felt) -> dict:
    """
    Get the contract class definition associated with the given hash
    """
    try:
        result = state.starknet_wrapper.contracts.get_class_by_hash(class_hash=int(class_hash, 16))
    except StarknetDevnetException as ex:
        raise RpcError(code=28, message="The supplied contract class hash is invalid or unknown") from ex

    return rpc_contract_class(result)


async def get_class_hash_at(block_id: BlockId, contract_address: Address) -> Felt:
    """
    Get the contract class hash in the given block for the contract deployed at the given address
    """
    try:
        result = state.starknet_wrapper.contracts.get_class_hash_at(address=int(contract_address, 16))
    except StarknetDevnetException as ex:
        raise RpcError(code=28, message="The supplied contract class hash is invalid or unknown") from ex

    return rpc_felt(result)


async def get_class_at(block_id: BlockId, contract_address: Address) -> dict:
    """
    Get the contract class definition in the given block at the given address
    """
    try:
        class_hash = state.starknet_wrapper.contracts.get_class_hash_at(address=int(contract_address, 16))
        result = state.starknet_wrapper.contracts.get_class_by_hash(class_hash=class_hash)
    except StarknetDevnetException as ex:
        raise RpcError(code=20, message="Contract not found") from ex

    return rpc_contract_class(result)


async def get_block_transaction_count(block_id: BlockId) -> int:
    """
    Get the number of transactions in a block given a block id
    """
    block_id = block_tag_to_block_number(block_id)

    try:
        if "block_hash" in block_id:
            block = state.starknet_wrapper.blocks.get_by_hash(block_hash=block_id["block_hash"])
        else:
            block = state.starknet_wrapper.blocks.get_by_number(block_number=block_id["block_number"])
    except StarknetDevnetException as ex:
        raise RpcError(code=24, message="Invalid block id") from ex

    return len(block.transactions)


async def call(request: RpcInvokeTransaction, block_id: BlockId) -> List[Felt]:
    """
    Call a starknet function without creating a StarkNet transaction
    """
    request_body = {
        "contract_address": request["contract_address"],
        "entry_point_selector": request["entry_point_selector"],
        "calldata": request["calldata"]
    }

    # For now, we only support 'latest' block, support for specific blocks
    # in devnet is more complicated if possible at all
    if block_id != "latest":
        # By RPC here we should return `24 invalid block id` but in this case I believe it's more
        # descriptive to the user to use a custom error
        raise RpcError(code=-1, message="Calls with block_id != 'latest' are not supported currently.")

    if not state.starknet_wrapper.contracts.is_deployed(int(request["contract_address"], 16)):
        raise RpcError(code=20, message="Contract not found")

    try:
        return await state.starknet_wrapper.call(transaction=make_invoke_function(request_body))
    except StarknetDevnetException as ex:
        raise RpcError(code=-1, message=ex.message) from ex
    except StarkException as ex:
        if f'Entry point {request["entry_point_selector"]} not found' in ex.message:
            raise RpcError(code=21, message="Invalid message selector") from ex
        if "While handling calldata" in ex.message:
            raise RpcError(code=22, message="Invalid call data") from ex
        raise RpcError(code=-1, message=ex.message) from ex


async def estimate_fee(request: RpcInvokeTransaction, block_id: BlockId) -> dict:
    """
    Estimate the fee for a given StarkNet transaction
    """
    raise NotImplementedError()


async def block_number() -> int:
    """
    Get the most recent accepted block number
    """
    number_of_blocks = state.starknet_wrapper.blocks.get_number_of_blocks()
    if number_of_blocks == 0:
        raise RpcError(code=32, message="There are no blocks")

    return number_of_blocks - 1


async def block_hash_and_number() -> dict:
    """
    Get the most recent accepted block hash and number
    """
    last_block_number = state.starknet_wrapper.blocks.get_number_of_blocks() - 1

    try:
        last_block = state.starknet_wrapper.blocks.get_by_number(last_block_number)
    except StarknetDevnetException as ex:
        raise RpcError(code=32, message="There are no blocks") from ex

    result = {
        "block_hash": rpc_felt(last_block.block_hash),
        "block_number": last_block.block_number,
    }
    return result


async def chain_id() -> str:
    """
    Return the currently configured StarkNet chain id
    """
    devnet_state = await state.starknet_wrapper.get_state()
    config = devnet_state.general_config
    chain: int = config.chain_id.value
    return hex(chain)


async def pending_transactions() -> List[Union[RpcInvokeTransaction, RpcDeclareTransaction, RpcDeployTransaction]]:
    """
    Returns the transactions in the transaction pool, recognized by this sequencer
    """
    raise NotImplementedError()


async def protocol_version() -> str:
    """
    Returns the current starknet protocol version identifier, as supported by this sequencer
    """
    protocol_hex = PROTOCOL_VERSION.encode("utf-8").hex()
    return "0x" + protocol_hex


async def syncing() -> dict:
    """
    Returns an object about the sync status, or false if the node is not synching
    """
    raise NotImplementedError()


async def get_events() -> dict:
    """
    Returns all events matching the given filter
    """
    raise NotImplementedError()


async def get_nonce(contract_address: Address) -> Felt:
    """
    Get the latest nonce associated with the given address
    """
    raise NotImplementedError()


async def add_invoke_transaction(function_invocation: dict, signature: List[str], max_fee: str, version: str) -> dict:
    """
    Submit a new transaction to be added to the chain
    """
    invoke_function = InvokeFunction(
        contract_address=int(function_invocation["contract_address"], 16),
        entry_point_selector=int(function_invocation["entry_point_selector"], 16),
        calldata=[int(data, 16) for data in function_invocation["calldata"]],
        max_fee=int(max_fee, 16),
        version=int(version, 16),
        signature=[int(data, 16) for data in signature],
    )

    _, transaction_hash, _ = await state.starknet_wrapper.invoke(invoke_function=invoke_function)
    return RpcInvokeTransactionResult(
        transaction_hash=rpc_felt(transaction_hash),
    )


async def add_declare_transaction(contract_class: RpcContractClass, version: str) -> dict:
    """
    Submit a new class declaration transaction
    """
    try:
        decompressed_program = decompress_program({"contract_class": contract_class}, False)["contract_class"]
        contract_definition = ContractClass.load(decompressed_program)

        # Replace None with [] in abi key to avoid Missing Abi exception
        contract_definition = dataclasses.replace(contract_definition, abi=[])
    except (StarkException, TypeError, MarshmallowError) as ex:
        raise RpcError(code=50, message="Invalid contract class") from ex

    declare_transaction = Declare(
        contract_class=contract_definition,
        version=version,
        sender_address=DECLARE_SENDER_ADDRESS,
        max_fee=0,
        signature=[],
        nonce=0,
    )

    class_hash, transaction_hash = await state.starknet_wrapper.declare(declare_transaction=declare_transaction)
    return RpcDeclareTransactionResult(
        transaction_hash=rpc_felt(transaction_hash),
        class_hash=rpc_felt(class_hash),
    )


async def add_deploy_transaction(contract_address_salt: str, constructor_calldata: List[str], contract_definition: RpcContractClass) -> dict:
    """
    Submit a new deploy contract transaction
    """
    try:
        decompressed_program = decompress_program({"contract_definition": contract_definition}, False)["contract_definition"]
        contract_class = ContractClass.load(decompressed_program)
        contract_class = dataclasses.replace(contract_class, abi=[])
    except (StarkException, TypeError, MarshmallowError) as ex:
        raise RpcError(code=50, message="Invalid contract class") from ex

    deploy_transaction = Deploy(
        contract_address_salt=contract_address_salt,
        constructor_calldata=constructor_calldata,
        contract_definition=contract_class,
        version=constants.TRANSACTION_VERSION,
    )

    contract_address, transaction_hash = await state.starknet_wrapper.deploy(deploy_transaction=deploy_transaction)
    return RpcDeployTransactionResult(
        transaction_hash=rpc_felt(transaction_hash),
        contract_address=rpc_felt(contract_address),
    )


def make_invoke_function(request_body: dict) -> InvokeFunction:
    """
    Convert RPC request to internal InvokeFunction
    """
    return InvokeFunction(
        contract_address=int(request_body["contract_address"], 16),
        entry_point_selector=int(request_body["entry_point_selector"], 16),
        calldata=[int(data, 16) for data in request_body["calldata"]],
        max_fee=0,
        version=0,
        signature=[],
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
    async def transactions() -> List[Union[RpcInvokeTransaction, RpcDeclareTransaction]]:
        # pylint: disable=no-member
        return [rpc_transaction(tx) for tx in block.transactions]

    async def transaction_hashes() -> List[str]:
        return [tx["transaction_hash"] for tx in await transactions()]

    async def full_transactions() -> list[dict[str, Any]]:
        transactions_and_receipts = []
        _transactions = await transactions()
        for transaction in _transactions:
            receipt = await get_transaction_receipt(transaction["txn_hash"])
            combined = {**receipt, **transaction}
            transactions_and_receipts.append(combined)
        return transactions_and_receipts

    def new_root() -> str:
        # pylint: disable=no-member
        return rpc_root(block.state_root.hex())

    mapping: dict[str, Callable] = {
        "TXN_HASH": transaction_hashes,
        "FULL_TXNS": transactions,
        "FULL_TXN_AND_RECEIPTS": full_transactions,
    }
    transactions: list = await mapping[requested_scope]()

    devnet_state = await state.starknet_wrapper.get_state()
    config = devnet_state.general_config

    block: RpcBlock = {
        "status": block.status.name,
        "block_hash": rpc_felt(block.block_hash),
        "parent_hash": rpc_felt(block.parent_block_hash) or "0x0",
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
                "class_hash": rpc_felt(contract.class_hash)
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


# def rpc_state_diff_contract(contract: dict) -> dict:
#     """
#     Convert gateway contract state diff to rpc contract state diff
#     """
#     return {
#         "address": contract["address"],
#         "contract_hash": f"0x{contract['contract_hash']}",
#     }


# def rpc_state_diff_storage(contract: dict) -> dict:
#     """
#     Convert gateway storage state diff to rpc storage state diff
#     """
#     return {
#         "address": contract["address"],
#         "key": contract["key"],
#         "value": contract["value"],
#     }


class RpcInvokeTransactionResult(TypedDict):
    """
    TypedDict for rpc invoke transaction result
    """
    transaction_hash: str


class RpcDeclareTransactionResult(TypedDict):
    """
    TypedDict for rpc declare transaction result
    """
    transaction_hash: str
    class_hash: str


class RpcDeployTransactionResult(TypedDict):
    """
    TypedDict for rpc deploy transaction result
    """
    transaction_hash: str
    contract_address: str


def rpc_transaction(transaction: TransactionSpecificInfo) -> Union[RpcInvokeTransaction, RpcDeclareTransaction, RpcDeployTransaction]:
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
    status: str
    statusData: Optional[str]


class RpcPendingReceipt(TypedDict):
    """
    TypedDict for rpc pending transaction receipt
    """
    messages_sent: List[MessageToL1]
    l1_origin_message: Optional[MessageToL2]
    events: List[Event]
    # Common
    transaction_hash: TxnHash
    actual_fee: Felt

    status: TxnStatus
    statusData: Optional[str]
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
    statusData: Optional[str]
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
    statusData: Optional[str]
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
    statusData: Optional[str]
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
        "txn_hash": base_receipt["txn_hash"],
        "status": base_receipt["status"],
        "statusData": base_receipt["statusData"],
        "actual_fee": base_receipt["actual_fee"],
    }
    return receipt


def rpc_declare_receipt(txr) -> RpcDeclareReceipt:
    """
    Convert rpc declare transaction receipt to rpc format
    """
    base_receipt = rpc_base_transaction_receipt(txr)
    receipt: RpcDeclareReceipt = {
        "txn_hash": base_receipt["txn_hash"],
        "status": base_receipt["status"],
        "statusData": base_receipt["statusData"],
        "actual_fee": base_receipt["actual_fee"],
    }
    return receipt


def rpc_deploy_receipt(txr) -> RpcBaseTransactionReceipt:
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
        "txn_hash": rpc_felt(txr.transaction_hash),
        "status": status(),
        "statusData": status_data(),
        "actual_fee": rpc_felt(txr.actual_fee or 0),
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


def rpc_response(message_id: int, content: dict) -> dict:
    """
    Wrap response content in rpc format
    """
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "result": content
    }


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


def rpc_felt(value: int) -> str:
    """
    Convert integer to 0x0 prefixed felt
    """
    return "0x0" + hex(value).lstrip("0x")


def rpc_root(root: str) -> str:
    """
    Convert 0 prefixed root to 0x prefixed root
    """
    root = root[1:]
    return "0x0" + root


def parse_body(body: dict) -> Tuple[Callable, Union[List, dict], int]:
    """
    Parse rpc call body to function name and params
    """
    methods = {
        "getBlockWithTxHashes": get_block_with_tx_hashes,
        "getBlockWithTxs": get_block_with_txs,
        "getStateUpdate": get_state_update,
        "getStorageAt": get_storage_at,
        "getTransactionByHash": get_transaction_by_hash,
        "starknet_getTransactionByBlockIdAndIndex": get_transaction_by_block_id_and_index,
        "getTransactionReceipt": get_transaction_receipt,
        "getClass": get_class,
        "getClassHashAt": get_class_hash_at,
        "getClassAt": get_class_at,
        "getBlockTransactionCount": get_block_transaction_count,
        "call": call,
        "estimateFee": estimate_fee,
        "blockNumber": block_number,
        "blockHashAndNumber": block_hash_and_number,
        "chainId": chain_id,
        "pendingTransactions": pending_transactions,
        "protocolVersion": protocol_version,
        "syncing": syncing,
        "getEvents": get_events,
        "getNonce": get_nonce,
        "addInvokeTransaction": add_invoke_transaction,
        "addDeclareTransaction": add_declare_transaction,
        "addDeployTransaction": add_deploy_transaction,
    }
    method_name = body["method"].replace("starknet_", "")
    args: Union[List, dict] = body["params"]
    message_id = body["id"]

    if method_name not in methods:
        raise RpcError(code=-1, message="Method not found")

    return methods[method_name], args, message_id


class RpcError(Exception):
    """
    Error message returned by rpc
    """

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message
