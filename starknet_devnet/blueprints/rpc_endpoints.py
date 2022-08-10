"""
RPC endpoints
API Specification v0.1.0
https://github.com/starkware-libs/starknet-specs/releases/tag/v0.1.0
"""

from __future__ import annotations

import dataclasses
from typing import List, Optional

from marshmallow.exceptions import MarshmallowError
from starkware.starknet.definitions import constants
from starkware.starknet.services.api.contract_class import ContractClass
from starkware.starknet.services.api.feeder_gateway.response_objects import TransactionStatus
from starkware.starknet.services.api.gateway.transaction import (
    DECLARE_SENDER_ADDRESS,
    Declare,
    Deploy,
    InvokeFunction,
)
from starkware.starknet.services.api.gateway.transaction_utils import decompress_program
from starkware.starkware_utils.error_handling import StarkException

from starknet_devnet.state import state
from .rpc_utils import get_block_by_block_id, rpc_block, BlockId, block_tag_to_block_number, rpc_state_update, \
    assert_block_id_is_latest, rpc_transaction, TxnHash, Address, rpc_felt, rpc_transaction_receipt, Felt, \
    rpc_contract_class, FunctionCall, make_invoke_function, RpcInvokeTransaction, rpc_fee_estimate, RpcTransaction, \
    NumAsHex, RpcInvokeTransactionResult, RpcContractClass, RpcDeclareTransactionResult, RpcDeployTransactionResult, \
    RpcError
from ..util import StarknetDevnetException


async def get_block_with_tx_hashes(block_id: BlockId) -> dict:
    """
    Get block information with transaction hashes given the block id
    """
    block = get_block_by_block_id(block_id)
    return await rpc_block(block=block)


async def get_block_with_txs(block_id: BlockId) -> dict:
    """
    Get block information with full transactions given the block id
    """
    block = get_block_by_block_id(block_id)
    return await rpc_block(block=block, tx_type="FULL_TXNS")


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
    assert_block_id_is_latest(block_id)

    if not state.starknet_wrapper.contracts.is_deployed(int(contract_address, 16)):
        raise RpcError(code=20, message="Contract not found")

    storage = await state.starknet_wrapper.get_storage_at(
        contract_address=int(contract_address, 16),
        key=int(key, 16)
    )
    return rpc_felt(int(storage, 16))


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
    block = get_block_by_block_id(block_id)

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
    assert_block_id_is_latest(block_id)

    try:
        result = state.starknet_wrapper.contracts.get_class_hash_at(address=int(contract_address, 16))
    except StarknetDevnetException as ex:
        raise RpcError(code=28, message="The supplied contract class hash is invalid or unknown") from ex

    return rpc_felt(result)


async def get_class_at(block_id: BlockId, contract_address: Address) -> dict:
    """
    Get the contract class definition in the given block at the given address
    """
    assert_block_id_is_latest(block_id)

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
    block = get_block_by_block_id(block_id)
    return len(block.transactions)


async def call(request: FunctionCall, block_id: BlockId) -> List[Felt]:
    """
    Call a starknet function without creating a StarkNet transaction
    """
    assert_block_id_is_latest(block_id)

    if not state.starknet_wrapper.contracts.is_deployed(int(request["contract_address"], 16)):
        raise RpcError(code=20, message="Contract not found")

    try:
        result = await state.starknet_wrapper.call(transaction=make_invoke_function(request))
        result["result"] = [rpc_felt(int(res, 16)) for res in result["result"]]
        return result
    except StarknetDevnetException as ex:
        raise RpcError(code=-1, message=ex.message) from ex
    except StarkException as ex:
        if f"Entry point {request['entry_point_selector']} not found" in ex.message:
            raise RpcError(code=21, message="Invalid message selector") from ex
        if "While handling calldata" in ex.message:
            raise RpcError(code=22, message="Invalid call data") from ex
        raise RpcError(code=-1, message=ex.message) from ex


async def estimate_fee(request: RpcInvokeTransaction, block_id: BlockId) -> dict:
    """
    Estimate the fee for a given StarkNet transaction
    """
    assert_block_id_is_latest(block_id)

    if not state.starknet_wrapper.contracts.is_deployed(int(request["contract_address"], 16)):
        raise RpcError(code=20, message="Contract not found")

    invoke_function = make_invoke_function(request)

    try:
        fee_response = await state.starknet_wrapper.calculate_actual_fee(invoke_function)
    except StarkException as ex:
        if f"Entry point {request['entry_point_selector']} not found" in ex.message:
            raise RpcError(code=21, message="Invalid message selector") from ex
        if "While handling calldata" in ex.message:
            raise RpcError(code=22, message="Invalid call data") from ex
        raise RpcError(code=-1, message=ex.message) from ex
    return rpc_fee_estimate(fee_response)


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
    devnet_state = state.starknet_wrapper.get_state()
    config = devnet_state.general_config
    chain: int = config.chain_id.value
    return hex(chain)


async def pending_transactions() -> List[RpcTransaction]:
    """
    Returns the transactions in the transaction pool, recognized by this sequencer
    """
    raise NotImplementedError()


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


# pylint: disable=unused-argument
async def get_nonce(contract_address: Address) -> Felt:
    """
    Get the latest nonce associated with the given address
    """
    raise NotImplementedError()


async def add_invoke_transaction(function_invocation: FunctionCall, max_fee: NumAsHex, version: NumAsHex,
                                 signature: Optional[List[Felt]] = None) -> dict:
    """
    Submit a new transaction to be added to the chain
    """
    invoke_function = InvokeFunction(
        contract_address=int(function_invocation["contract_address"], 16),
        entry_point_selector=int(function_invocation["entry_point_selector"], 16),
        calldata=[int(data, 16) for data in function_invocation["calldata"]],
        max_fee=int(max_fee, 16),
        version=int(version, 16),
        signature=[int(data, 16) for data in signature] if signature is not None else [],
    )

    _, transaction_hash, _ = await state.starknet_wrapper.invoke(invoke_function=invoke_function)
    return RpcInvokeTransactionResult(
        transaction_hash=rpc_felt(transaction_hash),
    )


async def add_declare_transaction(contract_class: RpcContractClass, version: NumAsHex) -> dict:
    """
    Submit a new class declaration transaction
    """
    try:
        decompressed_program = decompress_program({"contract_class": contract_class}, False)
        decompressed_program = decompressed_program["contract_class"]

        contract_definition = ContractClass.load(decompressed_program)
        # Replace None with [] in abi key to avoid Missing Abi exception
        contract_definition = dataclasses.replace(contract_definition, abi=[])
    except (StarkException, TypeError, MarshmallowError) as ex:
        raise RpcError(code=50, message="Invalid contract class") from ex

    declare_transaction = Declare(
        contract_class=contract_definition,
        version=int(version, 16),
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


async def add_deploy_transaction(contract_address_salt: Felt, constructor_calldata: List[Felt],
                                 contract_definition: RpcContractClass) -> dict:
    """
    Submit a new deploy contract transaction
    """
    try:
        decompressed_program = decompress_program({"contract_definition": contract_definition}, False)
        decompressed_program = decompressed_program["contract_definition"]

        contract_class = ContractClass.load(decompressed_program)
        contract_class = dataclasses.replace(contract_class, abi=[])
    except (StarkException, TypeError, MarshmallowError) as ex:
        raise RpcError(code=50, message="Invalid contract class") from ex

    deploy_transaction = Deploy(
        contract_address_salt=int(contract_address_salt, 16),
        constructor_calldata=[int(data, 16) for data in constructor_calldata],
        contract_definition=contract_class,
        version=constants.TRANSACTION_VERSION,
    )

    contract_address, transaction_hash = await state.starknet_wrapper.deploy(deploy_transaction=deploy_transaction)
    return RpcDeployTransactionResult(
        transaction_hash=rpc_felt(transaction_hash),
        contract_address=rpc_felt(contract_address),
    )
