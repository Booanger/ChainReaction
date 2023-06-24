import hashlib
import time
import socket
import threading
import json
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


# Constants
HOST = "localhost"
PORT = 5000
# PEERS = [("localhost", 5001), ("localhost", 5002)]
BOOTSTRAP_NODES = [("localhost", 5001), ("localhost", 5002)]

# Logger configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def public_key_to_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def bytes_to_public_key(public_key_bytes):
    return serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend(),
    )


class Block:
    def __init__(self, index, timestamp, transactions, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        hash_data = (
            str(self.index)
            + str(self.timestamp)
            + str(self.transactions)
            + str(self.previous_hash)
            + str(self.nonce)
        )
        return hashlib.sha256(hash_data.encode()).hexdigest()

    def mine_block(self, difficulty):
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        logger.info("Block mined: %s", self.hash)

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, data):
        block = cls(
            data["index"],
            data["timestamp"],
            [Transaction.from_dict(tx) for tx in data["transactions"]],
            data["previous_hash"],
        )
        block.nonce = data["nonce"]
        block.hash = data["hash"]
        return block


class Transaction:
    def __init__(self, sender, recipient, amount, signature=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature

    def sign_transaction(self, private_key):
        data = self.sender + self.recipient + str(self.amount).encode()
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        self.signature = signature

    def verify_transaction(self, public_key):
        try:
            public_key.verify(
                self.signature,
                self.sender + self.recipient + str(self.amount).encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            data["sender"],
            data["recipient"],
            data["amount"],
            data["signature"],
        )


class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 5
        self.pending_transactions = []
        self.voters = set()
        self.candidates = {}
        self.lock = threading.Lock()

    def create_genesis_block(self):
        return Block(0, time.time(), [], "0")

    @property
    def latest_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self):
        if len(self.pending_transactions) > 0:
            block = Block(
                len(self.chain),
                time.time(),
                self.pending_transactions,
                self.latest_block.hash,
            )
            block.mine_block(self.difficulty)
            self.chain.append(block)
            self.pending_transactions = []

    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.sender == address:
                    balance -= transaction.amount
                if transaction.recipient == address:
                    balance += transaction.amount
        return balance

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def register_voter(self, public_key):
        self.voters.add(public_key_to_bytes(public_key))

    def register_candidate(self, public_key, name):
        self.candidates[public_key_to_bytes(public_key)] = name

    def add_block(self, block):
        with self.lock:
            if len(self.chain) > 0:
                previous_block = self.chain[-1]
                if block.previous_hash != previous_block.hash:
                    raise ValueError("Invalid block. Previous hash does not match.")
            self.chain.append(block)
            logger.info("Block added to the blockchain.")

    def to_dict(self):
        return {
            "chain": [block.to_dict() for block in self.chain],
            "difficulty": self.difficulty,
            "pending_transactions": [tx.to_dict() for tx in self.pending_transactions],
            "voters": [
                bytes_to_public_key(v)
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .hex()
                for v in self.voters
            ],
            "candidates": {
                bytes_to_public_key(k)
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .hex(): v
                for k, v in self.candidates.items()
            },
        }

    @classmethod
    def from_dict(cls, data):
        blockchain = cls()
        blockchain.chain = [Block.from_dict(block_data) for block_data in data["chain"]]
        blockchain.difficulty = data["difficulty"]
        blockchain.pending_transactions = [
            Transaction.from_dict(tx) for tx in data["pending_transactions"]
        ]
        blockchain.voters = {bytes.fromhex(v) for v in data["voters"]}
        blockchain.candidates = {
            bytes.fromhex(k): v for k, v in data["candidates"].items()
        }
        return blockchain


class PeerManager:
    def __init__(self, node, known_peers=None):
        if known_peers is None:
            known_peers = []
        self.node = node
        self.known_peers = set(known_peers)
        self.lock = threading.Lock()

    def add_peer(self, peer):
        with self.lock:
            self.known_peers.add(peer)

    def remove_peer(self, peer):
        with self.lock:
            self.known_peers.remove(peer)

    def get_peers(self):
        with self.lock:
            return list(self.known_peers)

    def discover_peers(self):
        self.bootstrap_discovery()
        while True:
            time.sleep(30)  # Adjust the peer discovery interval as needed
            self.exchange_peers()

    def bootstrap_discovery(self):
        for bootstrap_node in self.known_peers:
            self.connect_to_peer(bootstrap_node)

    def exchange_peers(self):
        peers = self.get_peers()
        for peer in peers:
            self.connect_to_peer(peer)

    def connect_to_peer(self, peer):
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(f"Type: {type(peer)}, Value: {peer}")
            peer_socket.connect(peer)

            # Ask for the peer's known peers
            peer_socket.send(json.dumps({"get_peers": True}).encode())
            response = peer_socket.recv(4096).decode()
            response = json.loads(response)
            if "peers" in response:
                for new_peer in response["peers"]:
                    self.add_peer(new_peer)

            self.node.handle_peer(peer_socket)
            peer_socket.close()
        except ConnectionRefusedError:
            return


class Node:
    def __init__(self, bootstrap_nodes=None):
        self.blockchain = Blockchain()
        self.peer_manager = PeerManager(self, bootstrap_nodes)
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((HOST, PORT))

    def start(self):
        self.server.listen(10)
        threading.Thread(target=self.peer_manager.discover_peers).start()
        threading.Thread(target=self.start_mining).start()
        while True:
            client_socket, address = self.server.accept()
            threading.Thread(
                target=self.handle_client,
                args=(client_socket,),
            ).start()

    def handle_client(self, client_socket):
        try:
            request = client_socket.recv(4096).decode()
            request = json.loads(request)

            if "transaction" in request:
                self.handle_transaction_request(request)
            elif "get_balance" in request:
                self.handle_balance_request(request, client_socket)
            elif "register_voter" in request:
                self.handle_voter_registration_request(request)
            elif "register_candidate" in request:
                self.handle_candidate_registration_request(request)
            elif "get_blockchain" in request:
                self.handle_blockchain_request(client_socket)
            elif "add_block" in request:
                self.handle_block_addition_request(request)
            elif "get_peers" in request:
                self.handle_peer_request(client_socket)

        except json.JSONDecodeError:
            logger.error("Invalid request format.")
        except ValueError as e:
            logger.error(str(e))
        except ConnectionResetError:
            logger.error("Connection with client closed abruptly.")

        client_socket.close()

    def handle_transaction_request(self, request):
        transaction_data = request["transaction"]
        transaction = Transaction.from_dict(transaction_data)
        public_key = bytes_to_public_key(bytes.fromhex(transaction_data["sender"]))

        if transaction.verify_transaction(public_key):
            self.blockchain.add_transaction(transaction)
            logger.info("Transaction added to the pending transactions.")
        else:
            logger.info("Invalid transaction.")

    def handle_balance_request(self, request, client_socket):
        address = request["get_balance"]
        balance = self.blockchain.get_balance(address)
        response = json.dumps({"balance": balance})
        client_socket.send(response.encode())

    def handle_voter_registration_request(self, request):
        public_key = bytes_to_public_key(bytes.fromhex(request["register_voter"]))
        self.blockchain.register_voter(public_key)
        logger.info("Voter registered.")

    def handle_candidate_registration_request(self, request):
        public_key = bytes_to_public_key(
            bytes.fromhex(request["register_candidate"]["public_key"])
        )
        name = request["register_candidate"]["name"]
        self.blockchain.register_candidate(public_key, name)
        logger.info("Candidate registered.")

    def handle_blockchain_request(self, client_socket):
        response = json.dumps(
            {"blockchain": self.blockchain.to_dict()},
            indent=4,
        )
        client_socket.send(response.encode())

    def handle_block_addition_request(self, request):
        block_data = request["add_block"]
        block = Block.from_dict(block_data)
        self.blockchain.add_block(block)
        logger.info("Block received and added to the blockchain.")

    def handle_peer(self, peer_socket):
        request = {"get_blockchain": True}
        peer_socket.send(json.dumps(request).encode())
        response = peer_socket.recv(4096).decode()
        response = json.loads(response)

        if "blockchain" in response:
            received_blockchain = response["blockchain"]
            if len(received_blockchain) > len(self.blockchain.chain):
                self.blockchain.chain = received_blockchain

    def start_mining(self):
        while True:
            time.sleep(5)  # Adjust the mining interval as needed
            self.blockchain.mine_pending_transactions()
            logger.info("Mining completed.")

    def handle_peer_request(self, client_socket):
        response = json.dumps({"peers": self.peer_manager.get_peers()})
        client_socket.send(response.encode())


class Wallet:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        self.public_key = self.private_key.public_key()

    def get_address(self):
        address = public_key_to_bytes(self.public_key)
        return address.hex()

    def sign_transaction(self, transaction):
        transaction.sign_transaction(self.private_key)


if __name__ == "__main__":
    bootstrap_nodes = BOOTSTRAP_NODES
    node = Node(bootstrap_nodes)
    node.start()
