import hashlib
import time
import socket
import threading
import json
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


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

    def mine_block(self, difficulty):  # Proof of Work
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        print("Block mined:", self.hash)

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
            [Transaction.from_dict(tx_data) for tx_data in data["transactions"]],
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
            "sender": self.sender.decode(),
            "recipient": self.recipient.decode(),
            "amount": self.amount,
            "signature": self.signature.hex(),  # Convert bytes to hexadecimal string
        }

    @classmethod
    def from_dict(cls, data):
        sender = data["sender"].encode()
        recipient = data["recipient"].encode()
        amount = data["amount"]
        signature = bytes.fromhex(
            data["signature"]
        )  # Convert hexadecimal string to bytes
        return cls(sender, recipient, amount, signature)


class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 4
        self.pending_transactions = []
        self.voters = set()
        self.candidates = {}

    def create_genesis_block(self):
        return Block(0, time.time(), [], "0")

    @property
    def latest_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self):
        print("PENDING TRANSACTIONS:", len(self.pending_transactions))
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

    def register_voter(self, voter_public_key):
        self.voters.add(voter_public_key)

    def authenticate_voter(self, voter_public_key):
        return voter_public_key in self.voters

    def register_candidate(self, candidate_public_key):
        self.candidates[candidate_public_key] = 0

    def vote_for_candidate(self, sender_wallet, candidate_public_key, amount):
        transaction = Transaction(
            sender_wallet.get_public_key_bytes(), candidate_public_key, amount
        )
        sender_wallet.sign_transaction(transaction)
        if transaction.verify_transaction(sender_wallet.public_key):
            self.add_transaction(transaction)
            self.candidates[candidate_public_key] += amount
        else:
            print("Failed to validate the transaction.")

    def get_candidate_votes(self, candidate_public_key):
        return self.candidates.get(candidate_public_key, 0)


class Wallet:
    def __init__(self):
        self.private_key, self.public_key = self.generate_keys()

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_transaction(self, transaction):
        transaction.sign_transaction(self.private_key)

    def get_public_key_bytes(self):
        return public_key_to_bytes(self.public_key)


class Node:
    def __init__(self, host, port, blockchain):
        self.host = host
        self.port = port
        self.node_id = f"{self.host}:{self.port}"
        self.blockchain = blockchain
        self.server = None
        self.peers = set()

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        print(f"Node {self.node_id} listening on {self.host}:{self.port}")
        threading.Thread(target=self.accept_connections).start()
        threading.Thread(target=self.discover_peers).start()

    def accept_connections(self):
        while True:
            client_socket, client_address = self.server.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()
            threading.Thread(target=self.handle_peer, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        request = self.receive_message(client_socket)
        print("Handle Client")
        if request:
            message_type = request["type"]
            if message_type == "new_transaction":
                transaction = Transaction(
                    request["data"]["sender"],
                    request["data"]["recipient"],
                    request["data"]["amount"],
                    request["data"]["signature"],
                )
                if transaction.verify_transaction(
                    bytes_to_public_key(transaction.sender)
                ):
                    self.blockchain.add_transaction(transaction)
                    response = {"type": "transaction_added"}
                else:
                    response = {"type": "transaction_invalid"}
                self.send_message(client_socket, response)
            elif message_type == "get_balance":
                balance = self.blockchain.get_balance(request["data"]["address"])
                response = {"type": "balance_response", "data": {"balance": balance}}
                self.send_message(client_socket, response)
            elif message_type == "get_candidate_votes":
                votes = self.blockchain.get_candidate_votes(
                    request["data"]["candidate_public_key"]
                )
                response = {
                    "type": "candidate_votes_response",
                    "data": {"votes": votes},
                }
                self.send_message(client_socket, response)
            elif message_type == "get_blockchain":
                response = {
                    "type": "blockchain_response",
                    "data": {
                        "blockchain": [
                            block.to_dict() for block in self.blockchain.chain
                        ]
                    },
                }
                self.send_message(client_socket, response)
            else:
                response = {"type": "error", "message": "Invalid message type"}
                self.send_message(client_socket, response)
        client_socket.close()

    def send_message(self, client_socket, message):
        data = self.serialize_message(message)
        client_socket.sendall(data)

    def receive_message(self, client_socket):
        complete_data = b""
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            complete_data += data

            # Check if the complete message has been received
            if len(complete_data) >= 4:
                message_length = int.from_bytes(complete_data[:4], "big")
                if len(complete_data) >= 4 + message_length:
                    message_data = complete_data[4 : 4 + message_length]
                    message = self.deserialize_message(message_data)
                    return message

        return None

    @staticmethod
    def serialize_message(message):
        return json.dumps(message).encode()

    @staticmethod
    def deserialize_message(data):
        return json.loads(data.decode())

    def connect_to_peer(self, peer_host, peer_port):
        if (peer_host, peer_port) not in self.peers:
            try:
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.connect((peer_host, peer_port))
                self.peers.add((peer_host, peer_port))
                threading.Thread(target=self.handle_peer, args=(peer_socket,)).start()
                print(f"Connected to peer {peer_host}:{peer_port}")
                self.send_message(peer_socket, {"type": "get_blockchain"})
            except ConnectionRefusedError:
                print(f"Connection to peer {peer_host}:{peer_port} refused")

    def handle_peer(self, peer_socket):
        request = self.receive_message(peer_socket)
        print("HANDLE PEER")
        if request:
            message_type = request["type"]
            if message_type == "get_peers":
                response = {
                    "type": "peers_response",
                    "data": {"peers": list(self.peers)},
                }
                self.send_message(peer_socket, response)
            elif message_type == "add_peer":
                peer_host = request["data"]["host"]
                peer_port = request["data"]["port"]
                self.connect_to_peer(peer_host, peer_port)
            elif message_type == "blockchain_response":
                received_blockchain = request["data"]["blockchain"]
                if len(received_blockchain) > len(self.blockchain.chain):
                    self.blockchain.chain = [
                        Block.from_dict(block_data)
                        for block_data in received_blockchain
                    ]
                    print("Updated blockchain received from peer")
            elif message_type == "new_block":
                block_data = request["data"]
                block = Block.from_dict(block_data)
                if block.index == self.blockchain.latest_block.index + 1:
                    self.blockchain.chain.append(block)
                    print("New block added to the blockchain")
                else:
                    print("Received block has incorrect index")
            else:
                response = {"type": "error", "message": "Invalid message type"}
                self.send_message(peer_socket, response)
        peer_socket.close()

    def broadcast_message(self, message):
        for peer_host, peer_port in self.peers:
            print(self.host, self.port, "Broadcasted to:", peer_host, peer_port)
            try:
                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer_socket.connect((peer_host, peer_port))
                self.send_message(peer_socket, message)
                peer_socket.close()
            except ConnectionRefusedError:
                print(f"Connection to peer {peer_host}:{peer_port} refused")

    def start_mining(self, difficulty):
        while True:
            self.blockchain.mine_pending_transactions()
            block = self.blockchain.latest_block
            message = {"type": "new_block", "data": block.to_dict()}
            self.broadcast_message(message)
            time.sleep(5)  # Mine a new block every 10 seconds

    def discover_peers(self):
        while True:
            for peer_host, peer_port in self.peers.copy():
                try:
                    peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    peer_socket.connect((peer_host, peer_port))
                    self.send_message(peer_socket, {"type": "get_peers"})
                    response = self.receive_message(peer_socket)
                    if response and response["type"] == "peers_response":
                        new_peers = response["data"]["peers"]
                        for new_peer in new_peers:
                            if (
                                new_peer != (self.host, self.port)
                                and new_peer not in self.peers
                            ):
                                self.peers.add(new_peer)
                                self.send_message(
                                    peer_socket,
                                    {
                                        "type": "add_peer",
                                        "data": {"host": self.host, "port": self.port},
                                    },
                                )
                    peer_socket.close()
                except ConnectionRefusedError:
                    print(f"Connection to peer {peer_host}:{peer_port} refused")
            time.sleep(30)  # Discover peers every 30 seconds


def main():
    # Create a blockchain instance
    blockchain = Blockchain()

    # Create a node and start it
    node = Node("localhost", 5000, blockchain)
    node.start()

    # Create a node and start it
    Bootstrap5001 = Node("localhost", 5001, blockchain)
    Bootstrap5001.start()

    # Create a node and start it
    Bootstrap5002 = Node("localhost", 5002, blockchain)
    Bootstrap5002.start()

    # Connect to peers
    node.connect_to_peer("localhost", 5001)
    node.connect_to_peer("localhost", 5002)

    # Start mining thread
    threading.Thread(target=node.start_mining, args=(blockchain.difficulty,)).start()
    # threading.Thread(
    #     target=Bootstrap5001.start_mining, args=(blockchain.difficulty,)
    # ).start()
    # threading.Thread(
    #     target=Bootstrap5002.start_mining, args=(blockchain.difficulty,)
    # ).start()

    # Create candidates
    candidate1 = Wallet()
    candidate2 = Wallet()

    # Register candidates
    blockchain.register_candidate(candidate1.get_public_key_bytes())
    blockchain.register_candidate(candidate2.get_public_key_bytes())

    # Get the list of candidate public keys
    candidate_public_keys = list(blockchain.candidates.keys())

    # Wait for mining thread to complete
    while True:
        # Create a list to store voters
        voters = []

        # Create voters and register them
        for _ in range(random.randint(1, 10)):
            voter = Wallet()
            voters.append(voter)
            blockchain.register_voter(voter.get_public_key_bytes())

        # Vote for candidates randomly
        for voter in voters:
            candidate_public_key = random.choice(candidate_public_keys)
            amount = 1
            blockchain.vote_for_candidate(voter, candidate_public_key, amount)

        # Print candidate votes
        print(
            "Candidate 1 Votes:",
            blockchain.get_candidate_votes(candidate1.get_public_key_bytes()),
        )
        print(
            "Candidate 2 Votes:",
            blockchain.get_candidate_votes(candidate2.get_public_key_bytes()),
        )
        print("Is the chain valid:", blockchain.is_chain_valid())
        time.sleep(3)


if __name__ == "__main__":
    main()
