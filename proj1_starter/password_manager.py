from typing import Optional, Tuple

from util import dict_to_json_str, json_str_to_dict
from util import str_to_bytes, bytes_to_str, encode_bytes, decode_bytes

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# number of iterations for PBKDF2 algorithm
PBKDF2_ITERATIONS = 100000
# we can assume no password is longer than this many characters
MAX_PASSWORD_LENGTH = 64

########## START CODE HERE ##########
# Add any extra constants you may need
########### END CODE HERE ###########


class Keychain:
    def __init__(
        self,
        ########## START CODE HERE ##########
        ########### END CODE HERE ###########
    ):
        """
        Initializes the keychain using the provided information. Note that external users should
        likely never invoke the constructor directly and instead use either Keychain.new or
        Keychain.load.

        Args:
            You may design the constructor with any additional arguments you would like.
        Returns:
            None
        """
        ########## START CODE HERE ##########
        self.data = {
            # Store member variables that you intend to be public here
            # (i.e. information that will not compromise security if an adversary sees).
            # This data should be dumped by the Keychain.dump function.
            # You should store the key-value store (KVS) in the "kvs" item in this dictionary.
            "kvs": None,
        }
        self.secrets = {
            # Store member variables that you intend to be private here
            # (information that an adversary should NOT see).
        }
        raise NotImplementedError(
            "Delete this line once you've implemented the Keychain constructor (__init__)"
        )
        ########### END CODE HERE ###########

    ########## START CODE HERE ##########
    # Add any helper functions you may want to add here

    ########### END CODE HERE ###########

    @staticmethod
    def new(keychain_password: str) -> "Keychain":
        """
        Creates an empty keychain with the given keychain password.

        Args:
            keychain_password: the password to unlock the keychain
        Returns:
            A Keychain instance
        """
        ########## START CODE HERE ##########
        raise NotImplementedError("Delete this line once you've implemented Keychain.new")
        ########### END CODE HERE ###########

    @staticmethod
    def load(
        keychain_password: str, repr: str, trusted_data_check: Optional[bytes] = None
    ) -> "Keychain":
        """
        Creates a new keychain from an existing key-value store.

        Loads the keychain state from the provided representation (repr). You can assume that
        the representation passed to load is well-formed (i.e., it will be a valid JSON object)
        and was generated from the Keychain.dump function.

        Use the provided `json_str_to_dict` function to convert a JSON string into a nested dictionary.

        Args:
            keychain_password: the password to unlock the keychain
            repr: a JSON-encoded serialization of the contents of the key-value store (string)
            trusted_data_check: an optional SHA-256 checksum of the KVS (bytes or None)
        Returns:
            A Keychain instance containing the data from repr
        Throws:
            ValueError: if the checksum is provided in trusted_data_check and the checksum check fails
            ValueError: if the provided keychain password is not correct for the repr (hint: this is
                thrown for you by HMAC.verify)
        """
        ########## START CODE HERE ##########
        raise NotImplementedError("Delete this line once you've implemented Keychain.load")
        ########### END CODE HERE ###########

    def dump(self) -> Tuple[str, bytes]:
        """
        Returns a JSON serialization and a checksum of the contents of the keychain that can be
        loaded back using the Keychain.load function.

        For testing purposes, please ensure that the JSON string you return contains the key
        'kvs' with your KVS dict as its value. The KVS should have one key per domain.

        Use the provided `dict_to_json_str` function to convert a nested dictionary into
        its JSON representation.

        Returns:
            A tuple consisting of (1) the JSON serialization of the contents, and (2) the SHA256
            checksum of the JSON serialization
        """
        ########## START CODE HERE ##########
        raise NotImplementedError("Delete this line once you've implemented Keychain.dump")
        ########### END CODE HERE ###########

    def get(self, domain: str) -> Optional[str]:
        """
        Fetches the password corresponding to a given domain from the key-value store.

        Args:
            domain: the domain for which the password is requested
        Returns:
            The password for the domain if it exists in the KVS, or None if it does not exist
        """
        ########## START CODE HERE ##########
        raise NotImplementedError("Delete this line once you've implemented Keychain.get")
        ########### END CODE HERE ###########

    def set(self, domain: str, password: str):
        """
        Inserts the domain and password into the KVS. If the domain is already
        in the password manager, this will update the password for that domain.
        If it is not, a new entry in the password manager is created.

        Args:
            domain: the domain for the provided password. This domain may already exist in the KVS
            password: the password for the provided domain
        """
        ########## START CODE HERE ##########
        raise NotImplementedError("Delete this line once you've implemented Keychain.set")
        ########### END CODE HERE ###########

    def remove(self, domain: str) -> bool:
        """
        Removes the domain-password pair for the provided domain from the password manager.
        If the domain does not exist in the password manager, this method deos nothing.

        Args:
            domain: the domain which should be removed from the KVS, along with its password
        Returns:
            True if the domain existed in the KVS and was removed, False otherwise
        """
        ########## START CODE HERE ##########
        raise NotImplementedError("Delete this line once you've implemented Keychain.remove")
        ########### END CODE HERE ###########
