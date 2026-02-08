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
PASSWORD_CHECK_CONTEXT = b"keychain-password-check"
########### END CODE HERE ###########


class Keychain:
    def __init__(
        ########## START CODE HERE ##########
        self, keychain_password: str, *, salt: Optional[bytes] = None, 
        kvs: Optional[dict] = None
        ########### END CODE HERE ###########
    ):
        """
        Initializes the keychain using the provided information. Note that 
        external users should likely never invoke the constructor directly and 
        instead use either Keychain.new or Keychain.load.

        If salt and kvs are provided, the keychain is restored deterministically
        from persisted state. Otherwise, fresh random state is created for a new
        keychain.

        Args:
            You may design the constructor with any additional arguments you 
            would like.
        Returns:
            None
        """
        ########## START CODE HERE ##########
        if salt is None: salt = get_random_bytes(16)
        if kvs is None: kvs = {}

        self.data = {
            # Store member variables that you intend to be public here
            # (i.e. information that will not compromise security if an 
            # adversary sees).
            # This data should be dumped by the Keychain.dump function.
            # You should store the key-value store (KVS) in the "kvs" item in 
            # this dictionary.
            "salt": salt,
            "kvs": kvs,
        }
        master = PBKDF2(keychain_password, self.data["salt"], 32, 
                        count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
        dom_key = HMAC.new(master, b"domain", digestmod=SHA256).digest()
        enc_key = HMAC.new(master, b"encryption", digestmod=SHA256).digest()
        
        # Store member variables that you intend to be private here
        # (information that an adversary should NOT see).
        self.secrets = {"dom_key": dom_key, "enc_key": enc_key}
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
        return Keychain(keychain_password)
        ########### END CODE HERE ###########

    @staticmethod
    def load(
        keychain_password: str, repr: str, 
        trusted_data_check: Optional[bytes] = None
    ) -> "Keychain":
        """
        Creates a new keychain from an existing key-value store.

        Loads the keychain state from the provided representation (repr).
        You can assume that the representation passed to load is
        well-formed (i.e., it will be a valid JSON object) and was
        generated from the Keychain.dump function.

        Use the provided `json_str_to_dict` function to convert a JSON
        string into a nested dictionary.

        Args:
            keychain_password: the password to unlock the keychain
            repr: a JSON-encoded serialization of the KVS (string)
            trusted_data_check: an optional SHA-256 checksum of the
                KVS (bytes or None)
        Returns:
            A Keychain instance containing the data from repr
        Throws:
            ValueError: if the checksum is provided in
                trusted_data_check and the checksum check fails
            ValueError: if the provided keychain password is not
                correct for the repr (hint: this is thrown for you by
                HMAC.verify)
        """
        ########## START CODE HERE ##########
        # If a trusted checksum is provided, recompute the checksum and reject
        # if it has been modified.
        if trusted_data_check is not None:
            computed_check = SHA256.new(str_to_bytes(repr)).digest()
            if computed_check != trusted_data_check:
                raise ValueError("Checksum verification failed")
            
        serialized = json_str_to_dict(repr)
        # Load the stored salt to re-derive keys from the password.
        salt = decode_bytes(serialized["salt"])

        # Normalize the key-value store to a dictionary.
        kvs = serialized.get("kvs")

        # Restore persisted state through __init__.
        keychain = Keychain(keychain_password, salt=salt, kvs=kvs)

        # Verify correctness using persisted HMAC marker when available.
        # HMAC.verify raises ValueError on mismatch.
        if "pw_check" in serialized:
            verifier = HMAC.new(keychain.secrets["dom_key"], 
                                PASSWORD_CHECK_CONTEXT, digestmod=SHA256)
            verifier.verify(decode_bytes(serialized["pw_check"]))

        return keychain
        ########### END CODE HERE ###########

    def dump(self) -> Tuple[str, bytes]:
        """
        Returns a JSON serialization and a checksum of the
        contents of the keychain that can be loaded back using the
        Keychain.load function.

        For testing purposes, please ensure that the JSON string you
        return contains the key 'kvs' with your KVS dict as its value.
        The KVS should have one key per domain.

        Use the provided `dict_to_json_str` function to convert a
        nested dictionary into its JSON representation.

        Returns:
            A tuple consisting of (1) the JSON serialization of the
            contents, and (2) the SHA256 checksum of the JSON
            serialization
        """
        ########## START CODE HERE ##########
        # Build a JSON-safe public snapshot
        public_state = {
            "salt": encode_bytes(self.data["salt"]),
            "kvs": self.data["kvs"],
            # Add a password-verification marker so load can reject an
            # incorrect keychain password even for an empty KVS.
            "pw_check": encode_bytes(
                HMAC.new(self.secrets["dom_key"], PASSWORD_CHECK_CONTEXT,
                    digestmod=SHA256).digest()
            ),
        }

        # Serialize to stay consistent with the starter API.
        rep_str = dict_to_json_str(public_state)
        checksum = SHA256.new(str_to_bytes(rep_str)).digest()
        return rep_str, checksum
        ########### END CODE HERE ###########

    def get(self, domain: str) -> Optional[str]:
        """
        Fetches the password corresponding to a given domain from
        the key-value store.

        Args:
            domain: the domain for which the password is requested
        Returns:
            The password for the domain if it exists in the KVS,
            or None if it does not exist
        """
        ########## START CODE HERE ##########

        dom_key = HMAC.new(self.secrets["dom_key"], str_to_bytes(domain),
            digestmod=SHA256).digest()
        
        record = self.data["kvs"].get(encode_bytes(dom_key))
        if record is None: return None

        # Recreate the cipher using the stored nonce and the encryption key, 
        # then decrypt and verify the ciphertext.
        cipher = AES.new(self.secrets["enc_key"], AES.MODE_GCM, 
                         nonce=decode_bytes(record["nonce"]),
        )
        plaintext = cipher.decrypt_and_verify(decode_bytes(record["ct"]), 
                                              decode_bytes(record["tag"]),
        )
        return bytes_to_str(plaintext)
        ########### END CODE HERE ###########

    def set(self, domain: str, password: str):
        """
        Inserts the domain and password into the KVS. If the domain is already
        in the password manager, this will update the password for that domain.
        If it is not, a new entry in the password manager is created.

        Args:
            domain: the domain for the provided password. This
                domain may already exist in the KVS
            password: the password for the provided domain
        """
        ########## START CODE HERE ##########
        dom_key = HMAC.new(self.secrets["dom_key"], str_to_bytes(domain), 
                           digestmod=SHA256).digest()

        # Create an AES-GCM cipher with the encryption key and encrypt password
        cipher = AES.new(self.secrets["enc_key"], AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(str_to_bytes(password))

        # Store the record using encoded byte-strings for portability
        self.data["kvs"][encode_bytes(dom_key)] = {
            "nonce": encode_bytes(cipher.nonce),
            "ct": encode_bytes(ciphertext),
            "tag": encode_bytes(tag),
        }
        ########### END CODE HERE ###########

    def remove(self, domain: str) -> bool:
        """
        Removes the domain-password pair for the provided domain
        from the password manager. If the domain does not exist in the
        password manager, this method deos nothing.

        Args:
            domain: the domain which should be removed from the
                KVS, along with its password
        Returns:
            True if the domain existed in the KVS and was removed,
            False otherwise
        """
        ########## START CODE HERE ##########
        # Derive the same deterministic key used when storing the domain.
        dom_key = HMAC.new(self.secrets["dom_key"], str_to_bytes(domain), 
                           digestmod=SHA256).digest()
        encoded_dom_key = encode_bytes(dom_key)

        # Delete and return True only when the entry exists.
        if encoded_dom_key in self.data["kvs"]:
            del self.data["kvs"][encoded_dom_key]
            return True
        return False
        ########### END CODE HERE ###########
