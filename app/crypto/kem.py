from app.crypto._oqs_loader import load_key_encapsulation
from app.services.algorithm_support import enabled_mechanisms

class KEMManager:
    @staticmethod
    def get_supported_kems():
        """
        Returns a static list of core KEM algorithms. 
        Bypasses the unstable liboqs-python discovery method to ensure stability.
        """
        enabled, _ = enabled_mechanisms()
        preferred = (
            "ML-KEM-512",
            "ML-KEM-768",
            "ML-KEM-1024",
            "Kyber512",
            "Kyber768",
            "Kyber1024",
        )
        return [name for name in preferred if name.casefold() in enabled]

    @staticmethod
    def generate_keypair(algorithm_name):
        KeyEncapsulation = load_key_encapsulation()
        with KeyEncapsulation(algorithm_name) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
            return {"public_key": public_key, "private_key": private_key}

    @staticmethod
    def encapsulate(algorithm_name, public_key):
        KeyEncapsulation = load_key_encapsulation()
        with KeyEncapsulation(algorithm_name) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return {"ciphertext": ciphertext, "shared_secret": shared_secret}

    @staticmethod
    def decapsulate(algorithm_name, ciphertext, private_key):
        KeyEncapsulation = load_key_encapsulation()
        with KeyEncapsulation(algorithm_name, private_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
            return {"shared_secret": shared_secret}
