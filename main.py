import random
import math


class KnapsackCrypto:
    def __init__(self):
        self.alphabet = " " + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.char_to_int = {char: i for i, char in enumerate(self.alphabet)}
        self.int_to_char = {i: char for i, char in enumerate(self.alphabet)}
        self.block_size = 0  # Will be set during key gen

    def _generate_superincreasing(self, n):
        """
        Generates a superincreasing sequence of length n.
        """
        w = []
        current_sum = 0
        for _ in range(n):
            next_val = random.randint(current_sum + 1, current_sum + 100)
            w.append(next_val)
            current_sum += next_val
        return w, current_sum

    def generate_keys(self, n=10):
        """
        n is The length of the key (number of items in the knapsack).
           Ideally a multiple of 5 (since 1 char = 5 bits).
           Defaulting to 10 (2 chars at a time).
        """
        self.block_size = n

        # 1. Generate Private Key part: Superincreasing sequence (w)
        w, total_sum = self._generate_superincreasing(n)

        # 2. Choose Modulus (q) such that q > sum(w)
        q = random.randint(total_sum + 1, total_sum + 500)

        # 3. Choose Multiplier (r) such that gcd(r, q) = 1 (coprime)
        r = random.randint(2, q - 1)
        while math.gcd(r, q) != 1:
            r = random.randint(2, q - 1)

        # 4. Calculate Public Key (beta)
        # beta = (w * r) mod q
        beta = [(val * r) % q for val in w]

        public_key = beta
        private_key = (w, q, r)

        return public_key, private_key

    def _text_to_bits(self, plaintext):
        """Converts text to a binary string based on 27-char alphabet."""
        bit_string = ""
        for char in plaintext.upper():
            if char not in self.char_to_int:
                raise ValueError(f"Invalid character found: '{char}'")

            val = self.char_to_int[char]
            # Convert to 5-bit binary (27 chars needs 5 bits)
            # 0 becomes '00000', 1 becomes '00001', etc.
            binary = format(val, '05b')
            bit_string += binary
        return bit_string

    def encrypt(self, plaintext, public_key):
        """
        Using the public key, encrypts a given plaintext.
        """
        # 1. Validation
        if not all(c in self.alphabet for c in plaintext.upper()):
            raise ValueError("Plaintext contains characters not in the defined alphabet.")

        n = len(public_key)

        # 2. Convert text to bits
        bit_string = self._text_to_bits(plaintext)

        # 3. Pad the bit string if it doesn't fit the key length perfectly
        remainder = len(bit_string) % n
        if remainder != 0:
            padding_needed = n - remainder
            # Pad with 0s (which maps to Space in our logic, so it's safe)
            bit_string += '0' * padding_needed

        # 4. Encrypt blocks
        ciphertext_blocks = []

        # Process the bit string in chunks of size n
        for i in range(0, len(bit_string), n):
            chunk = bit_string[i:i + n]

            # Calculate Dot Product: sum(bit * public_key_val)
            block_sum = 0
            for bit_index, bit in enumerate(chunk):
                if bit == '1':
                    block_sum += public_key[bit_index]

            ciphertext_blocks.append(block_sum)

        return ciphertext_blocks


# example use for testing
if __name__ == "__main__":
    crypto = KnapsackCrypto()

    # Generate Keys (the size,n, is the number of bits per block, ideally multiple of 5 since n / 5 will be the number of chars in each block)
    pub_key, priv_key = crypto.generate_keys(n=10)

    print(f"Public Key: {pub_key}")
    print(f"Private Key: {priv_key}")

    message = input("\nEnter plaintext (Space and A-Z only): ")
    print(f"\nOriginal Message: '{message}'")

    # Encrypt
    try:
        cipher = crypto.encrypt(message, pub_key)
        print(f"Encrypted Ciphertext: {cipher}")
    except ValueError as e:
        print(f"Error: {e}")