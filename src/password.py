import hashlib
import hmac
import string

def derive_password(user_secret, local_secret, unique_string):
    master = (user_secret + local_secret).encode()
    salt = unique_string.encode()

    key = hashlib.scrypt(
        master,
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32
    )
    return bytes.fromhex(key.hex())



def sanitize_password(
    raw_bytes: bytes,
    length=16,
    require_upper=True,
    require_lower=True,
    require_digit=True,
    require_symbol=True,
    allowed_symbols="!@#$%^&*",
    max_repeat=2,
    must_start_letter=False,
):
    """

    :param raw_bytes:
    :param length: Use a specific length, if site does not allow the default 16, use the minimum allowed length.
    :param require_upper: Must have at least one uppercase letter
    :param require_lower: Must have at least one lowercase letter
    :param require_digit: Must have at least one digit
    :param require_symbol: Must have at least one symbol
    :param allowed_symbols: A string containing all the symbols required by the site
    :param max_repeat:
    :param must_start_letter:
    :return:
    """
    rng = DeterministicRNG(raw_bytes)

    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    symbols = allowed_symbols

    allowed = ""
    if require_lower: allowed += lower
    if require_upper: allowed += upper
    if require_digit: allowed += digits
    if require_symbol: allowed += symbols

    # fallback if symbols not allowed
    if not allowed:
        allowed = lower + upper + digits

    password = []

    # Ensure required classes exist
    if require_lower:
        password.append(rng.choice(lower))
    if require_upper:
        password.append(rng.choice(upper))
    if require_digit:
        password.append(rng.choice(digits))
    if require_symbol:
        password.append(rng.choice(symbols))

    # Fill remaining length
    while len(password) < length:
        password.append(rng.choice(allowed))

    # Shuffle deterministically
    password = rng.shuffle(password)

    # Enforce starting letter
    if must_start_letter and password[0] not in (lower + upper):
        for i in range(1, len(password)):
            if password[i] in (lower + upper):
                password[0], password[i] = password[i], password[0]
                break

    # Enforce max repeat rule
    def fix_repeats(pw):
        for i in range(1, len(pw)):
            count = 1
            for j in range(i-1, -1, -1):
                if pw[j] == pw[i]:
                    count += 1
                else:
                    break
            if count > max_repeat:
                pw[i] = rng.choice(allowed)
        return pw

    password = fix_repeats(password)

    return ''.join(password[:length])



class DeterministicRNG:
    def __init__(self, seed: bytes):
        self.seed = seed
        self.counter = 0

    def random_bytes(self, n):
        result = b''
        while len(result) < n:
            block = hmac.new(
                self.seed,
                self.counter.to_bytes(8, 'big'),
                hashlib.sha256
            ).digest()
            result += block
            self.counter += 1
        return result[:n]

    def choice(self, seq):
        idx = int.from_bytes(self.random_bytes(4), 'big') % len(seq)
        return seq[idx]

    def shuffle(self, seq):
        seq = list(seq)
        for i in reversed(range(1, len(seq))):
            j = int.from_bytes(self.random_bytes(4), 'big') % (i + 1)
            seq[i], seq[j] = seq[j], seq[i]
        return seq