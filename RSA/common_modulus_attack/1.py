from Crypto.Util.number import inverse, long_to_bytes, GCD

# Given values
n = ...  # common modulus
e1 = ... # first public exponent
e2 = ... # second public exponent
c1 = ... # ciphertext using e1
c2 = ... # ciphertext using e2

# Step 1: Check GCD(e1, e2) == 1 to ensure e1 and e2 are coprime
assert GCD(e1, e2) == 1, "e1 and e2 must be coprime for the common modulus attack."

# Step 2: Use Extended Euclidean Algorithm to find x and y such that x*e1 + y*e2 = 1
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

_, x, y = extended_gcd(e1, e2)

# Step 3: Calculate m = (c1^x * c2^y) mod n
if x < 0:
    c1 = inverse(c1, n)  # Inverse if x is negative
    x = -x
if y < 0:
    c2 = inverse(c2, n)  # Inverse if y is negative
    y = -y

m = (pow(c1, x, n) * pow(c2, y, n)) % n

# Step 4: Convert m to plaintext
plaintext = long_to_bytes(m)
print("Recovered message:", plaintext)
