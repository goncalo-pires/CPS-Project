from IBE import IBE

# ibe can be a 3rd party which initializes the global
# parameters and master-key for Bob. But it can also be Bob
# who generates his own global parameters and master-key.
print("Initializing IBE with Bob's parameters and master-key...")
ibe = IBE()

# Bob's e-mail is his public key ID:
BobID = "bob@mail.com"

# Alice's message to be encrypted and sent to Bob.
plaintext = ("In this Python Object t-Oriented Tutorial, we will "
    "be learning about class variables. We will see how they "
    "differ from instance variables and also some ideas for "
    "exactly how we would want to use them. Let's get started.")

# Alice requests the 3rd party or Bob for Bob's
# global parameters so that she can encrypt the message
# using Bob's public key ID.
try:
    print("Alice: Encrypting message...")
    ciphertext = IBE.encrypt(ibe.params, BobID, plaintext)
except Exception as e:
    print(str(e))

# Bob authenticates before the IBE, if it is a 3rd party,
# which generates his private key using 'extract', which
# uses the master-key, that only the IBE knows, and also
# Bob's public key ID.
# Authentication with the IBE is not part of this project.
try:
    print("Bob: Extracting private key...")
    BobPK = ibe.extract(ibe.params, BobID)
except Exception as e:
    print(str(e))

# Bob requests the IBE to decrypt the message using
# his private key and global parameters.
try:
    print("Bob: Decrypting message...")
    msg = IBE.decrypt(ibe.params, ciphertext, BobPK)
    print("Bob: Decrypted message: '{}'.".format(msg))
except Exception as e:
    print(str(e))
