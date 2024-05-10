# public Crypto (Class)
`QuatschAndSuch.Crypto`  

Static class to provide cryptographic functionality


## Fields

## Properties

## Methods
### public object GenerateKeyPair()
Generates new private and public keys using RSA

### public object SecuredHash()
Securly generates a hash for the inputted data using PBKDF2

### public object SecuredHash()
Securly generates a hash for the inputted data using PBKDF2, using a random value for the salt

### public object Extract(byte[] key)
Gets the public key out of the private key

#### byte[] key
The private key


### public object SaveKey(string path, byte[] key, string password)
Locally saves the key, along with the verification information for the password

#### string path
The path to saves this information to


#### byte[] key
The CSP blob for the private key to save


#### string password
The password to use for PKCS#8. Make sure to handle this securely!


### public object RetrieveKey(string path, string password)
Retrieve the locally stored key information, and verifies the password

#### string path
The path to get the information from


#### string password
The password to use for PKCS#8. Make sure to handle this securely!


### public object RetrieveKey(string path, int offset, string password, System.Int32@ bytesRead)
Retrieve the locally stored key information, and verifies the password

#### string path
The path to get the information from


#### int offset
The offset index from whihc to start reading the key information


#### string password
The password to use for PKCS#8. Make sure to handle this securely!


#### System.Int32@ bytesRead
How many bytes wereread for the key information


### public object Decrypt(byte[] packet, byte[] key)
Decrypts an encryption packet, and checks its hash to make sure it arrived correctly. Throws a DecryptionHashMismatchException when the sent hash and hash of the decrypted string are not the same

#### byte[] packet
The encryption packet. It contains the length of the following encrypted messgae string, followed by the 32 byte hash of the original string


#### byte[] key
The private key of the recipient


### public object Encrypt(string message, byte[] key)
Enrypts a string using the provided public key of the recipient

#### string message
The string to be encrypted. Supports Unicode (UTF-16)


#### byte[] key
The CSP blob of the recipients public key


### public object SaveEncrypted(string path, string content, string key)
Locally save a file, encrypted with symmetric encryption. Make sure to not lose the key!

#### string path
The path to save the encrypted file at


#### string content
To content to encrypt and save


#### string key
The key to encrypt everything with. Make sure to pick a secure, hard to guess key


### public object RetrieveEncrypted(string path, string key)
Retrieve and decrypt the contents of a locally saved, symmetrically enrypted file.

#### string path
The path to the encrypted file


#### string key
The key that was used to encrypt the data


