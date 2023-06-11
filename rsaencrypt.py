import base64
import concurrent.futures
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

BATCH_SIZE = 100

def encrypt_email_addresses(email_addresses, public_key):
    encrypted_email_addresses = []
    max_workers = 6  # Processor of this mac is 2.6 GHz 6-Core Intel Core i7, 
    batched_email_addresses = [email_addresses[i:i+BATCH_SIZE] for i in range(0, len(email_addresses), BATCH_SIZE)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for batch in batched_email_addresses:
            future = executor.submit(encrypt_batch, batch, public_key)
            futures.append(future)
        for future in concurrent.futures.as_completed(futures):
            encrypted_email_addresses.extend(future.result())
    return encrypted_email_addresses

def decrypt_email_addresses(encrypted_emails, private_key):
    decrypted_email_addresses = []
    max_workers = 6  # Get the number of available CPU cores
    batched_encrypted_emails = [encrypted_emails[i:i+BATCH_SIZE] for i in range(0, len(encrypted_emails), BATCH_SIZE)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for batch in batched_encrypted_emails:
            future = executor.submit(decrypt_batch, batch, private_key)
            futures.append(future)
        for future in concurrent.futures.as_completed(futures):
            decrypted_email_addresses.extend(future.result())
    return decrypted_email_addresses

def encrypt_batch(emails, public_key):
    encrypted_emails = []
    for email in emails:
        email_bytes = email.encode('utf-8')
        encrypted_email = public_key.encrypt(
            email_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("email encrypted is : " + str(email))
        encrypted_emails.append(encrypted_email)
    return encrypted_emails

def decrypt_batch(encrypted_emails, private_key):
    decrypted_emails = []
    count = 1
    for encrypted_email in encrypted_emails:
        decrypted_email = private_key.decrypt(
            encrypted_email,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_emails.append(decrypted_email.decode('utf-8'))
        print(str(count) + "st encrypted email is decrypted")
        count =count+1
    return decrypted_emails

# Generate a 4096-bit RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)
public_key = private_key.public_key()

# Save the public key to a file
with open('/Users/dhruv.varshney/Documents/encrypt/public_key.txt', 'wb') as key_file:
    key_file.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Save the private key to a file
with open('/Users/dhruv.varshney/Documents/encrypt/private_key.txt', 'wb') as key_file:
    key_file.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Example email addresses
with open('/Users/dhruv.varshney/Documents/email_list.txt', 'r') as file:
    content = file.readlines()
    content = [line.strip() for line in content]
print("Emails to encrypt:", len(content))

# Encrypt the email addresses
encrypted_emails = encrypt_email_addresses(content, public_key)

# Encode encrypted emails as Base64
encoded_emails = [base64.b64encode(email).decode('utf-8') for email in encrypted_emails]
count = 1
# for i in encoded_emails:
#     print(str(count) + " "+ str(i) + '\n')
#     count = count+1
# Save the encoded emails to a file
emails_count = 1
with open('/Users/dhruv.varshney/Documents/encrypt/email6.txt', 'w') as file:
    for email in encoded_emails:
        file.write(str(emails_count) + " " + str(email) + '\n')
        file.write('\n')
        emails_count = emails_count+1
print("encrytion done decryption started")
# Decrypt the email addresses
decrypted_emails = decrypt_email_addresses(encrypted_emails, private_key)

# Print the decrypted email addresses
decrypt_email_count=1
print("Now encypted emails are decrypting and are getting stored in different file")
with open('/Users/dhruv.varshney/Documents/encrypt/emaildecrpted.txt', 'w') as file:
    for email in decrypted_emails:
        file.write(str(decrypt_email_count) + " " + str(email) + '\n')
        file.write('\n')
        decrypt_email_count = decrypt_email_count+1

print("Now emails are decrypted and are stored in different file")
