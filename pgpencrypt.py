import gnupg
import concurrent.futures

def encrypt_email(email, import_result):
    gpg = gnupg.GPG('/usr/local/bin/gpg')
    print(f'Encrypting email: {email}')
    encrypted = gpg.encrypt(email, import_result.fingerprints[0], armor=True)
    return str(encrypted) if encrypted.ok else None

def encrypt_emails(emails_file, public_key_file, output_file, num_workers=4):
    gpg = gnupg.GPG('/usr/local/bin/gpg')

    # Import the public key
    with open(public_key_file, 'r') as f:
        key_data = f.read()
        import_result = gpg.import_keys(key_data)

    # Check if the key import was successful
    if import_result.counts['count'] == 0:
        print('Failed to import the public key.')
        return

    with open(emails_file, 'r') as f:
        emails = [f.read()]

    print(f'Length of email list: {len(emails)}')

    encrypted_emails = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(encrypt_email, email, import_result) for email in emails]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                encrypted_emails.append(result)

    with open(output_file, 'w') as f:
        f.write('\n'.join(encrypted_emails))

    print(f'Encryption completed. Encrypted emails saved in {output_file}.')

# Usage
emails_file = '/Users/dhruv.varshney/Documents/email_list.txt'
public_key_file = '/Users/dhruv.varshney/Downloads/macys_2023_pgp_prod.txt'
output_file = '/Users/dhruv.varshney/Documents/encrypted_emails.pgp'
num_workers = 6  # Adjust the number of workers as per your system's capabilities

encrypt_emails(emails_file, public_key_file, output_file, num_workers)
