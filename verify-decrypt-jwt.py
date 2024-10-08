# we'll focus on the server-side processing. 
# After the client sends the signed JWT, the server (Payment Gateway) must
# Verify the JWT signature.
# Decrypt the encrypted credit card data.

import jwt
import boto3
import base64

# AWS KMS client
kms_client = boto3.client('kms', region_name='us-east-1')

# Load public key for JWT signature verification
public_key = open('public.pem').read()  # Load your public key

# Function to decrypt the encrypted credit card data using AWS KMS
def decrypt_credit_card_data(encrypted_data):
    response = kms_client.decrypt(
        CiphertextBlob=encrypted_data
    )
    decrypted_data = response['Plaintext'].decode('utf-8')  # Decode the decrypted data
    return json.loads(decrypted_data)

# Function to verify JWT and extract meta_data
def process_jwt(jwt_token):
    try:
        # Verify JWT signature and extract payload
        decoded_jwt = jwt.decode(jwt_token, public_key, algorithms=['RS256'], audience='payment-gateway')

        # Decrypt meta_data
        encrypted_meta_data = decoded_jwt['meta_data']
        decrypted_meta_data = decrypt_credit_card_data(encrypted_meta_data)
        
        print(f"Decrypted Credit Card Data: {decrypted_meta_data}")
        
        # Proceed with payment processing logic here...

    except jwt.ExpiredSignatureError:
        print("JWT has expired.")
    except jwt.InvalidTokenError:
        print("Invalid JWT.")

# Example of how to use the process_jwt function
received_jwt_token = 'REPLACE_WITH_RECEIVED_JWT'
process_jwt(received_jwt_token)
