import json

import cbor2
from flask import Flask, request
from flask_cors import CORS
from pycardano import Address
from pycose.exceptions import CoseException
from pycose.keys import CoseKey
from pycose.messages import Sign1Message

app = Flask(__name__)
CORS(app, resources={r"*": {"origins": "*"}})

registered_users = [
    'yourstakeaddress',
]


@app.route('/login', methods=['POST'])
def login():
    """
    Simple login endpoint that verifies the signature and the payload.

    The payload is expected to be in the following format:

    {
        "body": {
            "key": "hex",
            "signature": "hex"
        }
    }

    The message is expected to be in the following format:
    account: <address>
    """

    args = request.get_json()

    signature_data = json.loads(args.get('body'))

    print(args)

    key_hex = signature_data.get('key')
    signature_hex = signature_data.get('signature')

    # Convert the key and the signature from hex to bytes
    key_bytes = bytes.fromhex(key_hex)
    signature_bytes = bytes.fromhex(signature_hex)

    # Load the signature from the bytes to cbor
    signature_cbor = cbor2.loads(signature_bytes)

    # Create a COSE message object from the signature
    cose_message = Sign1Message.from_cose_obj(signature_cbor, True)

    # Extract the address from the header
    header_map = cose_message.phdr
    address_hex = header_map['address']
    address = Address.from_primitive(address_hex)

    # Create the COSE key from the key bytes
    cose_key = CoseKey.decode(key_bytes)
    cose_message.key = cose_key

    # verify:
    is_verified = False
    try:
        is_verified = cose_message.verify_signature()
    except (CoseException, ValueError) as err:
        print(err)

    payload = cose_message.payload.decode()
    expected_payload = f'account: {address.encode()}'
    payload_as_expected = payload == expected_payload

    signer_is_registered = address.encode() in registered_users

    is_auth_success = is_verified and payload_as_expected and signer_is_registered

    return {
        'success': is_auth_success,
        'message': '✅ Authentication success!' if is_auth_success else '❌ Authentication failed.'
    }


if __name__ == '__main__':
    app.run()
