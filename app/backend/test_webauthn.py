import json
from webauthn.helpers.structs import PublicKeyCredentialDescriptor
from webauthn import generate_authentication_options
from webauthn.helpers import options_to_json, base64url_to_bytes

cred_id = "some-id"
allow_credentials = [
    PublicKeyCredentialDescriptor(id=b'test')
]
options = generate_authentication_options(
    rp_id="localhost",
    allow_credentials=allow_credentials,
)
print(options_to_json(options))
