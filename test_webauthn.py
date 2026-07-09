import json
from webauthn.helpers.structs import PublicKeyCredentialDescriptor
from webauthn import generate_authentication_options
from webauthn.helpers import options_to_json

allow_credentials = [
    PublicKeyCredentialDescriptor(id=b'test_id_which_is_not_multiple_of_4_chars')
]
options = generate_authentication_options(
    rp_id="localhost",
    allow_credentials=allow_credentials,
)
print(options_to_json(options))
