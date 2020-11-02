# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and


# [START kms_create_key_for_import]
def create_key_for_import():
    """
    Generate Cloud KMS-compatible key material locally.

    Args:
      None
    Returns:
        bytes: Locally generated key material in PKCS #8 DER format.
    """

    # Import Python standard cryptographic libraries.
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec


    # Generate some key material in Python and format it in PKCS #8 DER as
    # required by Google Cloud KMS.
    key = ec.generate_private_key(ec.SECP256R1, default_backend())
    return key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())

# [END kms_create_key_for_import]
