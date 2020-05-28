# Copyright 2017 Google, Inc
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

import hashlib
import os
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from google.cloud import kms
from google.cloud.kms_v1.proto import resources_pb2
import pytest

from create_key_asymmetric_decrypt import create_key_asymmetric_decrypt
from create_key_asymmetric_sign import create_key_asymmetric_sign
from create_key_hsm import create_key_hsm
from create_key_labels import create_key_labels
from create_key_ring import create_key_ring
from create_key_rotation_schedule import create_key_rotation_schedule
from create_key_symmetric_encrypt_decrypt import create_key_symmetric_encrypt_decrypt
from create_key_version import create_key_version
from decrypt_asymmetric import decrypt_asymmetric
from decrypt_symmetric import decrypt_symmetric
from destroy_key_version import destroy_key_version
from disable_key_version import disable_key_version
from enable_key_version import enable_key_version
from encrypt_asymmetric import encrypt_asymmetric
from encrypt_symmetric import encrypt_symmetric
from get_key_labels import get_key_labels
from get_key_version_attestation import get_key_version_attestation
from get_public_key import get_public_key
from iam_add_member import iam_add_member
from iam_get_policy import iam_get_policy
from iam_remove_member import iam_remove_member
from quickstart import quickstart
from restore_key_version import restore_key_version
from sign_asymmetric import sign_asymmetric
from update_key_add_rotation import update_key_add_rotation
from update_key_remove_labels import update_key_remove_labels
from update_key_remove_rotation import update_key_remove_rotation
from update_key_set_primary import update_key_set_primary
from update_key_update_labels import update_key_update_labels
from verify_asymmetric_ec import verify_asymmetric_ec
from verify_asymmetric_rsa import verify_asymmetric_rsa


@pytest.fixture(scope="module")
def client():
    return kms.KeyManagementServiceClient()


@pytest.fixture(scope="module")
def project_id():
    return os.environ['GCLOUD_PROJECT']


@pytest.fixture(scope="module")
def location_id():
    return "us-east1"


@pytest.fixture(scope="module")
def key_ring_id(client, project_id, location_id):
    location_name = client.location_path(project_id, location_id)
    key_ring_id = '{}'.format(uuid.uuid4())
    key_ring = client.create_key_ring(location_name, key_ring_id, {})

    yield key_ring_id

    for key in client.list_crypto_keys(key_ring.name):
        if key.rotation_period.seconds > 0 or key.next_rotation_time.seconds > 0:
            # https://github.com/googleapis/gapic-generator-python/issues/364
            updated_key = resources_pb2.CryptoKey()
            updated_key.name = key.name
            update_mask = {'paths': ['rotation_period', 'next_rotation_time']}
            client.update_crypto_key(updated_key, update_mask)

        f = 'state != DESTROYED AND state != DESTROY_SCHEDULED'
        for version in client.list_crypto_key_versions(key.name, filter_=f):
            client.destroy_crypto_key_version(version.name)


@pytest.fixture(scope="module")
def asymmetric_decrypt_key_id(client, project_id, location_id, key_ring_id):
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)
    key_id = '{}'.format(uuid.uuid4())
    key = client.create_crypto_key(key_ring_name, key_id, {
        'purpose': kms.enums.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_DECRYPT,
        'version_template': {
            'algorithm': kms.enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_DECRYPT_OAEP_2048_SHA256
        },
        'labels': {'foo': 'bar', 'zip': 'zap'}
    })
    wait_for_ready(client, '{}/cryptoKeyVersions/1'.format(key.name))
    return key_id


@pytest.fixture(scope="module")
def asymmetric_sign_ec_key_id(client, project_id, location_id, key_ring_id):
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)
    key_id = '{}'.format(uuid.uuid4())
    key = client.create_crypto_key(key_ring_name, key_id, {
        'purpose': kms.enums.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
        'version_template': {
            'algorithm': kms.enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256
        },
        'labels': {'foo': 'bar', 'zip': 'zap'}
    })
    wait_for_ready(client, '{}/cryptoKeyVersions/1'.format(key.name))
    return key_id


@pytest.fixture(scope="module")
def asymmetric_sign_rsa_key_id(client, project_id, location_id, key_ring_id):
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)
    key_id = '{}'.format(uuid.uuid4())
    key = client.create_crypto_key(key_ring_name, key_id, {
        'purpose': kms.enums.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
        'version_template': {
            'algorithm': kms.enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256
        },
        'labels': {'foo': 'bar', 'zip': 'zap'}
    })
    wait_for_ready(client, '{}/cryptoKeyVersions/1'.format(key.name))
    return key_id


@pytest.fixture(scope="module")
def hsm_key_id(client, project_id, location_id, key_ring_id):
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)
    key_id = '{}'.format(uuid.uuid4())
    key = client.create_crypto_key(key_ring_name, key_id, {
        'purpose': kms.enums.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
        'version_template': {
            'algorithm': kms.enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
            'protection_level': kms.enums.ProtectionLevel.HSM
        },
        'labels': {'foo': 'bar', 'zip': 'zap'}
    })
    wait_for_ready(client, '{}/cryptoKeyVersions/1'.format(key.name))
    return key_id


@pytest.fixture(scope="module")
def symmetric_key_id(client, project_id, location_id, key_ring_id):
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)
    key_id = '{}'.format(uuid.uuid4())
    key = client.create_crypto_key(key_ring_name, key_id, {
        'purpose': kms.enums.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
        'version_template': {
            'algorithm': kms.enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
        },
        'labels': {'foo': 'bar', 'zip': 'zap'}
    })
    wait_for_ready(client, '{}/cryptoKeyVersions/1'.format(key.name))
    return key_id


def wait_for_ready(client, key_version_name):
    for i in range(5):
        key_version = client.get_crypto_key_version(key_version_name)
        if key_version.state == kms.enums.CryptoKeyVersion.CryptoKeyVersionState.ENABLED:
            return
        time.sleep(0.1*(i**2))
    pytest.fail('{} not ready'.format(key_version_name))


def test_create_key_asymmetric_decrypt(project_id, location_id, key_ring_id):
    key_id = '{}'.format(uuid.uuid4())
    key = create_key_asymmetric_decrypt(project_id, location_id, key_ring_id, key_id)
    assert key.purpose == kms.enums.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_DECRYPT
    assert key.version_template.algorithm == kms.enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_DECRYPT_OAEP_2048_SHA256


def test_create_key_asymmetric_sign(project_id, location_id, key_ring_id):
    key_id = '{}'.format(uuid.uuid4())
    key = create_key_asymmetric_sign(project_id, location_id, key_ring_id, key_id)
    assert key.purpose == kms.enums.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN
    assert key.version_template.algorithm == kms.enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256


def test_create_key_hsm(project_id, location_id, key_ring_id):
    key_id = '{}'.format(uuid.uuid4())
    key = create_key_hsm(project_id, location_id, key_ring_id, key_id)
    assert key.purpose == kms.enums.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
    assert key.version_template.algorithm == kms.enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    assert key.version_template.protection_level == kms.enums.ProtectionLevel.HSM


def test_create_key_labels(project_id, location_id, key_ring_id):
    key_id = '{}'.format(uuid.uuid4())
    key = create_key_labels(project_id, location_id, key_ring_id, key_id)
    assert key.purpose == kms.enums.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
    assert key.version_template.algorithm == kms.enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    assert key.labels == {'team': 'alpha', 'cost_center': 'cc1234'}


def test_create_key_ring(project_id, location_id):
    key_ring_id = '{}'.format(uuid.uuid4())
    key_ring = create_key_ring(project_id, location_id, key_ring_id)
    assert key_ring


def test_create_key_rotation_schedule(project_id, location_id, key_ring_id):
    key_id = '{}'.format(uuid.uuid4())
    key = create_key_rotation_schedule(project_id, location_id, key_ring_id, key_id)
    assert key.rotation_period.seconds == 60*60*24*30
    assert key.next_rotation_time.seconds > 0


def test_create_key_symmetric_encrypt_decrypt(project_id, location_id, key_ring_id):
    key_id = '{}'.format(uuid.uuid4())
    key = create_key_symmetric_encrypt_decrypt(project_id, location_id, key_ring_id, key_id)
    assert key.purpose == kms.enums.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
    assert key.version_template.algorithm == kms.enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION


def test_create_key_version(project_id, location_id, key_ring_id, symmetric_key_id):
    version = create_key_version(project_id, location_id, key_ring_id, symmetric_key_id)
    assert version


def test_decrypt_asymmetric(client, project_id, location_id, key_ring_id, asymmetric_decrypt_key_id):
    message = 'my message'.encode('utf-8')

    key_version_name = client.crypto_key_version_path(project_id, location_id, key_ring_id, asymmetric_decrypt_key_id, '1')
    public_key = client.get_public_key(key_version_name)

    pem = public_key.pem.encode('utf-8')
    rsa_key = serialization.load_pem_public_key(pem, default_backend())

    pad = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                       algorithm=hashes.SHA256(),
                       label=None)
    ciphertext = rsa_key.encrypt(message, pad)

    response = decrypt_asymmetric(project_id, location_id, key_ring_id, asymmetric_decrypt_key_id, '1', ciphertext)
    assert response.plaintext == message


def test_decrypt_symmetric(client, project_id, location_id, key_ring_id, symmetric_key_id):
    plaintext = 'my message'.encode('utf-8')

    key_version_name = client.crypto_key_path(project_id, location_id, key_ring_id, symmetric_key_id)
    encrypt_response = client.encrypt(key_version_name, plaintext)
    ciphertext = encrypt_response.ciphertext

    decrypt_response = decrypt_symmetric(project_id, location_id, key_ring_id, symmetric_key_id, ciphertext)
    assert decrypt_response.plaintext == plaintext


def test_destroy_restore_key_version(client, project_id, location_id, key_ring_id, asymmetric_decrypt_key_id):
    key_name = client.crypto_key_path(project_id, location_id, key_ring_id, asymmetric_decrypt_key_id)
    version = client.create_crypto_key_version(key_name, {})
    version_id = version.name.split('/')[-1]

    wait_for_ready(client, version.name)

    destroyed_version = destroy_key_version(project_id, location_id, key_ring_id, asymmetric_decrypt_key_id, version_id)
    assert destroyed_version.state == kms.enums.CryptoKeyVersion.CryptoKeyVersionState.DESTROY_SCHEDULED

    restored_version = restore_key_version(project_id, location_id, key_ring_id, asymmetric_decrypt_key_id, version_id)
    assert restored_version.state == kms.enums.CryptoKeyVersion.CryptoKeyVersionState.DISABLED


def test_disable_enable_key_version(client, project_id, location_id, key_ring_id, asymmetric_decrypt_key_id):
    key_name = client.crypto_key_path(project_id, location_id, key_ring_id, asymmetric_decrypt_key_id)
    version = client.create_crypto_key_version(key_name, {})
    version_id = version.name.split('/')[-1]

    wait_for_ready(client, version.name)

    disabled_version = disable_key_version(project_id, location_id, key_ring_id, asymmetric_decrypt_key_id, version_id)
    assert disabled_version.state == kms.enums.CryptoKeyVersion.CryptoKeyVersionState.DISABLED

    enabled_version = enable_key_version(project_id, location_id, key_ring_id, asymmetric_decrypt_key_id, version_id)
    assert enabled_version.state == kms.enums.CryptoKeyVersion.CryptoKeyVersionState.ENABLED


def test_encrypt_asymmetric(client, project_id, location_id, key_ring_id, asymmetric_decrypt_key_id):
    plaintext = 'my message'
    ciphertext = encrypt_asymmetric(project_id, location_id, key_ring_id, asymmetric_decrypt_key_id, '1', plaintext)

    key_version_name = client.crypto_key_version_path(project_id, location_id, key_ring_id, asymmetric_decrypt_key_id, '1')
    response = client.asymmetric_decrypt(key_version_name, ciphertext)
    assert response.plaintext == plaintext.encode('utf-8')


def test_encrypt_symmetric(client, project_id, location_id, key_ring_id, symmetric_key_id):
    plaintext = 'my message'
    encrypt_response = encrypt_symmetric(project_id, location_id, key_ring_id, symmetric_key_id, plaintext)

    key_name = client.crypto_key_path(project_id, location_id, key_ring_id, symmetric_key_id)
    decrypt_response = client.decrypt(key_name, encrypt_response.ciphertext)
    assert decrypt_response.plaintext == plaintext.encode('utf-8')


def test_get_key_labels(project_id, location_id, key_ring_id, symmetric_key_id):
    key = get_key_labels(project_id, location_id, key_ring_id, symmetric_key_id)
    assert key.labels == {'foo': 'bar', 'zip': 'zap'}


def test_get_key_version_attestation(project_id, location_id, key_ring_id, hsm_key_id):
    attestation = get_key_version_attestation(project_id, location_id, key_ring_id, hsm_key_id, '1')
    assert attestation.format
    assert attestation.content


def test_get_public_key(project_id, location_id, key_ring_id, asymmetric_decrypt_key_id):
    public_key = get_public_key(project_id, location_id, key_ring_id, asymmetric_decrypt_key_id, '1')
    assert public_key.pem


def test_iam_add_member(project_id, location_id, key_ring_id, symmetric_key_id):
    member = 'group:test@google.com'
    policy = iam_add_member(project_id, location_id, key_ring_id, symmetric_key_id, member)
    assert any(member in b.members for b in policy.bindings)


def test_iam_get_policy(project_id, location_id, key_ring_id, symmetric_key_id):
    policy = iam_get_policy(project_id, location_id, key_ring_id, symmetric_key_id)
    assert policy


def test_iam_remove_member(client, project_id, location_id, key_ring_id, asymmetric_sign_rsa_key_id):
    resource_name = client.crypto_key_path(project_id, location_id, key_ring_id, asymmetric_sign_rsa_key_id)

    policy = client.get_iam_policy(resource_name)
    policy.bindings.add(
        role='roles/cloudkms.cryptoKeyEncrypterDecrypter',
        members=['group:test@google.com', 'group:tester@google.com'])
    client.set_iam_policy(resource_name, policy)

    policy = iam_remove_member(project_id, location_id, key_ring_id, asymmetric_sign_rsa_key_id, 'group:test@google.com')
    assert not any('group:test@google.com' in b.members for b in policy.bindings)
    assert any('group:tester@google.com' in b.members for b in policy.bindings)


def test_sign_asymmetric(client, project_id, location_id, key_ring_id, asymmetric_sign_rsa_key_id):
    message = 'my message'

    sign_response = sign_asymmetric(project_id, location_id, key_ring_id, asymmetric_sign_rsa_key_id, '1', message)
    assert sign_response.signature

    key_version_name = client.crypto_key_version_path(project_id, location_id, key_ring_id, asymmetric_sign_rsa_key_id, '1')
    public_key = client.get_public_key(key_version_name)
    pem = public_key.pem.encode('utf-8')
    rsa_key = serialization.load_pem_public_key(pem, default_backend())
    hash_ = hashlib.sha256(message.encode('utf-8')).digest()

    try:
        sha256 = hashes.SHA256()
        pad = padding.PKCS1v15()
        rsa_key.verify(sign_response.signature, hash_, pad, utils.Prehashed(sha256))
    except InvalidSignature:
        pytest.fail('invalid signature')


def test_update_key_add_rotation(project_id, location_id, key_ring_id, symmetric_key_id):
    key = update_key_add_rotation(project_id, location_id, key_ring_id, symmetric_key_id)
    assert key.rotation_period.seconds == 60*60*24*30
    assert key.next_rotation_time.seconds > 0


def test_update_key_remove_labels(project_id, location_id, key_ring_id, symmetric_key_id):
    key = update_key_remove_labels(project_id, location_id, key_ring_id, symmetric_key_id)
    assert key.labels == {}


def test_update_key_remove_rotation(project_id, location_id, key_ring_id, symmetric_key_id):
    key = update_key_remove_rotation(project_id, location_id, key_ring_id, symmetric_key_id)
    assert key.rotation_period.seconds == 0
    assert key.next_rotation_time.seconds == 0


def test_update_key_set_primary(project_id, location_id, key_ring_id, symmetric_key_id):
    key = update_key_set_primary(project_id, location_id, key_ring_id, symmetric_key_id, '1')
    assert '1' in key.primary.name


def test_update_key_update_labels(project_id, location_id, key_ring_id, symmetric_key_id):
    key = update_key_update_labels(project_id, location_id, key_ring_id, symmetric_key_id)
    assert key.labels == {'new_label': 'new_value'}


def test_verify_asymmetric_ec(client, project_id, location_id, key_ring_id, asymmetric_sign_ec_key_id):
    message = 'my message'

    key_version_name = client.crypto_key_version_path(project_id, location_id, key_ring_id, asymmetric_sign_ec_key_id, '1')
    hash_ = hashlib.sha256(message.encode('utf-8')).digest()
    sign_response = client.asymmetric_sign(key_version_name, {'sha256': hash_})

    verified = verify_asymmetric_ec(project_id, location_id, key_ring_id, asymmetric_sign_ec_key_id, '1', message, sign_response.signature)
    assert verified


def test_verify_asymmetric_rsa(client, project_id, location_id, key_ring_id, asymmetric_sign_rsa_key_id):
    message = 'my message'

    key_version_name = client.crypto_key_version_path(project_id, location_id, key_ring_id, asymmetric_sign_rsa_key_id, '1')
    hash_ = hashlib.sha256(message.encode('utf-8')).digest()
    sign_response = client.asymmetric_sign(key_version_name, {'sha256': hash_})

    verified = verify_asymmetric_rsa(project_id, location_id, key_ring_id, asymmetric_sign_rsa_key_id, '1', message, sign_response.signature)
    assert verified


def test_quickstart(project_id, location_id):
    key_rings = quickstart(project_id, location_id)
    assert key_rings
