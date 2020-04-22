# -*- coding: utf-8 -*-
#
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Wrappers for protocol buffer enum types."""

import enum


class ProtectionLevel(enum.IntEnum):
    """
    Request message for ``KeyManagementService.GetImportJob``.

    Attributes:
      PROTECTION_LEVEL_UNSPECIFIED (int): Not specified.
      SOFTWARE (int): Crypto operations are performed in software.
      HSM (int): Crypto operations are performed in a Hardware Security Module.
      EXTERNAL (int): Crypto operations are performed by an external key manager.
    """

    PROTECTION_LEVEL_UNSPECIFIED = 0
    SOFTWARE = 1
    HSM = 2
    EXTERNAL = 3


class CryptoKey(object):
    class CryptoKeyPurpose(enum.IntEnum):
        """
        Encrypts data, so that it can only be recovered by a call to
        ``Decrypt``. The ``CryptoKey.purpose`` must be ``ENCRYPT_DECRYPT``.

        Attributes:
          CRYPTO_KEY_PURPOSE_UNSPECIFIED (int): Not specified.
          ENCRYPT_DECRYPT (int): Required. The ``name`` of the ``KeyRing`` to get.
          ASYMMETRIC_SIGN (int): Specifies the identities requesting access for a Cloud Platform
          resource. ``members`` can have the following values:

          -  ``allUsers``: A special identifier that represents anyone who is on
             the internet; with or without a Google account.

          -  ``allAuthenticatedUsers``: A special identifier that represents
             anyone who is authenticated with a Google account or a service
             account.

          -  ``user:{emailid}``: An email address that represents a specific
             Google account. For example, ``alice@example.com`` .

          -  ``serviceAccount:{emailid}``: An email address that represents a
             service account. For example,
             ``my-other-app@appspot.gserviceaccount.com``.

          -  ``group:{emailid}``: An email address that represents a Google group.
             For example, ``admins@example.com``.

          -  ``domain:{domain}``: The G Suite domain (primary) that represents all
             the users of that domain. For example, ``google.com`` or
             ``example.com``.
          ASYMMETRIC_DECRYPT (int): A subset of ``TestPermissionsRequest.permissions`` that the caller
          is allowed.
        """

        CRYPTO_KEY_PURPOSE_UNSPECIFIED = 0
        ENCRYPT_DECRYPT = 1
        ASYMMETRIC_SIGN = 5
        ASYMMETRIC_DECRYPT = 6


class CryptoKeyVersion(object):
    class CryptoKeyVersionAlgorithm(enum.IntEnum):
        """
        Indicates whether ``CryptoKeys`` with ``protection_level`` ``HSM``
        can be created in this location.

        Attributes:
          CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED (int): Not specified.
          GOOGLE_SYMMETRIC_ENCRYPTION (int): Creates symmetric encryption keys.
          RSA_SIGN_PSS_2048_SHA256 (int): RSASSA-PSS 2048 bit key with a SHA256 digest.
          RSA_SIGN_PSS_3072_SHA256 (int): RSASSA-PSS 3072 bit key with a SHA256 digest.
          RSA_SIGN_PSS_4096_SHA256 (int): RSASSA-PSS 4096 bit key with a SHA256 digest.
          RSA_SIGN_PSS_4096_SHA512 (int): RSASSA-PSS 4096 bit key with a SHA512 digest.
          RSA_SIGN_PKCS1_2048_SHA256 (int): Response message for ``KeyManagementService.AsymmetricSign``.
          RSA_SIGN_PKCS1_3072_SHA256 (int): Specifies the log_type that was be enabled. ADMIN_ACTIVITY is always
          enabled, and cannot be configured. Required
          RSA_SIGN_PKCS1_4096_SHA256 (int): Signs data using a ``CryptoKeyVersion`` with ``CryptoKey.purpose``
          ASYMMETRIC_SIGN, producing a signature that can be verified with the
          public key retrieved from ``GetPublicKey``.
          RSA_SIGN_PKCS1_4096_SHA512 (int): Output only. Statement that was generated and signed by the key
          creator (for example, an HSM) at key creation time. Use this statement
          to verify attributes of the key as stored on the HSM, independently of
          Google. Only present if the chosen ``ImportMethod`` is one with a
          protection level of ``HSM``.
          RSA_DECRYPT_OAEP_2048_SHA256 (int): RSAES-OAEP 2048 bit key with a SHA256 digest.
          RSA_DECRYPT_OAEP_3072_SHA256 (int): RSAES-OAEP 3072 bit key with a SHA256 digest.
          RSA_DECRYPT_OAEP_4096_SHA256 (int): RSAES-OAEP 4096 bit key with a SHA256 digest.
          RSA_DECRYPT_OAEP_4096_SHA512 (int): RSAES-OAEP 4096 bit key with a SHA512 digest.
          EC_SIGN_P256_SHA256 (int): ECDSA on the NIST P-256 curve with a SHA256 digest.
          EC_SIGN_P384_SHA384 (int): ECDSA on the NIST P-384 curve with a SHA384 digest.
          EXTERNAL_SYMMETRIC_ENCRYPTION (int): Algorithm representing symmetric encryption by an external key manager.
        """

        CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED = 0
        GOOGLE_SYMMETRIC_ENCRYPTION = 1
        RSA_SIGN_PSS_2048_SHA256 = 2
        RSA_SIGN_PSS_3072_SHA256 = 3
        RSA_SIGN_PSS_4096_SHA256 = 4
        RSA_SIGN_PSS_4096_SHA512 = 15
        RSA_SIGN_PKCS1_2048_SHA256 = 5
        RSA_SIGN_PKCS1_3072_SHA256 = 6
        RSA_SIGN_PKCS1_4096_SHA256 = 7
        RSA_SIGN_PKCS1_4096_SHA512 = 16
        RSA_DECRYPT_OAEP_2048_SHA256 = 8
        RSA_DECRYPT_OAEP_3072_SHA256 = 9
        RSA_DECRYPT_OAEP_4096_SHA256 = 10
        RSA_DECRYPT_OAEP_4096_SHA512 = 17
        EC_SIGN_P256_SHA256 = 12
        EC_SIGN_P384_SHA384 = 13
        EXTERNAL_SYMMETRIC_ENCRYPTION = 18

    class CryptoKeyVersionState(enum.IntEnum):
        """
        Request message for ``KeyManagementService.GetCryptoKeyVersion``.

        Attributes:
          CRYPTO_KEY_VERSION_STATE_UNSPECIFIED (int): Not specified.
          PENDING_GENERATION (int): Required. The ``name`` of the ``CryptoKeyVersion`` to get.
          ENABLED (int): This version may be used for cryptographic operations.
          DISABLED (int): Required. The data encrypted with the named ``CryptoKeyVersion``'s
          public key using OAEP.
          DESTROYED (int): This version is destroyed, and the key material is no longer stored.
          A version may not leave this state once entered.
          DESTROY_SCHEDULED (int): Response message for ``KeyManagementService.Encrypt``.
          PENDING_IMPORT (int): Defines an Identity and Access Management (IAM) policy. It is used
          to specify access control policies for Cloud Platform resources.

          A ``Policy`` is a collection of ``bindings``. A ``binding`` binds one or
          more ``members`` to a single ``role``. Members can be user accounts,
          service accounts, Google groups, and domains (such as G Suite). A
          ``role`` is a named list of permissions (defined by IAM or configured by
          users). A ``binding`` can optionally specify a ``condition``, which is a
          logic expression that further constrains the role binding based on
          attributes about the request and/or target resource.

          **JSON Example**

          ::

              {
                "bindings": [
                  {
                    "role": "roles/resourcemanager.organizationAdmin",
                    "members": [
                      "user:mike@example.com",
                      "group:admins@example.com",
                      "domain:google.com",
                      "serviceAccount:my-project-id@appspot.gserviceaccount.com"
                    ]
                  },
                  {
                    "role": "roles/resourcemanager.organizationViewer",
                    "members": ["user:eve@example.com"],
                    "condition": {
                      "title": "expirable access",
                      "description": "Does not grant access after Sep 2020",
                      "expression": "request.time <
                      timestamp('2020-10-01T00:00:00.000Z')",
                    }
                  }
                ]
              }

          **YAML Example**

          ::

              bindings:
              - members:
                - user:mike@example.com
                - group:admins@example.com
                - domain:google.com
                - serviceAccount:my-project-id@appspot.gserviceaccount.com
                role: roles/resourcemanager.organizationAdmin
              - members:
                - user:eve@example.com
                role: roles/resourcemanager.organizationViewer
                condition:
                  title: expirable access
                  description: Does not grant access after Sep 2020
                  expression: request.time < timestamp('2020-10-01T00:00:00.000Z')

          For a description of IAM and its features, see the `IAM developer's
          guide <https://cloud.google.com/iam/docs>`__.
          IMPORT_FAILED (int): ``ProtectionLevel`` specifies how cryptographic operations are
          performed. For more information, see [Protection levels]
          (https://cloud.google.com/kms/docs/algorithms#protection_levels).
        """

        CRYPTO_KEY_VERSION_STATE_UNSPECIFIED = 0
        PENDING_GENERATION = 5
        ENABLED = 1
        DISABLED = 2
        DESTROYED = 3
        DESTROY_SCHEDULED = 4
        PENDING_IMPORT = 6
        IMPORT_FAILED = 7

    class CryptoKeyVersionView(enum.IntEnum):
        """
        Decrypts data that was encrypted with a public key retrieved from
        ``GetPublicKey`` corresponding to a ``CryptoKeyVersion`` with
        ``CryptoKey.purpose`` ASYMMETRIC_DECRYPT.

        Attributes:
          CRYPTO_KEY_VERSION_VIEW_UNSPECIFIED (int): A token to retrieve next page of results. Pass this value in
          ``ListCryptoKeysRequest.page_token`` to retrieve the next page of
          results.
          FULL (int): Request message for
          ``KeyManagementService.UpdateCryptoKeyPrimaryVersion``.
        """

        CRYPTO_KEY_VERSION_VIEW_UNSPECIFIED = 0
        FULL = 1


class ImportJob(object):
    class ImportJobState(enum.IntEnum):
        """
        Returns metadata for a given ``CryptoKeyVersion``.

        Attributes:
          IMPORT_JOB_STATE_UNSPECIFIED (int): Not specified.
          PENDING_GENERATION (int): Required. The resource name of the ``CryptoKeyVersion`` to destroy.
          ACTIVE (int): Request message for ``KeyManagementService.CreateKeyRing``.
          EXPIRED (int): This job can no longer be used and may not leave this state once entered.
        """

        IMPORT_JOB_STATE_UNSPECIFIED = 0
        PENDING_GENERATION = 1
        ACTIVE = 2
        EXPIRED = 3

    class ImportMethod(enum.IntEnum):
        """
        The URI for an external resource that this ``CryptoKeyVersion``
        represents.

        Attributes:
          IMPORT_METHOD_UNSPECIFIED (int): Not specified.
          RSA_OAEP_3072_SHA1_AES_256 (int): Schedule a ``CryptoKeyVersion`` for destruction.

          Upon calling this method, ``CryptoKeyVersion.state`` will be set to
          ``DESTROY_SCHEDULED`` and ``destroy_time`` will be set to a time 24
          hours in the future, at which point the ``state`` will be changed to
          ``DESTROYED``, and the key material will be irrevocably destroyed.

          Before the ``destroy_time`` is reached, ``RestoreCryptoKeyVersion`` may
          be called to reverse the process.
          RSA_OAEP_4096_SHA1_AES_256 (int): A list of HTTP configuration rules that apply to individual API
          methods.

          **NOTE:** All service configuration rules follow "last one wins" order.
        """

        IMPORT_METHOD_UNSPECIFIED = 0
        RSA_OAEP_3072_SHA1_AES_256 = 1
        RSA_OAEP_4096_SHA1_AES_256 = 2


class KeyOperationAttestation(object):
    class AttestationFormat(enum.IntEnum):
        """
        Attestation formats provided by the HSM.

        Attributes:
          ATTESTATION_FORMAT_UNSPECIFIED (int): Not specified.
          CAVIUM_V1_COMPRESSED (int): Cavium HSM attestation compressed with gzip. Note that this format is
          defined by Cavium and subject to change at any time.
          CAVIUM_V2_COMPRESSED (int): Cavium HSM attestation V2 compressed with gzip. This is a new format
          introduced in Cavium's version 3.2-08.
        """

        ATTESTATION_FORMAT_UNSPECIFIED = 0
        CAVIUM_V1_COMPRESSED = 3
        CAVIUM_V2_COMPRESSED = 4
