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


import google.api_core.grpc_helpers

from google.cloud.kms_v1.proto import service_pb2_grpc
from google.iam.v1 import iam_policy_pb2_grpc as iam_policy_pb2_grpc


class KeyManagementServiceGrpcTransport(object):
    """gRPC transport class providing stubs for
    google.cloud.kms.v1 KeyManagementService API.

    The transport provides access to the raw gRPC stubs,
    which can be used to take advantage of advanced
    features of gRPC.
    """

    # The scopes needed to make gRPC calls to all of the methods defined
    # in this service.
    _OAUTH_SCOPES = (
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/cloudkms",
    )

    def __init__(
        self, channel=None, credentials=None, address="cloudkms.googleapis.com:443"
    ):
        """Instantiate the transport class.

        Args:
            channel (grpc.Channel): A ``Channel`` instance through
                which to make calls. This argument is mutually exclusive
                with ``credentials``; providing both will raise an exception.
            credentials (google.auth.credentials.Credentials): The
                authorization credentials to attach to requests. These
                credentials identify this application to the service. If none
                are specified, the client will attempt to ascertain the
                credentials from the environment.
            address (str): The address where the service is hosted.
        """
        # If both `channel` and `credentials` are specified, raise an
        # exception (channels come with credentials baked in already).
        if channel is not None and credentials is not None:
            raise ValueError(
                "The `channel` and `credentials` arguments are mutually " "exclusive."
            )

        # Create the channel.
        if channel is None:
            channel = self.create_channel(
                address=address,
                credentials=credentials,
                options={
                    "grpc.max_send_message_length": -1,
                    "grpc.max_receive_message_length": -1,
                }.items(),
            )

        self._channel = channel

        # gRPC uses objects called "stubs" that are bound to the
        # channel and provide a basic method for each RPC.
        self._stubs = {
            "key_management_service_stub": service_pb2_grpc.KeyManagementServiceStub(
                channel
            ),
            "iam_policy_stub": iam_policy_pb2_grpc.IAMPolicyStub(channel),
        }

    @classmethod
    def create_channel(
        cls, address="cloudkms.googleapis.com:443", credentials=None, **kwargs
    ):
        """Create and return a gRPC channel object.

        Args:
            address (str): The host for the channel to use.
            credentials (~.Credentials): The
                authorization credentials to attach to requests. These
                credentials identify this application to the service. If
                none are specified, the client will attempt to ascertain
                the credentials from the environment.
            kwargs (dict): Keyword arguments, which are passed to the
                channel creation.

        Returns:
            grpc.Channel: A gRPC channel object.
        """
        return google.api_core.grpc_helpers.create_channel(
            address, credentials=credentials, scopes=cls._OAUTH_SCOPES, **kwargs
        )

    @property
    def channel(self):
        """The gRPC channel used by the transport.

        Returns:
            grpc.Channel: A gRPC channel object.
        """
        return self._channel

    @property
    def list_key_rings(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.list_key_rings`.

        Optional. Optional limit on the number of ``KeyRings`` to include in
        the response. Further ``KeyRings`` can subsequently be obtained by
        including the ``ListKeyRingsResponse.next_page_token`` in a subsequent
        request. If unspecified, the server will pick an appropriate default.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].ListKeyRings

    @property
    def list_import_jobs(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.list_import_jobs`.

        This version is still being generated. It may not be used, enabled,
        disabled, or destroyed yet. Cloud KMS will automatically mark this
        version ``ENABLED`` as soon as the version is ready.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].ListImportJobs

    @property
    def list_crypto_keys(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.list_crypto_keys`.

        The hostname for this service. This should be specified with no
        prefix or protocol.

        Example:

        service Foo { option (google.api.default_host) = "foo.googleapi.com";
        ... }

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].ListCryptoKeys

    @property
    def list_crypto_key_versions(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.list_crypto_key_versions`.

        Required. The resource name of the ``CryptoKeyVersion`` to use for
        decryption.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].ListCryptoKeyVersions

    @property
    def get_key_ring(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.get_key_ring`.

        An ``ImportJob`` can be used to create ``CryptoKeys`` and
        ``CryptoKeyVersions`` using pre-existing key material, generated outside
        of Cloud KMS.

        When an ``ImportJob`` is created, Cloud KMS will generate a "wrapping
        key", which is a public/private key pair. You use the wrapping key to
        encrypt (also known as wrap) the pre-existing key material to protect it
        during the import process. The nature of the wrapping key depends on the
        choice of ``import_method``. When the wrapping key generation is
        complete, the ``state`` will be set to ``ACTIVE`` and the ``public_key``
        can be fetched. The fetched public key can then be used to wrap your
        pre-existing key material.

        Once the key material is wrapped, it can be imported into a new
        ``CryptoKeyVersion`` in an existing ``CryptoKey`` by calling
        ``ImportCryptoKeyVersion``. Multiple ``CryptoKeyVersions`` can be
        imported with a single ``ImportJob``. Cloud KMS uses the private key
        portion of the wrapping key to unwrap the key material. Only Cloud KMS
        has access to the private key.

        An ``ImportJob`` expires 3 days after it is created. Once expired, Cloud
        KMS will no longer be able to import or unwrap any key material that was
        wrapped with the ``ImportJob``'s public key.

        For more information, see `Importing a
        key <https://cloud.google.com/kms/docs/importing-a-key>`__.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].GetKeyRing

    @property
    def get_import_job(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.get_import_job`.

        Required. It must be unique within a KeyRing and match the regular
        expression ``[a-zA-Z0-9_-]{1,63}``

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].GetImportJob

    @property
    def get_crypto_key(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.get_crypto_key`.

        Optional. Optional pagination token, returned earlier via
        ``ListKeyRingsResponse.next_page_token``.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].GetCryptoKey

    @property
    def get_crypto_key_version(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.get_crypto_key_version`.

        Imports a new ``CryptoKeyVersion`` into an existing ``CryptoKey``
        using the wrapped key material provided in the request.

        The version ID will be assigned the next sequential id within the
        ``CryptoKey``.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].GetCryptoKeyVersion

    @property
    def create_key_ring(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.create_key_ring`.

        Required. The resource name of the ``CryptoKeyVersion`` to use for
        signing.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].CreateKeyRing

    @property
    def create_import_job(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.create_import_job`.

        This version is scheduled for destruction, and will be destroyed
        soon. Call ``RestoreCryptoKeyVersion`` to put it back into the
        ``DISABLED`` state.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].CreateImportJob

    @property
    def create_crypto_key(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.create_crypto_key`.

        Optional. Only include resources that match the filter in the
        response. For more information, see `Sorting and filtering list
        results <https://cloud.google.com/kms/docs/sorting-and-filtering>`__.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].CreateCryptoKey

    @property
    def create_crypto_key_version(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.create_crypto_key_version`.

        The custom pattern is used for specifying an HTTP method that is not
        included in the ``pattern`` field, such as HEAD, or "*" to leave the
        HTTP method unspecified for this rule. The wild-card rule is useful for
        services that provide content to Web (HTML) clients.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].CreateCryptoKeyVersion

    @property
    def import_crypto_key_version(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.import_crypto_key_version`.

        Protocol Buffers - Google's data interchange format Copyright 2008
        Google Inc. All rights reserved.
        https://developers.google.com/protocol-buffers/

        Redistribution and use in source and binary forms, with or without
        modification, are permitted provided that the following conditions are
        met:

        ::

            * Redistributions of source code must retain the above copyright

        notice, this list of conditions and the following disclaimer. \*
        Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution. \*
        Neither the name of Google Inc. nor the names of its contributors may be
        used to endorse or promote products derived from this software without
        specific prior written permission.

        THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
        IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
        TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
        PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
        OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
        EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
        PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
        PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
        LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
        NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
        SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].ImportCryptoKeyVersion

    @property
    def update_crypto_key(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.update_crypto_key`.

        Required. A ``CryptoKey`` with initial field values.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].UpdateCryptoKey

    @property
    def update_crypto_key_version(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.update_crypto_key_version`.

        The name of the request field whose value is mapped to the HTTP
        request body, or ``*`` for mapping all request fields not captured by
        the path pattern to the HTTP body, or omitted for not having any HTTP
        request body.

        NOTE: the referred field must be present at the top-level of the request
        message type.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].UpdateCryptoKeyVersion

    @property
    def encrypt(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.encrypt`.

        Required. The digest of the data to sign. The digest must be
        produced with the same digest algorithm as specified by the key
        version's ``algorithm``.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].Encrypt

    @property
    def decrypt(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.decrypt`.

        This version is still being imported. It may not be used, enabled,
        disabled, or destroyed yet. Cloud KMS will automatically mark this
        version ``ENABLED`` as soon as the version is ready.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].Decrypt

    @property
    def update_crypto_key_primary_version(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.update_crypto_key_primary_version`.

        The list of ``CryptoKeyVersions``.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].UpdateCryptoKeyPrimaryVersion

    @property
    def destroy_crypto_key_version(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.destroy_crypto_key_version`.

        This version was not imported successfully. It may not be used,
        enabled, disabled, or destroyed. The submitted key material has been
        discarded. Additional details can be found in
        ``CryptoKeyVersion.import_failure_reason``.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].DestroyCryptoKeyVersion

    @property
    def restore_crypto_key_version(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.restore_crypto_key_version`.

        Request message for ``KeyManagementService.Encrypt``.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].RestoreCryptoKeyVersion

    @property
    def get_public_key(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.get_public_key`.

        The jstype option determines the JavaScript type used for values of
        the field. The option is permitted only for 64 bit integral and fixed
        types (int64, uint64, sint64, fixed64, sfixed64). A field with jstype
        JS_STRING is represented as JavaScript string, which avoids loss of
        precision that can happen when a large value is converted to a floating
        point JavaScript. Specifying JS_NUMBER for the jstype causes the
        generated JavaScript code to use the JavaScript "number" type. The
        behavior of the default option JS_NORMAL is implementation dependent.

        This option is an enum to permit additional types to be added, e.g.
        goog.math.Integer.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].GetPublicKey

    @property
    def asymmetric_decrypt(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.asymmetric_decrypt`.

        Input and output type names. These are resolved in the same way as
        FieldDescriptorProto.type_name, but must refer to a message type.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].AsymmetricDecrypt

    @property
    def asymmetric_sign(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.asymmetric_sign`.

        Optional. Specify how the results should be sorted. If not
        specified, the results will be sorted in the default order. For more
        information, see `Sorting and filtering list
        results <https://cloud.google.com/kms/docs/sorting-and-filtering>`__.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["key_management_service_stub"].AsymmetricSign

    @property
    def set_iam_policy(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.set_iam_policy`.

        Sets the access control policy on the specified resource. Replaces
        any existing policy.

        Can return Public Errors: NOT_FOUND, INVALID_ARGUMENT and
        PERMISSION_DENIED

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["iam_policy_stub"].SetIamPolicy

    @property
    def get_iam_policy(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.get_iam_policy`.

        Gets the access control policy for a resource. Returns an empty policy
        if the resource exists and does not have a policy set.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["iam_policy_stub"].GetIamPolicy

    @property
    def test_iam_permissions(self):
        """Return the gRPC stub for :meth:`KeyManagementServiceClient.test_iam_permissions`.

        Returns permissions that a caller has on the specified resource. If the
        resource does not exist, this will return an empty set of
        permissions, not a NOT_FOUND error.

        Note: This operation is designed to be used for building
        permission-aware UIs and command-line tools, not for authorization
        checking. This operation may "fail open" without warning.

        Returns:
            Callable: A callable which accepts the appropriate
                deserialized request object and returns a
                deserialized response object.
        """
        return self._stubs["iam_policy_stub"].TestIamPermissions
