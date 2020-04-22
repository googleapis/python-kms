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

"""Accesses the google.cloud.kms.v1 KeyManagementService API."""

import functools
import pkg_resources
import warnings

from google.oauth2 import service_account
import google.api_core.client_options
import google.api_core.gapic_v1.client_info
import google.api_core.gapic_v1.config
import google.api_core.gapic_v1.method
import google.api_core.gapic_v1.routing_header
import google.api_core.grpc_helpers
import google.api_core.page_iterator
import google.api_core.path_template
import google.api_core.protobuf_helpers
import grpc

from google.cloud.kms_v1.gapic import enums
from google.cloud.kms_v1.gapic import key_management_service_client_config
from google.cloud.kms_v1.gapic.transports import key_management_service_grpc_transport
from google.cloud.kms_v1.proto import resources_pb2
from google.cloud.kms_v1.proto import service_pb2
from google.cloud.kms_v1.proto import service_pb2_grpc
from google.iam.v1 import iam_policy_pb2
from google.iam.v1 import iam_policy_pb2_grpc
from google.iam.v1 import options_pb2
from google.iam.v1 import policy_pb2
from google.protobuf import field_mask_pb2


_GAPIC_LIBRARY_VERSION = pkg_resources.get_distribution("google-cloud-kms").version


class KeyManagementServiceClient(object):
    """Request message for ``SetIamPolicy`` method."""

    SERVICE_ADDRESS = "cloudkms.googleapis.com:443"
    """The default address of the service."""

    # The name of the interface for this client. This is the key used to
    # find the method configuration in the client_config dictionary.
    _INTERFACE_NAME = "google.cloud.kms.v1.KeyManagementService"

    @classmethod
    def from_service_account_file(cls, filename, *args, **kwargs):
        """Creates an instance of this client using the provided credentials
        file.

        Args:
            filename (str): The path to the service account private key json
                file.
            args: Additional arguments to pass to the constructor.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            KeyManagementServiceClient: The constructed client.
        """
        credentials = service_account.Credentials.from_service_account_file(filename)
        kwargs["credentials"] = credentials
        return cls(*args, **kwargs)

    from_service_account_json = from_service_account_file

    @classmethod
    def crypto_key_path(cls, project, location, key_ring, crypto_key):
        """Return a fully-qualified crypto_key string."""
        return google.api_core.path_template.expand(
            "projects/{project}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{crypto_key}",
            project=project,
            location=location,
            key_ring=key_ring,
            crypto_key=crypto_key,
        )

    @classmethod
    def crypto_key_path_path(cls, project, location, key_ring, crypto_key_path):
        """Return a fully-qualified crypto_key_path string."""
        return google.api_core.path_template.expand(
            "projects/{project}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{crypto_key_path=**}",
            project=project,
            location=location,
            key_ring=key_ring,
            crypto_key_path=crypto_key_path,
        )

    @classmethod
    def crypto_key_version_path(
        cls, project, location, key_ring, crypto_key, crypto_key_version
    ):

        """Return a fully-qualified crypto_key_version string."""
        return google.api_core.path_template.expand(
            "projects/{project}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{crypto_key}/cryptoKeyVersions/{crypto_key_version}",
            project=project,
            location=location,
            key_ring=key_ring,
            crypto_key=crypto_key,
            crypto_key_version=crypto_key_version,
        )

    @classmethod
    def import_job_path(cls, project, location, key_ring, import_job):
        """Return a fully-qualified import_job string."""
        return google.api_core.path_template.expand(
            "projects/{project}/locations/{location}/keyRings/{key_ring}/importJobs/{import_job}",
            project=project,
            location=location,
            key_ring=key_ring,
            import_job=import_job,
        )

    @classmethod
    def key_ring_path(cls, project, location, key_ring):
        """Return a fully-qualified key_ring string."""
        return google.api_core.path_template.expand(
            "projects/{project}/locations/{location}/keyRings/{key_ring}",
            project=project,
            location=location,
            key_ring=key_ring,
        )

    @classmethod
    def location_path(cls, project, location):
        """Return a fully-qualified location string."""
        return google.api_core.path_template.expand(
            "projects/{project}/locations/{location}",
            project=project,
            location=location,
        )

    def __init__(
        self,
        transport=None,
        channel=None,
        credentials=None,
        client_config=None,
        client_info=None,
        client_options=None,
    ):
        """Constructor.

        Args:
            transport (Union[~.KeyManagementServiceGrpcTransport,
                    Callable[[~.Credentials, type], ~.KeyManagementServiceGrpcTransport]): A transport
                instance, responsible for actually making the API calls.
                The default transport uses the gRPC protocol.
                This argument may also be a callable which returns a
                transport instance. Callables will be sent the credentials
                as the first argument and the default transport class as
                the second argument.
            channel (grpc.Channel): DEPRECATED. A ``Channel`` instance
                through which to make calls. This argument is mutually exclusive
                with ``credentials``; providing both will raise an exception.
            credentials (google.auth.credentials.Credentials): The
                authorization credentials to attach to requests. These
                credentials identify this application to the service. If none
                are specified, the client will attempt to ascertain the
                credentials from the environment.
                This argument is mutually exclusive with providing a
                transport instance to ``transport``; doing so will raise
                an exception.
            client_config (dict): DEPRECATED. A dictionary of call options for
                each method. If not specified, the default configuration is used.
            client_info (google.api_core.gapic_v1.client_info.ClientInfo):
                The client info used to send a user-agent string along with
                API requests. If ``None``, then default info will be used.
                Generally, you only need to set this if you're developing
                your own client library.
            client_options (Union[dict, google.api_core.client_options.ClientOptions]):
                Client options used to set user options on the client. API Endpoint
                should be set through client_options.
        """
        # Raise deprecation warnings for things we want to go away.
        if client_config is not None:
            warnings.warn(
                "The `client_config` argument is deprecated.",
                PendingDeprecationWarning,
                stacklevel=2,
            )
        else:
            client_config = key_management_service_client_config.config

        if channel:
            warnings.warn(
                "The `channel` argument is deprecated; use " "`transport` instead.",
                PendingDeprecationWarning,
                stacklevel=2,
            )

        api_endpoint = self.SERVICE_ADDRESS
        if client_options:
            if type(client_options) == dict:
                client_options = google.api_core.client_options.from_dict(
                    client_options
                )
            if client_options.api_endpoint:
                api_endpoint = client_options.api_endpoint

        # Instantiate the transport.
        # The transport is responsible for handling serialization and
        # deserialization and actually sending data to the service.
        if transport:
            if callable(transport):
                self.transport = transport(
                    credentials=credentials,
                    default_class=key_management_service_grpc_transport.KeyManagementServiceGrpcTransport,
                    address=api_endpoint,
                )
            else:
                if credentials:
                    raise ValueError(
                        "Received both a transport instance and "
                        "credentials; these are mutually exclusive."
                    )
                self.transport = transport
        else:
            self.transport = key_management_service_grpc_transport.KeyManagementServiceGrpcTransport(
                address=api_endpoint, channel=channel, credentials=credentials
            )

        if client_info is None:
            client_info = google.api_core.gapic_v1.client_info.ClientInfo(
                gapic_version=_GAPIC_LIBRARY_VERSION
            )
        else:
            client_info.gapic_version = _GAPIC_LIBRARY_VERSION
        self._client_info = client_info

        # Parse out the default settings for retry and timeout for each RPC
        # from the client configuration.
        # (Ordinarily, these are the defaults specified in the `*_config.py`
        # file next to this one.)
        self._method_configs = google.api_core.gapic_v1.config.parse_method_configs(
            client_config["interfaces"][self._INTERFACE_NAME]
        )

        # Save a dictionary of cached API call functions.
        # These are the actual callables which invoke the proper
        # transport methods, wrapped with `wrap_method` to add retry,
        # timeout, and the like.
        self._inner_api_calls = {}

    # Service calls
    def list_key_rings(
        self,
        parent,
        page_size=None,
        filter_=None,
        order_by=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Optional. Optional limit on the number of ``KeyRings`` to include in
        the response. Further ``KeyRings`` can subsequently be obtained by
        including the ``ListKeyRingsResponse.next_page_token`` in a subsequent
        request. If unspecified, the server will pick an appropriate default.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> parent = client.location_path('[PROJECT]', '[LOCATION]')
            >>>
            >>> # Iterate over all results
            >>> for element in client.list_key_rings(parent):
            ...     # process element
            ...     pass
            >>>
            >>>
            >>> # Alternatively:
            >>>
            >>> # Iterate over results one page at a time
            >>> for page in client.list_key_rings(parent).pages:
            ...     for element in page:
            ...         # process element
            ...         pass

        Args:
            parent (str): A view for ``CryptoKeyVersion``\ s. Controls the level of detail
                returned for ``CryptoKeyVersions`` in
                ``KeyManagementService.ListCryptoKeyVersions`` and
                ``KeyManagementService.ListCryptoKeys``.
            page_size (int): The maximum number of resources contained in the
                underlying API response. If page streaming is performed per-
                resource, this parameter does not affect the return value. If page
                streaming is performed per-page, this determines the maximum number
                of resources in a page.
            filter_ (str): Default view for each ``CryptoKeyVersion``. Does not include the
                ``attestation`` field.
            order_by (str): Required. The resource name of the ``KeyRing`` to list, in the
                format ``projects/*/locations/*/keyRings/*``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.api_core.page_iterator.PageIterator` instance.
            An iterable of :class:`~google.cloud.kms_v1.types.KeyRing` instances.
            You can also iterate over the pages of the response
            using its `pages` property.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "list_key_rings" not in self._inner_api_calls:
            self._inner_api_calls[
                "list_key_rings"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.list_key_rings,
                default_retry=self._method_configs["ListKeyRings"].retry,
                default_timeout=self._method_configs["ListKeyRings"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.ListKeyRingsRequest(
            parent=parent, page_size=page_size, filter=filter_, order_by=order_by
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        iterator = google.api_core.page_iterator.GRPCIterator(
            client=None,
            method=functools.partial(
                self._inner_api_calls["list_key_rings"],
                retry=retry,
                timeout=timeout,
                metadata=metadata,
            ),
            request=request,
            items_field="key_rings",
            request_token_field="page_token",
            response_token_field="next_page_token",
        )
        return iterator

    def list_import_jobs(
        self,
        parent,
        page_size=None,
        filter_=None,
        order_by=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        This version is still being generated. It may not be used, enabled,
        disabled, or destroyed yet. Cloud KMS will automatically mark this
        version ``ENABLED`` as soon as the version is ready.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> parent = client.key_ring_path('[PROJECT]', '[LOCATION]', '[KEY_RING]')
            >>>
            >>> # Iterate over all results
            >>> for element in client.list_import_jobs(parent):
            ...     # process element
            ...     pass
            >>>
            >>>
            >>> # Alternatively:
            >>>
            >>> # Iterate over results one page at a time
            >>> for page in client.list_import_jobs(parent).pages:
            ...     for element in page:
            ...         # process element
            ...         pass

        Args:
            parent (str): Request message for ``KeyManagementService.ImportCryptoKeyVersion``.
            page_size (int): The maximum number of resources contained in the
                underlying API response. If page streaming is performed per-
                resource, this parameter does not affect the return value. If page
                streaming is performed per-page, this determines the maximum number
                of resources in a page.
            filter_ (str): Response message for ``TestIamPermissions`` method.
            order_by (str): OPTIONAL: A ``GetPolicyOptions`` object for specifying options to
                ``GetIamPolicy``. This field is only used by Cloud IAM.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.api_core.page_iterator.PageIterator` instance.
            An iterable of :class:`~google.cloud.kms_v1.types.ImportJob` instances.
            You can also iterate over the pages of the response
            using its `pages` property.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "list_import_jobs" not in self._inner_api_calls:
            self._inner_api_calls[
                "list_import_jobs"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.list_import_jobs,
                default_retry=self._method_configs["ListImportJobs"].retry,
                default_timeout=self._method_configs["ListImportJobs"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.ListImportJobsRequest(
            parent=parent, page_size=page_size, filter=filter_, order_by=order_by
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        iterator = google.api_core.page_iterator.GRPCIterator(
            client=None,
            method=functools.partial(
                self._inner_api_calls["list_import_jobs"],
                retry=retry,
                timeout=timeout,
                metadata=metadata,
            ),
            request=request,
            items_field="import_jobs",
            request_token_field="page_token",
            response_token_field="next_page_token",
        )
        return iterator

    def list_crypto_keys(
        self,
        parent,
        page_size=None,
        version_view=None,
        filter_=None,
        order_by=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        The hostname for this service. This should be specified with no
        prefix or protocol.

        Example:

        service Foo { option (google.api.default_host) = "foo.googleapi.com";
        ... }

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> parent = client.key_ring_path('[PROJECT]', '[LOCATION]', '[KEY_RING]')
            >>>
            >>> # Iterate over all results
            >>> for element in client.list_crypto_keys(parent):
            ...     # process element
            ...     pass
            >>>
            >>>
            >>> # Alternatively:
            >>>
            >>> # Iterate over results one page at a time
            >>> for page in client.list_crypto_keys(parent).pages:
            ...     for element in page:
            ...         # process element
            ...         pass

        Args:
            parent (str): Request message for ``TestIamPermissions`` method.
            page_size (int): The maximum number of resources contained in the
                underlying API response. If page streaming is performed per-
                resource, this parameter does not affect the return value. If page
                streaming is performed per-page, this determines the maximum number
                of resources in a page.
            version_view (~google.cloud.kms_v1.types.CryptoKeyVersionView): The fields of the primary version to include in the response.
            filter_ (str): A ``Digest`` holds a cryptographic message digest.
            order_by (str): Output only. The resource name for this ``CryptoKeyVersion`` in the
                format
                ``projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.api_core.page_iterator.PageIterator` instance.
            An iterable of :class:`~google.cloud.kms_v1.types.CryptoKey` instances.
            You can also iterate over the pages of the response
            using its `pages` property.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "list_crypto_keys" not in self._inner_api_calls:
            self._inner_api_calls[
                "list_crypto_keys"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.list_crypto_keys,
                default_retry=self._method_configs["ListCryptoKeys"].retry,
                default_timeout=self._method_configs["ListCryptoKeys"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.ListCryptoKeysRequest(
            parent=parent,
            page_size=page_size,
            version_view=version_view,
            filter=filter_,
            order_by=order_by,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        iterator = google.api_core.page_iterator.GRPCIterator(
            client=None,
            method=functools.partial(
                self._inner_api_calls["list_crypto_keys"],
                retry=retry,
                timeout=timeout,
                metadata=metadata,
            ),
            request=request,
            items_field="crypto_keys",
            request_token_field="page_token",
            response_token_field="next_page_token",
        )
        return iterator

    def list_crypto_key_versions(
        self,
        parent,
        page_size=None,
        view=None,
        filter_=None,
        order_by=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Required. The resource name of the ``CryptoKeyVersion`` to use for
        decryption.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> parent = client.crypto_key_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[CRYPTO_KEY]')
            >>>
            >>> # Iterate over all results
            >>> for element in client.list_crypto_key_versions(parent):
            ...     # process element
            ...     pass
            >>>
            >>>
            >>> # Alternatively:
            >>>
            >>> # Iterate over results one page at a time
            >>> for page in client.list_crypto_key_versions(parent).pages:
            ...     for element in page:
            ...         # process element
            ...         pass

        Args:
            parent (str): Required. Immutable. The protection level of the ``ImportJob``. This
                must match the ``protection_level`` of the ``version_template`` on the
                ``CryptoKey`` you attempt to import into.
            page_size (int): The maximum number of resources contained in the
                underlying API response. If page streaming is performed per-
                resource, this parameter does not affect the return value. If page
                streaming is performed per-page, this determines the maximum number
                of resources in a page.
            view (~google.cloud.kms_v1.types.CryptoKeyVersionView): The fields to include in the response.
            filter_ (str): The current state of the ``CryptoKeyVersion``.
            order_by (str): Optional. Optional pagination token, returned earlier via
                ``ListCryptoKeysResponse.next_page_token``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.api_core.page_iterator.PageIterator` instance.
            An iterable of :class:`~google.cloud.kms_v1.types.CryptoKeyVersion` instances.
            You can also iterate over the pages of the response
            using its `pages` property.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "list_crypto_key_versions" not in self._inner_api_calls:
            self._inner_api_calls[
                "list_crypto_key_versions"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.list_crypto_key_versions,
                default_retry=self._method_configs["ListCryptoKeyVersions"].retry,
                default_timeout=self._method_configs["ListCryptoKeyVersions"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.ListCryptoKeyVersionsRequest(
            parent=parent,
            page_size=page_size,
            view=view,
            filter=filter_,
            order_by=order_by,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        iterator = google.api_core.page_iterator.GRPCIterator(
            client=None,
            method=functools.partial(
                self._inner_api_calls["list_crypto_key_versions"],
                retry=retry,
                timeout=timeout,
                metadata=metadata,
            ),
            request=request,
            items_field="crypto_key_versions",
            request_token_field="page_token",
            response_token_field="next_page_token",
        )
        return iterator

    def get_key_ring(
        self,
        name,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
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

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> name = client.key_ring_path('[PROJECT]', '[LOCATION]', '[KEY_RING]')
            >>>
            >>> response = client.get_key_ring(name)

        Args:
            name (str): Wrapped key material produced with ``RSA_OAEP_3072_SHA1_AES_256`` or
                ``RSA_OAEP_4096_SHA1_AES_256``.

                This field contains the concatenation of two wrapped keys:

                .. raw:: html

                    <ol>
                      <li>An ephemeral AES-256 wrapping key wrapped with the
                          `public_key` using RSAES-OAEP with SHA-1,
                          MGF1 with SHA-1, and an empty label.
                      </li>
                      <li>The key to be imported, wrapped with the ephemeral AES-256 key
                          using AES-KWP (RFC 5649).
                      </li>
                    </ol>

                If importing symmetric key material, it is expected that the unwrapped
                key contains plain bytes. If importing asymmetric key material, it is
                expected that the unwrapped key is in PKCS#8-encoded DER format (the
                PrivateKeyInfo structure from RFC 5208).

                This format is the same as the format produced by PKCS#11 mechanism
                CKM_RSA_AES_KEY_WRAP.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.KeyRing` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "get_key_ring" not in self._inner_api_calls:
            self._inner_api_calls[
                "get_key_ring"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.get_key_ring,
                default_retry=self._method_configs["GetKeyRing"].retry,
                default_timeout=self._method_configs["GetKeyRing"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.GetKeyRingRequest(name=name)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["get_key_ring"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def get_import_job(
        self,
        name,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Required. It must be unique within a KeyRing and match the regular
        expression ``[a-zA-Z0-9_-]{1,63}``

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> name = client.import_job_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[IMPORT_JOB]')
            >>>
            >>> response = client.get_import_job(name)

        Args:
            name (str): Lists ``CryptoKeys``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.ImportJob` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "get_import_job" not in self._inner_api_calls:
            self._inner_api_calls[
                "get_import_job"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.get_import_job,
                default_retry=self._method_configs["GetImportJob"].retry,
                default_timeout=self._method_configs["GetImportJob"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.GetImportJobRequest(name=name)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["get_import_job"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def get_crypto_key(
        self,
        name,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Optional. Optional pagination token, returned earlier via
        ``ListKeyRingsResponse.next_page_token``.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> name = client.crypto_key_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[CRYPTO_KEY]')
            >>>
            >>> response = client.get_crypto_key(name)

        Args:
            name (str): Output only. The time this ``CryptoKeyVersion``'s key material was
                generated.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.CryptoKey` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "get_crypto_key" not in self._inner_api_calls:
            self._inner_api_calls[
                "get_crypto_key"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.get_crypto_key,
                default_retry=self._method_configs["GetCryptoKey"].retry,
                default_timeout=self._method_configs["GetCryptoKey"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.GetCryptoKeyRequest(name=name)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["get_crypto_key"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def get_crypto_key_version(
        self,
        name,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Imports a new ``CryptoKeyVersion`` into an existing ``CryptoKey``
        using the wrapped key material provided in the request.

        The version ID will be assigned the next sequential id within the
        ``CryptoKey``.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> name = client.crypto_key_version_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[CRYPTO_KEY]', '[CRYPTO_KEY_VERSION]')
            >>>
            >>> response = client.get_crypto_key_version(name)

        Args:
            name (str): Request message for ``KeyManagementService.CreateImportJob``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.CryptoKeyVersion` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "get_crypto_key_version" not in self._inner_api_calls:
            self._inner_api_calls[
                "get_crypto_key_version"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.get_crypto_key_version,
                default_retry=self._method_configs["GetCryptoKeyVersion"].retry,
                default_timeout=self._method_configs["GetCryptoKeyVersion"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.GetCryptoKeyVersionRequest(name=name)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["get_crypto_key_version"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def create_key_ring(
        self,
        parent,
        key_ring_id,
        key_ring,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Required. The resource name of the ``CryptoKeyVersion`` to use for
        signing.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> parent = client.location_path('[PROJECT]', '[LOCATION]')
            >>>
            >>> # TODO: Initialize `key_ring_id`:
            >>> key_ring_id = ''
            >>>
            >>> # TODO: Initialize `key_ring`:
            >>> key_ring = {}
            >>>
            >>> response = client.create_key_ring(parent, key_ring_id, key_ring)

        Args:
            parent (str): Optional. Optional pagination token, returned earlier via
                ``ListCryptoKeyVersionsResponse.next_page_token``.
            key_ring_id (str): Output only. The time at which this ``ImportJob`` was created.
            key_ring (Union[dict, ~google.cloud.kms_v1.types.KeyRing]): Output only. The time this CryptoKeyVersion's key material was
                destroyed. Only present if ``state`` is ``DESTROYED``.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.kms_v1.types.KeyRing`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.KeyRing` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "create_key_ring" not in self._inner_api_calls:
            self._inner_api_calls[
                "create_key_ring"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.create_key_ring,
                default_retry=self._method_configs["CreateKeyRing"].retry,
                default_timeout=self._method_configs["CreateKeyRing"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.CreateKeyRingRequest(
            parent=parent, key_ring_id=key_ring_id, key_ring=key_ring
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["create_key_ring"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def create_import_job(
        self,
        parent,
        import_job_id,
        import_job,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        This version is scheduled for destruction, and will be destroyed
        soon. Call ``RestoreCryptoKeyVersion`` to put it back into the
        ``DISABLED`` state.

        Example:
            >>> from google.cloud import kms_v1
            >>> from google.cloud.kms_v1 import enums
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> parent = client.key_ring_path('[PROJECT]', '[LOCATION]', '[KEY_RING]')
            >>> import_job_id = 'my-import-job'
            >>> import_method = enums.ImportJob.ImportMethod.RSA_OAEP_3072_SHA1_AES_256
            >>> protection_level = enums.ProtectionLevel.HSM
            >>> import_job = {'import_method': import_method, 'protection_level': protection_level}
            >>>
            >>> response = client.create_import_job(parent, import_job_id, import_job)

        Args:
            parent (str): Output only. The time at which this ``CryptoKeyVersion``'s key
                material was imported.
            import_job_id (str): Required. ``CryptoKey`` with updated values.
            import_job (Union[dict, ~google.cloud.kms_v1.types.ImportJob]): Optional. Specify how the results should be sorted. If not
                specified, the results will be sorted in the default order. For more
                information, see `Sorting and filtering list
                results <https://cloud.google.com/kms/docs/sorting-and-filtering>`__.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.kms_v1.types.ImportJob`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.ImportJob` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "create_import_job" not in self._inner_api_calls:
            self._inner_api_calls[
                "create_import_job"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.create_import_job,
                default_retry=self._method_configs["CreateImportJob"].retry,
                default_timeout=self._method_configs["CreateImportJob"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.CreateImportJobRequest(
            parent=parent, import_job_id=import_job_id, import_job=import_job
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["create_import_job"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def create_crypto_key(
        self,
        parent,
        crypto_key_id,
        crypto_key,
        skip_initial_version_creation=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Optional. Only include resources that match the filter in the
        response. For more information, see `Sorting and filtering list
        results <https://cloud.google.com/kms/docs/sorting-and-filtering>`__.

        Example:
            >>> from google.cloud import kms_v1
            >>> from google.cloud.kms_v1 import enums
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> parent = client.key_ring_path('[PROJECT]', '[LOCATION]', '[KEY_RING]')
            >>> crypto_key_id = 'my-app-key'
            >>> purpose = enums.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
            >>> seconds = 2147483647
            >>> next_rotation_time = {'seconds': seconds}
            >>> seconds_2 = 604800
            >>> rotation_period = {'seconds': seconds_2}
            >>> crypto_key = {'purpose': purpose, 'next_rotation_time': next_rotation_time, 'rotation_period': rotation_period}
            >>>
            >>> response = client.create_crypto_key(parent, crypto_key_id, crypto_key)

        Args:
            parent (str): Not ZigZag encoded. Negative numbers take 10 bytes. Use TYPE_SINT32
                if negative values are likely.
            crypto_key_id (str): javalite_serializable
            crypto_key (Union[dict, ~google.cloud.kms_v1.types.CryptoKey]): Lists ``CryptoKeyVersions``.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.kms_v1.types.CryptoKey`
            skip_initial_version_creation (bool): Required. The resource name of the ``CryptoKey`` or
                ``CryptoKeyVersion`` to use for encryption.

                If a ``CryptoKey`` is specified, the server will use its
                ``primary version``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.CryptoKey` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "create_crypto_key" not in self._inner_api_calls:
            self._inner_api_calls[
                "create_crypto_key"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.create_crypto_key,
                default_retry=self._method_configs["CreateCryptoKey"].retry,
                default_timeout=self._method_configs["CreateCryptoKey"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.CreateCryptoKeyRequest(
            parent=parent,
            crypto_key_id=crypto_key_id,
            crypto_key=crypto_key,
            skip_initial_version_creation=skip_initial_version_creation,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["create_crypto_key"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def create_crypto_key_version(
        self,
        parent,
        crypto_key_version,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        The custom pattern is used for specifying an HTTP method that is not
        included in the ``pattern`` field, such as HEAD, or "*" to leave the
        HTTP method unspecified for this rule. The wild-card rule is useful for
        services that provide content to Web (HTML) clients.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> parent = client.crypto_key_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[CRYPTO_KEY]')
            >>>
            >>> # TODO: Initialize `crypto_key_version`:
            >>> crypto_key_version = {}
            >>>
            >>> response = client.create_crypto_key_version(parent, crypto_key_version)

        Args:
            parent (str): Output only. The name of the ``ImportJob`` used to import this
                ``CryptoKeyVersion``. Only present if the underlying key material was
                imported.
            crypto_key_version (Union[dict, ~google.cloud.kms_v1.types.CryptoKeyVersion]): Required. The ``name`` of the KeyRing associated with the
                ``CryptoKeys``.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.kms_v1.types.CryptoKeyVersion`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.CryptoKeyVersion` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "create_crypto_key_version" not in self._inner_api_calls:
            self._inner_api_calls[
                "create_crypto_key_version"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.create_crypto_key_version,
                default_retry=self._method_configs["CreateCryptoKeyVersion"].retry,
                default_timeout=self._method_configs["CreateCryptoKeyVersion"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.CreateCryptoKeyVersionRequest(
            parent=parent, crypto_key_version=crypto_key_version
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["create_crypto_key_version"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def import_crypto_key_version(
        self,
        parent,
        algorithm,
        import_job,
        rsa_aes_wrapped_key=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
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

        Example:
            >>> from google.cloud import kms_v1
            >>> from google.cloud.kms_v1 import enums
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> parent = client.crypto_key_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[CRYPTO_KEY]')
            >>>
            >>> # TODO: Initialize `algorithm`:
            >>> algorithm = enums.CryptoKeyVersion.CryptoKeyVersionAlgorithm.CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED
            >>>
            >>> # TODO: Initialize `import_job`:
            >>> import_job = ''
            >>>
            >>> response = client.import_crypto_key_version(parent, algorithm, import_job)

        Args:
            parent (str): javanano_as_lite
            algorithm (~google.cloud.kms_v1.types.CryptoKeyVersionAlgorithm): REQUIRED: The complete policy to be applied to the ``resource``. The
                size of the policy is limited to a few 10s of KB. An empty policy is a
                valid policy but certain Cloud Platform services (such as Projects)
                might reject them.
            import_job (str): Output only. The resource name for the ``KeyRing`` in the format
                ``projects/*/locations/*/keyRings/*``.
            rsa_aes_wrapped_key (bytes): Request message for ``KeyManagementService.UpdateCryptoKey``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.CryptoKeyVersion` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "import_crypto_key_version" not in self._inner_api_calls:
            self._inner_api_calls[
                "import_crypto_key_version"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.import_crypto_key_version,
                default_retry=self._method_configs["ImportCryptoKeyVersion"].retry,
                default_timeout=self._method_configs["ImportCryptoKeyVersion"].timeout,
                client_info=self._client_info,
            )

        # Sanity check: We have some fields which are mutually exclusive;
        # raise ValueError if more than one is sent.
        google.api_core.protobuf_helpers.check_oneof(
            rsa_aes_wrapped_key=rsa_aes_wrapped_key
        )

        request = service_pb2.ImportCryptoKeyVersionRequest(
            parent=parent,
            algorithm=algorithm,
            import_job=import_job,
            rsa_aes_wrapped_key=rsa_aes_wrapped_key,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("parent", parent)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["import_crypto_key_version"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def update_crypto_key(
        self,
        crypto_key,
        update_mask,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Required. A ``CryptoKey`` with initial field values.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> # TODO: Initialize `crypto_key`:
            >>> crypto_key = {}
            >>>
            >>> # TODO: Initialize `update_mask`:
            >>> update_mask = {}
            >>>
            >>> response = client.update_crypto_key(crypto_key, update_mask)

        Args:
            crypto_key (Union[dict, ~google.cloud.kms_v1.types.CryptoKey]): Output only. The time at which this ``KeyRing`` was created.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.kms_v1.types.CryptoKey`
            update_mask (Union[dict, ~google.cloud.kms_v1.types.FieldMask]): Required. List of fields to be updated in this request.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.kms_v1.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.CryptoKey` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "update_crypto_key" not in self._inner_api_calls:
            self._inner_api_calls[
                "update_crypto_key"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.update_crypto_key,
                default_retry=self._method_configs["UpdateCryptoKey"].retry,
                default_timeout=self._method_configs["UpdateCryptoKey"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.UpdateCryptoKeyRequest(
            crypto_key=crypto_key, update_mask=update_mask
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("crypto_key.name", crypto_key.name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["update_crypto_key"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def update_crypto_key_version(
        self,
        crypto_key_version,
        update_mask,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        The name of the request field whose value is mapped to the HTTP
        request body, or ``*`` for mapping all request fields not captured by
        the path pattern to the HTTP body, or omitted for not having any HTTP
        request body.

        NOTE: the referred field must be present at the top-level of the request
        message type.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> # TODO: Initialize `crypto_key_version`:
            >>> crypto_key_version = {}
            >>>
            >>> # TODO: Initialize `update_mask`:
            >>> update_mask = {}
            >>>
            >>> response = client.update_crypto_key_version(crypto_key_version, update_mask)

        Args:
            crypto_key_version (Union[dict, ~google.cloud.kms_v1.types.CryptoKeyVersion]): Returns metadata for a given ``KeyRing``.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.kms_v1.types.CryptoKeyVersion`
            update_mask (Union[dict, ~google.cloud.kms_v1.types.FieldMask]): Required. List of fields to be updated in this request.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.kms_v1.types.FieldMask`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.CryptoKeyVersion` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "update_crypto_key_version" not in self._inner_api_calls:
            self._inner_api_calls[
                "update_crypto_key_version"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.update_crypto_key_version,
                default_retry=self._method_configs["UpdateCryptoKeyVersion"].retry,
                default_timeout=self._method_configs["UpdateCryptoKeyVersion"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.UpdateCryptoKeyVersionRequest(
            crypto_key_version=crypto_key_version, update_mask=update_mask
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("crypto_key_version.name", crypto_key_version.name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["update_crypto_key_version"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def encrypt(
        self,
        name,
        plaintext,
        additional_authenticated_data=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Required. The digest of the data to sign. The digest must be
        produced with the same digest algorithm as specified by the key
        version's ``algorithm``.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> # TODO: Initialize `name`:
            >>> name = ''
            >>>
            >>> # TODO: Initialize `plaintext`:
            >>> plaintext = b''
            >>>
            >>> response = client.encrypt(name, plaintext)

        Args:
            name (str): An annotation that describes a resource definition without a
                corresponding message; see ``ResourceDescriptor``.
            plaintext (bytes): A ``CryptoKey`` represents a logical key that can be used for
                cryptographic operations.

                A ``CryptoKey`` is made up of one or more ``versions``, which represent
                the actual key material used in cryptographic operations.
            additional_authenticated_data (bytes): Required. The resource name of the ``KeyRing`` to list, in the
                format ``projects/*/locations/*/keyRings/*``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.EncryptResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "encrypt" not in self._inner_api_calls:
            self._inner_api_calls[
                "encrypt"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.encrypt,
                default_retry=self._method_configs["Encrypt"].retry,
                default_timeout=self._method_configs["Encrypt"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.EncryptRequest(
            name=name,
            plaintext=plaintext,
            additional_authenticated_data=additional_authenticated_data,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["encrypt"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def decrypt(
        self,
        name,
        ciphertext,
        additional_authenticated_data=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        This version is still being imported. It may not be used, enabled,
        disabled, or destroyed yet. Cloud KMS will automatically mark this
        version ``ENABLED`` as soon as the version is ready.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> name = client.crypto_key_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[CRYPTO_KEY]')
            >>>
            >>> # TODO: Initialize `ciphertext`:
            >>> ciphertext = b''
            >>>
            >>> response = client.decrypt(name, ciphertext)

        Args:
            name (str): Output only. The current state of the ``ImportJob``, indicating if
                it can be used.
            ciphertext (bytes): ExternalProtectionLevelOptions stores a group of additional fields
                for configuring a ``CryptoKeyVersion`` that are specific to the
                ``EXTERNAL`` protection level.
            additional_authenticated_data (bytes): OAuth scopes needed for the client.

                Example:

                | service Foo { option (google.api.oauth_scopes) =
                | "https://www.googleapis.com/auth/cloud-platform"; ... }

                If there is more than one scope, use a comma-separated string:

                Example:

                | service Foo { option (google.api.oauth_scopes) =
                | "https://www.googleapis.com/auth/cloud-platform,"
                  "https://www.googleapis.com/auth/monitoring"; ... }
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.DecryptResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "decrypt" not in self._inner_api_calls:
            self._inner_api_calls[
                "decrypt"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.decrypt,
                default_retry=self._method_configs["Decrypt"].retry,
                default_timeout=self._method_configs["Decrypt"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.DecryptRequest(
            name=name,
            ciphertext=ciphertext,
            additional_authenticated_data=additional_authenticated_data,
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["decrypt"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def update_crypto_key_primary_version(
        self,
        name,
        crypto_key_version_id,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        The list of ``CryptoKeyVersions``.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> name = client.crypto_key_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[CRYPTO_KEY]')
            >>>
            >>> # TODO: Initialize `crypto_key_version_id`:
            >>> crypto_key_version_id = ''
            >>>
            >>> response = client.update_crypto_key_primary_version(name, crypto_key_version_id)

        Args:
            name (str): Specifies the format of the policy.

                Valid values are 0, 1, and 3. Requests specifying an invalid value will
                be rejected.

                Operations affecting conditional bindings must specify version 3. This
                can be either setting a conditional policy, modifying a conditional
                binding, or removing a binding (conditional or unconditional) from the
                stored conditional policy. Operations on non-conditional policies may
                specify any valid value or leave the field unset.

                If no etag is provided in the call to ``setIamPolicy``, version
                compliance checks against the stored policy is skipped.
            crypto_key_version_id (str): Output only. The time this ``ImportJob``'s key material was
                generated.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.CryptoKey` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "update_crypto_key_primary_version" not in self._inner_api_calls:
            self._inner_api_calls[
                "update_crypto_key_primary_version"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.update_crypto_key_primary_version,
                default_retry=self._method_configs[
                    "UpdateCryptoKeyPrimaryVersion"
                ].retry,
                default_timeout=self._method_configs[
                    "UpdateCryptoKeyPrimaryVersion"
                ].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.UpdateCryptoKeyPrimaryVersionRequest(
            name=name, crypto_key_version_id=crypto_key_version_id
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["update_crypto_key_primary_version"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def destroy_crypto_key_version(
        self,
        name,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        This version was not imported successfully. It may not be used,
        enabled, disabled, or destroyed. The submitted key material has been
        discarded. Additional details can be found in
        ``CryptoKeyVersion.import_failure_reason``.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> name = client.crypto_key_version_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[CRYPTO_KEY]', '[CRYPTO_KEY_VERSION]')
            >>>
            >>> response = client.destroy_crypto_key_version(name)

        Args:
            name (str): ``CryptoKeys`` with this purpose may be used with
                ``AsymmetricDecrypt`` and ``GetPublicKey``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.CryptoKeyVersion` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "destroy_crypto_key_version" not in self._inner_api_calls:
            self._inner_api_calls[
                "destroy_crypto_key_version"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.destroy_crypto_key_version,
                default_retry=self._method_configs["DestroyCryptoKeyVersion"].retry,
                default_timeout=self._method_configs["DestroyCryptoKeyVersion"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.DestroyCryptoKeyVersionRequest(name=name)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["destroy_crypto_key_version"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def restore_crypto_key_version(
        self,
        name,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Request message for ``KeyManagementService.Encrypt``.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> name = client.crypto_key_version_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[CRYPTO_KEY]', '[CRYPTO_KEY_VERSION]')
            >>>
            >>> response = client.restore_crypto_key_version(name)

        Args:
            name (str): Output only. The time at which this ``CryptoKey`` was created.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.CryptoKeyVersion` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "restore_crypto_key_version" not in self._inner_api_calls:
            self._inner_api_calls[
                "restore_crypto_key_version"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.restore_crypto_key_version,
                default_retry=self._method_configs["RestoreCryptoKeyVersion"].retry,
                default_timeout=self._method_configs["RestoreCryptoKeyVersion"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.RestoreCryptoKeyVersionRequest(name=name)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["restore_crypto_key_version"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def get_public_key(
        self,
        name,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
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

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> name = client.crypto_key_version_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[CRYPTO_KEY]', '[CRYPTO_KEY_VERSION]')
            >>>
            >>> response = client.get_public_key(name)

        Args:
            name (str): Output only. The time this ``CryptoKeyVersion``'s key material is
                scheduled for destruction. Only present if ``state`` is
                ``DESTROY_SCHEDULED``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.PublicKey` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "get_public_key" not in self._inner_api_calls:
            self._inner_api_calls[
                "get_public_key"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.get_public_key,
                default_retry=self._method_configs["GetPublicKey"].retry,
                default_timeout=self._method_configs["GetPublicKey"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.GetPublicKeyRequest(name=name)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["get_public_key"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def asymmetric_decrypt(
        self,
        name,
        ciphertext,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Input and output type names. These are resolved in the same way as
        FieldDescriptorProto.type_name, but must refer to a message type.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> name = client.crypto_key_version_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[CRYPTO_KEY]', '[CRYPTO_KEY_VERSION]')
            >>>
            >>> # TODO: Initialize `ciphertext`:
            >>> ciphertext = b''
            >>>
            >>> response = client.asymmetric_decrypt(name, ciphertext)

        Args:
            name (str): The public key for a given ``CryptoKeyVersion``. Obtained via
                ``GetPublicKey``.
            ciphertext (bytes): An annotation that describes a resource definition, see
                ``ResourceDescriptor``.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.AsymmetricDecryptResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "asymmetric_decrypt" not in self._inner_api_calls:
            self._inner_api_calls[
                "asymmetric_decrypt"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.asymmetric_decrypt,
                default_retry=self._method_configs["AsymmetricDecrypt"].retry,
                default_timeout=self._method_configs["AsymmetricDecrypt"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.AsymmetricDecryptRequest(name=name, ciphertext=ciphertext)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["asymmetric_decrypt"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def asymmetric_sign(
        self,
        name,
        digest,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Optional. Specify how the results should be sorted. If not
        specified, the results will be sorted in the default order. For more
        information, see `Sorting and filtering list
        results <https://cloud.google.com/kms/docs/sorting-and-filtering>`__.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> name = client.crypto_key_version_path('[PROJECT]', '[LOCATION]', '[KEY_RING]', '[CRYPTO_KEY]', '[CRYPTO_KEY_VERSION]')
            >>>
            >>> # TODO: Initialize `digest`:
            >>> digest = {}
            >>>
            >>> response = client.asymmetric_sign(name, digest)

        Args:
            name (str): ``CryptoKeyPurpose`` describes the cryptographic capabilities of a
                ``CryptoKey``. A given key can only be used for the operations allowed
                by its purpose. For more information, see `Key
                purposes <https://cloud.google.com/kms/docs/algorithms#key_purposes>`__.
            digest (Union[dict, ~google.cloud.kms_v1.types.Digest]): Optional. Only include resources that match the filter in the
                response. For more information, see `Sorting and filtering list
                results <https://cloud.google.com/kms/docs/sorting-and-filtering>`__.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.kms_v1.types.Digest`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.AsymmetricSignResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "asymmetric_sign" not in self._inner_api_calls:
            self._inner_api_calls[
                "asymmetric_sign"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.asymmetric_sign,
                default_retry=self._method_configs["AsymmetricSign"].retry,
                default_timeout=self._method_configs["AsymmetricSign"].timeout,
                client_info=self._client_info,
            )

        request = service_pb2.AsymmetricSignRequest(name=name, digest=digest)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("name", name)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["asymmetric_sign"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def set_iam_policy(
        self,
        resource,
        policy,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Sets the access control policy on the specified resource. Replaces
        any existing policy.

        Can return Public Errors: NOT_FOUND, INVALID_ARGUMENT and
        PERMISSION_DENIED

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> # TODO: Initialize `resource`:
            >>> resource = ''
            >>>
            >>> # TODO: Initialize `policy`:
            >>> policy = {}
            >>>
            >>> response = client.set_iam_policy(resource, policy)

        Args:
            resource (str): REQUIRED: The resource for which the policy is being specified.
                See the operation documentation for the appropriate value for this field.
            policy (Union[dict, ~google.cloud.kms_v1.types.Policy]): This ImportMethod represents the CKM_RSA_AES_KEY_WRAP key wrapping
                scheme defined in the PKCS #11 standard. In summary, this involves
                wrapping the raw key with an ephemeral AES key, and wrapping the
                ephemeral AES key with a 3072 bit RSA key. For more details, see `RSA
                AES key wrap
                mechanism <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908>`__.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.kms_v1.types.Policy`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.Policy` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "set_iam_policy" not in self._inner_api_calls:
            self._inner_api_calls[
                "set_iam_policy"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.set_iam_policy,
                default_retry=self._method_configs["SetIamPolicy"].retry,
                default_timeout=self._method_configs["SetIamPolicy"].timeout,
                client_info=self._client_info,
            )

        request = iam_policy_pb2.SetIamPolicyRequest(resource=resource, policy=policy)
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("resource", resource)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["set_iam_policy"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def get_iam_policy(
        self,
        resource,
        options_=None,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Gets the access control policy for a resource. Returns an empty policy
        if the resource exists and does not have a policy set.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> # TODO: Initialize `resource`:
            >>> resource = ''
            >>>
            >>> response = client.get_iam_policy(resource)

        Args:
            resource (str): REQUIRED: The resource for which the policy is being requested.
                See the operation documentation for the appropriate value for this field.
            options_ (Union[dict, ~google.cloud.kms_v1.types.GetPolicyOptions]): This ImportMethod represents the CKM_RSA_AES_KEY_WRAP key wrapping
                scheme defined in the PKCS #11 standard. In summary, this involves
                wrapping the raw key with an ephemeral AES key, and wrapping the
                ephemeral AES key with a 4096 bit RSA key. For more details, see `RSA
                AES key wrap
                mechanism <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908>`__.

                If a dict is provided, it must be of the same form as the protobuf
                message :class:`~google.cloud.kms_v1.types.GetPolicyOptions`
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.Policy` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "get_iam_policy" not in self._inner_api_calls:
            self._inner_api_calls[
                "get_iam_policy"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.get_iam_policy,
                default_retry=self._method_configs["GetIamPolicy"].retry,
                default_timeout=self._method_configs["GetIamPolicy"].timeout,
                client_info=self._client_info,
            )

        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=resource, options=options_
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("resource", resource)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["get_iam_policy"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )

    def test_iam_permissions(
        self,
        resource,
        permissions,
        retry=google.api_core.gapic_v1.method.DEFAULT,
        timeout=google.api_core.gapic_v1.method.DEFAULT,
        metadata=None,
    ):
        """
        Returns permissions that a caller has on the specified resource. If the
        resource does not exist, this will return an empty set of
        permissions, not a NOT_FOUND error.

        Note: This operation is designed to be used for building
        permission-aware UIs and command-line tools, not for authorization
        checking. This operation may "fail open" without warning.

        Example:
            >>> from google.cloud import kms_v1
            >>>
            >>> client = kms_v1.KeyManagementServiceClient()
            >>>
            >>> # TODO: Initialize `resource`:
            >>> resource = ''
            >>>
            >>> # TODO: Initialize `permissions`:
            >>> permissions = []
            >>>
            >>> response = client.test_iam_permissions(resource, permissions)

        Args:
            resource (str): REQUIRED: The resource for which the policy detail is being requested.
                See the operation documentation for the appropriate value for this field.
            permissions (list[str]): Optional. Optional limit on the number of ``CryptoKeyVersions`` to
                include in the response. Further ``CryptoKeyVersions`` can subsequently
                be obtained by including the
                ``ListCryptoKeyVersionsResponse.next_page_token`` in a subsequent
                request. If unspecified, the server will pick an appropriate default.
            retry (Optional[google.api_core.retry.Retry]):  A retry object used
                to retry requests. If ``None`` is specified, requests will
                be retried using a default configuration.
            timeout (Optional[float]): The amount of time, in seconds, to wait
                for the request to complete. Note that if ``retry`` is
                specified, the timeout applies to each individual attempt.
            metadata (Optional[Sequence[Tuple[str, str]]]): Additional metadata
                that is provided to the method.

        Returns:
            A :class:`~google.cloud.kms_v1.types.TestIamPermissionsResponse` instance.

        Raises:
            google.api_core.exceptions.GoogleAPICallError: If the request
                    failed for any reason.
            google.api_core.exceptions.RetryError: If the request failed due
                    to a retryable error and retry attempts failed.
            ValueError: If the parameters are invalid.
        """
        # Wrap the transport method to add retry and timeout logic.
        if "test_iam_permissions" not in self._inner_api_calls:
            self._inner_api_calls[
                "test_iam_permissions"
            ] = google.api_core.gapic_v1.method.wrap_method(
                self.transport.test_iam_permissions,
                default_retry=self._method_configs["TestIamPermissions"].retry,
                default_timeout=self._method_configs["TestIamPermissions"].timeout,
                client_info=self._client_info,
            )

        request = iam_policy_pb2.TestIamPermissionsRequest(
            resource=resource, permissions=permissions
        )
        if metadata is None:
            metadata = []
        metadata = list(metadata)
        try:
            routing_header = [("resource", resource)]
        except AttributeError:
            pass
        else:
            routing_metadata = google.api_core.gapic_v1.routing_header.to_grpc_metadata(
                routing_header
            )
            metadata.append(routing_metadata)

        return self._inner_api_calls["test_iam_permissions"](
            request, retry=retry, timeout=timeout, metadata=metadata
        )
