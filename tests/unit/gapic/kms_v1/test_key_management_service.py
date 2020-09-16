# -*- coding: utf-8 -*-

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
# limitations under the License.
#

import os
import mock

import grpc
from grpc.experimental import aio
import math
import pytest
from proto.marshal.rules.dates import DurationRule, TimestampRule

from google import auth
from google.api_core import client_options
from google.api_core import exceptions
from google.api_core import gapic_v1
from google.api_core import grpc_helpers
from google.api_core import grpc_helpers_async
from google.auth import credentials
from google.auth.exceptions import MutualTLSChannelError
from google.cloud.kms_v1.services.key_management_service import (
    KeyManagementServiceAsyncClient,
)
from google.cloud.kms_v1.services.key_management_service import (
    KeyManagementServiceClient,
)
from google.cloud.kms_v1.services.key_management_service import pagers
from google.cloud.kms_v1.services.key_management_service import transports
from google.cloud.kms_v1.types import resources
from google.cloud.kms_v1.types import service
from google.iam.v1 import iam_policy_pb2 as iam_policy  # type: ignore
from google.iam.v1 import options_pb2 as options  # type: ignore
from google.iam.v1 import policy_pb2 as policy  # type: ignore
from google.oauth2 import service_account
from google.protobuf import duration_pb2 as duration  # type: ignore
from google.protobuf import field_mask_pb2 as field_mask  # type: ignore
from google.protobuf import timestamp_pb2 as timestamp  # type: ignore
from google.protobuf import wrappers_pb2 as wrappers  # type: ignore


def client_cert_source_callback():
    return b"cert bytes", b"key bytes"


# If default endpoint is localhost, then default mtls endpoint will be the same.
# This method modifies the default endpoint so the client can produce a different
# mtls endpoint for endpoint testing purposes.
def modify_default_endpoint(client):
    return (
        "foo.googleapis.com"
        if ("localhost" in client.DEFAULT_ENDPOINT)
        else client.DEFAULT_ENDPOINT
    )


def test__get_default_mtls_endpoint():
    api_endpoint = "example.googleapis.com"
    api_mtls_endpoint = "example.mtls.googleapis.com"
    sandbox_endpoint = "example.sandbox.googleapis.com"
    sandbox_mtls_endpoint = "example.mtls.sandbox.googleapis.com"
    non_googleapi = "api.example.com"

    assert KeyManagementServiceClient._get_default_mtls_endpoint(None) is None
    assert (
        KeyManagementServiceClient._get_default_mtls_endpoint(api_endpoint)
        == api_mtls_endpoint
    )
    assert (
        KeyManagementServiceClient._get_default_mtls_endpoint(api_mtls_endpoint)
        == api_mtls_endpoint
    )
    assert (
        KeyManagementServiceClient._get_default_mtls_endpoint(sandbox_endpoint)
        == sandbox_mtls_endpoint
    )
    assert (
        KeyManagementServiceClient._get_default_mtls_endpoint(sandbox_mtls_endpoint)
        == sandbox_mtls_endpoint
    )
    assert (
        KeyManagementServiceClient._get_default_mtls_endpoint(non_googleapi)
        == non_googleapi
    )


@pytest.mark.parametrize(
    "client_class", [KeyManagementServiceClient, KeyManagementServiceAsyncClient]
)
def test_key_management_service_client_from_service_account_file(client_class):
    creds = credentials.AnonymousCredentials()
    with mock.patch.object(
        service_account.Credentials, "from_service_account_file"
    ) as factory:
        factory.return_value = creds
        client = client_class.from_service_account_file("dummy/file/path.json")
        assert client._transport._credentials == creds

        client = client_class.from_service_account_json("dummy/file/path.json")
        assert client._transport._credentials == creds

        assert client._transport._host == "cloudkms.googleapis.com:443"


def test_key_management_service_client_get_transport_class():
    transport = KeyManagementServiceClient.get_transport_class()
    assert transport == transports.KeyManagementServiceGrpcTransport

    transport = KeyManagementServiceClient.get_transport_class("grpc")
    assert transport == transports.KeyManagementServiceGrpcTransport


@pytest.mark.parametrize(
    "client_class,transport_class,transport_name",
    [
        (
            KeyManagementServiceClient,
            transports.KeyManagementServiceGrpcTransport,
            "grpc",
        ),
        (
            KeyManagementServiceAsyncClient,
            transports.KeyManagementServiceGrpcAsyncIOTransport,
            "grpc_asyncio",
        ),
    ],
)
@mock.patch.object(
    KeyManagementServiceClient,
    "DEFAULT_ENDPOINT",
    modify_default_endpoint(KeyManagementServiceClient),
)
@mock.patch.object(
    KeyManagementServiceAsyncClient,
    "DEFAULT_ENDPOINT",
    modify_default_endpoint(KeyManagementServiceAsyncClient),
)
def test_key_management_service_client_client_options(
    client_class, transport_class, transport_name
):
    # Check that if channel is provided we won't create a new one.
    with mock.patch.object(KeyManagementServiceClient, "get_transport_class") as gtc:
        transport = transport_class(credentials=credentials.AnonymousCredentials())
        client = client_class(transport=transport)
        gtc.assert_not_called()

    # Check that if channel is provided via str we will create a new one.
    with mock.patch.object(KeyManagementServiceClient, "get_transport_class") as gtc:
        client = client_class(transport=transport_name)
        gtc.assert_called()

    # Check the case api_endpoint is provided.
    options = client_options.ClientOptions(api_endpoint="squid.clam.whelk")
    with mock.patch.object(transport_class, "__init__") as patched:
        patched.return_value = None
        client = client_class(client_options=options)
        patched.assert_called_once_with(
            credentials=None,
            credentials_file=None,
            host="squid.clam.whelk",
            scopes=None,
            ssl_channel_credentials=None,
            quota_project_id=None,
            client_info=transports.base.DEFAULT_CLIENT_INFO,
        )

    # Check the case api_endpoint is not provided and GOOGLE_API_USE_MTLS_ENDPOINT is
    # "never".
    with mock.patch.dict(os.environ, {"GOOGLE_API_USE_MTLS_ENDPOINT": "never"}):
        with mock.patch.object(transport_class, "__init__") as patched:
            patched.return_value = None
            client = client_class()
            patched.assert_called_once_with(
                credentials=None,
                credentials_file=None,
                host=client.DEFAULT_ENDPOINT,
                scopes=None,
                ssl_channel_credentials=None,
                quota_project_id=None,
                client_info=transports.base.DEFAULT_CLIENT_INFO,
            )

    # Check the case api_endpoint is not provided and GOOGLE_API_USE_MTLS_ENDPOINT is
    # "always".
    with mock.patch.dict(os.environ, {"GOOGLE_API_USE_MTLS_ENDPOINT": "always"}):
        with mock.patch.object(transport_class, "__init__") as patched:
            patched.return_value = None
            client = client_class()
            patched.assert_called_once_with(
                credentials=None,
                credentials_file=None,
                host=client.DEFAULT_MTLS_ENDPOINT,
                scopes=None,
                ssl_channel_credentials=None,
                quota_project_id=None,
                client_info=transports.base.DEFAULT_CLIENT_INFO,
            )

    # Check the case api_endpoint is not provided and GOOGLE_API_USE_MTLS_ENDPOINT has
    # unsupported value.
    with mock.patch.dict(os.environ, {"GOOGLE_API_USE_MTLS_ENDPOINT": "Unsupported"}):
        with pytest.raises(MutualTLSChannelError):
            client = client_class()

    # Check the case GOOGLE_API_USE_CLIENT_CERTIFICATE has unsupported value.
    with mock.patch.dict(
        os.environ, {"GOOGLE_API_USE_CLIENT_CERTIFICATE": "Unsupported"}
    ):
        with pytest.raises(ValueError):
            client = client_class()

    # Check the case quota_project_id is provided
    options = client_options.ClientOptions(quota_project_id="octopus")
    with mock.patch.object(transport_class, "__init__") as patched:
        patched.return_value = None
        client = client_class(client_options=options)
        patched.assert_called_once_with(
            credentials=None,
            credentials_file=None,
            host=client.DEFAULT_ENDPOINT,
            scopes=None,
            ssl_channel_credentials=None,
            quota_project_id="octopus",
            client_info=transports.base.DEFAULT_CLIENT_INFO,
        )


@pytest.mark.parametrize(
    "client_class,transport_class,transport_name,use_client_cert_env",
    [
        (
            KeyManagementServiceClient,
            transports.KeyManagementServiceGrpcTransport,
            "grpc",
            "true",
        ),
        (
            KeyManagementServiceAsyncClient,
            transports.KeyManagementServiceGrpcAsyncIOTransport,
            "grpc_asyncio",
            "true",
        ),
        (
            KeyManagementServiceClient,
            transports.KeyManagementServiceGrpcTransport,
            "grpc",
            "false",
        ),
        (
            KeyManagementServiceAsyncClient,
            transports.KeyManagementServiceGrpcAsyncIOTransport,
            "grpc_asyncio",
            "false",
        ),
    ],
)
@mock.patch.object(
    KeyManagementServiceClient,
    "DEFAULT_ENDPOINT",
    modify_default_endpoint(KeyManagementServiceClient),
)
@mock.patch.object(
    KeyManagementServiceAsyncClient,
    "DEFAULT_ENDPOINT",
    modify_default_endpoint(KeyManagementServiceAsyncClient),
)
@mock.patch.dict(os.environ, {"GOOGLE_API_USE_MTLS_ENDPOINT": "auto"})
def test_key_management_service_client_mtls_env_auto(
    client_class, transport_class, transport_name, use_client_cert_env
):
    # This tests the endpoint autoswitch behavior. Endpoint is autoswitched to the default
    # mtls endpoint, if GOOGLE_API_USE_CLIENT_CERTIFICATE is "true" and client cert exists.

    # Check the case client_cert_source is provided. Whether client cert is used depends on
    # GOOGLE_API_USE_CLIENT_CERTIFICATE value.
    with mock.patch.dict(
        os.environ, {"GOOGLE_API_USE_CLIENT_CERTIFICATE": use_client_cert_env}
    ):
        options = client_options.ClientOptions(
            client_cert_source=client_cert_source_callback
        )
        with mock.patch.object(transport_class, "__init__") as patched:
            ssl_channel_creds = mock.Mock()
            with mock.patch(
                "grpc.ssl_channel_credentials", return_value=ssl_channel_creds
            ):
                patched.return_value = None
                client = client_class(client_options=options)

                if use_client_cert_env == "false":
                    expected_ssl_channel_creds = None
                    expected_host = client.DEFAULT_ENDPOINT
                else:
                    expected_ssl_channel_creds = ssl_channel_creds
                    expected_host = client.DEFAULT_MTLS_ENDPOINT

                patched.assert_called_once_with(
                    credentials=None,
                    credentials_file=None,
                    host=expected_host,
                    scopes=None,
                    ssl_channel_credentials=expected_ssl_channel_creds,
                    quota_project_id=None,
                    client_info=transports.base.DEFAULT_CLIENT_INFO,
                )

    # Check the case ADC client cert is provided. Whether client cert is used depends on
    # GOOGLE_API_USE_CLIENT_CERTIFICATE value.
    with mock.patch.dict(
        os.environ, {"GOOGLE_API_USE_CLIENT_CERTIFICATE": use_client_cert_env}
    ):
        with mock.patch.object(transport_class, "__init__") as patched:
            with mock.patch(
                "google.auth.transport.grpc.SslCredentials.__init__", return_value=None
            ):
                with mock.patch(
                    "google.auth.transport.grpc.SslCredentials.is_mtls",
                    new_callable=mock.PropertyMock,
                ) as is_mtls_mock:
                    with mock.patch(
                        "google.auth.transport.grpc.SslCredentials.ssl_credentials",
                        new_callable=mock.PropertyMock,
                    ) as ssl_credentials_mock:
                        if use_client_cert_env == "false":
                            is_mtls_mock.return_value = False
                            ssl_credentials_mock.return_value = None
                            expected_host = client.DEFAULT_ENDPOINT
                            expected_ssl_channel_creds = None
                        else:
                            is_mtls_mock.return_value = True
                            ssl_credentials_mock.return_value = mock.Mock()
                            expected_host = client.DEFAULT_MTLS_ENDPOINT
                            expected_ssl_channel_creds = (
                                ssl_credentials_mock.return_value
                            )

                        patched.return_value = None
                        client = client_class()
                        patched.assert_called_once_with(
                            credentials=None,
                            credentials_file=None,
                            host=expected_host,
                            scopes=None,
                            ssl_channel_credentials=expected_ssl_channel_creds,
                            quota_project_id=None,
                            client_info=transports.base.DEFAULT_CLIENT_INFO,
                        )

    # Check the case client_cert_source and ADC client cert are not provided.
    with mock.patch.dict(
        os.environ, {"GOOGLE_API_USE_CLIENT_CERTIFICATE": use_client_cert_env}
    ):
        with mock.patch.object(transport_class, "__init__") as patched:
            with mock.patch(
                "google.auth.transport.grpc.SslCredentials.__init__", return_value=None
            ):
                with mock.patch(
                    "google.auth.transport.grpc.SslCredentials.is_mtls",
                    new_callable=mock.PropertyMock,
                ) as is_mtls_mock:
                    is_mtls_mock.return_value = False
                    patched.return_value = None
                    client = client_class()
                    patched.assert_called_once_with(
                        credentials=None,
                        credentials_file=None,
                        host=client.DEFAULT_ENDPOINT,
                        scopes=None,
                        ssl_channel_credentials=None,
                        quota_project_id=None,
                        client_info=transports.base.DEFAULT_CLIENT_INFO,
                    )


@pytest.mark.parametrize(
    "client_class,transport_class,transport_name",
    [
        (
            KeyManagementServiceClient,
            transports.KeyManagementServiceGrpcTransport,
            "grpc",
        ),
        (
            KeyManagementServiceAsyncClient,
            transports.KeyManagementServiceGrpcAsyncIOTransport,
            "grpc_asyncio",
        ),
    ],
)
def test_key_management_service_client_client_options_scopes(
    client_class, transport_class, transport_name
):
    # Check the case scopes are provided.
    options = client_options.ClientOptions(scopes=["1", "2"],)
    with mock.patch.object(transport_class, "__init__") as patched:
        patched.return_value = None
        client = client_class(client_options=options)
        patched.assert_called_once_with(
            credentials=None,
            credentials_file=None,
            host=client.DEFAULT_ENDPOINT,
            scopes=["1", "2"],
            ssl_channel_credentials=None,
            quota_project_id=None,
            client_info=transports.base.DEFAULT_CLIENT_INFO,
        )


@pytest.mark.parametrize(
    "client_class,transport_class,transport_name",
    [
        (
            KeyManagementServiceClient,
            transports.KeyManagementServiceGrpcTransport,
            "grpc",
        ),
        (
            KeyManagementServiceAsyncClient,
            transports.KeyManagementServiceGrpcAsyncIOTransport,
            "grpc_asyncio",
        ),
    ],
)
def test_key_management_service_client_client_options_credentials_file(
    client_class, transport_class, transport_name
):
    # Check the case credentials file is provided.
    options = client_options.ClientOptions(credentials_file="credentials.json")
    with mock.patch.object(transport_class, "__init__") as patched:
        patched.return_value = None
        client = client_class(client_options=options)
        patched.assert_called_once_with(
            credentials=None,
            credentials_file="credentials.json",
            host=client.DEFAULT_ENDPOINT,
            scopes=None,
            ssl_channel_credentials=None,
            quota_project_id=None,
            client_info=transports.base.DEFAULT_CLIENT_INFO,
        )


def test_key_management_service_client_client_options_from_dict():
    with mock.patch(
        "google.cloud.kms_v1.services.key_management_service.transports.KeyManagementServiceGrpcTransport.__init__"
    ) as grpc_transport:
        grpc_transport.return_value = None
        client = KeyManagementServiceClient(
            client_options={"api_endpoint": "squid.clam.whelk"}
        )
        grpc_transport.assert_called_once_with(
            credentials=None,
            credentials_file=None,
            host="squid.clam.whelk",
            scopes=None,
            ssl_channel_credentials=None,
            quota_project_id=None,
            client_info=transports.base.DEFAULT_CLIENT_INFO,
        )


def test_list_key_rings(
    transport: str = "grpc", request_type=service.ListKeyRingsRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.list_key_rings), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.ListKeyRingsResponse(
            next_page_token="next_page_token_value", total_size=1086,
        )

        response = client.list_key_rings(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.ListKeyRingsRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, pagers.ListKeyRingsPager)

    assert response.next_page_token == "next_page_token_value"

    assert response.total_size == 1086


def test_list_key_rings_from_dict():
    test_list_key_rings(request_type=dict)


@pytest.mark.asyncio
async def test_list_key_rings_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.ListKeyRingsRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_key_rings), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.ListKeyRingsResponse(
                next_page_token="next_page_token_value", total_size=1086,
            )
        )

        response = await client.list_key_rings(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, pagers.ListKeyRingsAsyncPager)

    assert response.next_page_token == "next_page_token_value"

    assert response.total_size == 1086


def test_list_key_rings_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.ListKeyRingsRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.list_key_rings), "__call__") as call:
        call.return_value = service.ListKeyRingsResponse()

        client.list_key_rings(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_list_key_rings_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.ListKeyRingsRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_key_rings), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.ListKeyRingsResponse()
        )

        await client.list_key_rings(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


def test_list_key_rings_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.list_key_rings), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.ListKeyRingsResponse()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.list_key_rings(parent="parent_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"


def test_list_key_rings_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.list_key_rings(
            service.ListKeyRingsRequest(), parent="parent_value",
        )


@pytest.mark.asyncio
async def test_list_key_rings_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_key_rings), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.ListKeyRingsResponse()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.ListKeyRingsResponse()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.list_key_rings(parent="parent_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"


@pytest.mark.asyncio
async def test_list_key_rings_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.list_key_rings(
            service.ListKeyRingsRequest(), parent="parent_value",
        )


def test_list_key_rings_pager():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials,)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.list_key_rings), "__call__") as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListKeyRingsResponse(
                key_rings=[
                    resources.KeyRing(),
                    resources.KeyRing(),
                    resources.KeyRing(),
                ],
                next_page_token="abc",
            ),
            service.ListKeyRingsResponse(key_rings=[], next_page_token="def",),
            service.ListKeyRingsResponse(
                key_rings=[resources.KeyRing(),], next_page_token="ghi",
            ),
            service.ListKeyRingsResponse(
                key_rings=[resources.KeyRing(), resources.KeyRing(),],
            ),
            RuntimeError,
        )

        metadata = ()
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", ""),)),
        )
        pager = client.list_key_rings(request={})

        assert pager._metadata == metadata

        results = [i for i in pager]
        assert len(results) == 6
        assert all(isinstance(i, resources.KeyRing) for i in results)


def test_list_key_rings_pages():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials,)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.list_key_rings), "__call__") as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListKeyRingsResponse(
                key_rings=[
                    resources.KeyRing(),
                    resources.KeyRing(),
                    resources.KeyRing(),
                ],
                next_page_token="abc",
            ),
            service.ListKeyRingsResponse(key_rings=[], next_page_token="def",),
            service.ListKeyRingsResponse(
                key_rings=[resources.KeyRing(),], next_page_token="ghi",
            ),
            service.ListKeyRingsResponse(
                key_rings=[resources.KeyRing(), resources.KeyRing(),],
            ),
            RuntimeError,
        )
        pages = list(client.list_key_rings(request={}).pages)
        for page_, token in zip(pages, ["abc", "def", "ghi", ""]):
            assert page_.raw_page.next_page_token == token


@pytest.mark.asyncio
async def test_list_key_rings_async_pager():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials,
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_key_rings),
        "__call__",
        new_callable=mock.AsyncMock,
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListKeyRingsResponse(
                key_rings=[
                    resources.KeyRing(),
                    resources.KeyRing(),
                    resources.KeyRing(),
                ],
                next_page_token="abc",
            ),
            service.ListKeyRingsResponse(key_rings=[], next_page_token="def",),
            service.ListKeyRingsResponse(
                key_rings=[resources.KeyRing(),], next_page_token="ghi",
            ),
            service.ListKeyRingsResponse(
                key_rings=[resources.KeyRing(), resources.KeyRing(),],
            ),
            RuntimeError,
        )
        async_pager = await client.list_key_rings(request={},)
        assert async_pager.next_page_token == "abc"
        responses = []
        async for response in async_pager:
            responses.append(response)

        assert len(responses) == 6
        assert all(isinstance(i, resources.KeyRing) for i in responses)


@pytest.mark.asyncio
async def test_list_key_rings_async_pages():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials,
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_key_rings),
        "__call__",
        new_callable=mock.AsyncMock,
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListKeyRingsResponse(
                key_rings=[
                    resources.KeyRing(),
                    resources.KeyRing(),
                    resources.KeyRing(),
                ],
                next_page_token="abc",
            ),
            service.ListKeyRingsResponse(key_rings=[], next_page_token="def",),
            service.ListKeyRingsResponse(
                key_rings=[resources.KeyRing(),], next_page_token="ghi",
            ),
            service.ListKeyRingsResponse(
                key_rings=[resources.KeyRing(), resources.KeyRing(),],
            ),
            RuntimeError,
        )
        pages = []
        async for page_ in (await client.list_key_rings(request={})).pages:
            pages.append(page_)
        for page_, token in zip(pages, ["abc", "def", "ghi", ""]):
            assert page_.raw_page.next_page_token == token


def test_list_crypto_keys(
    transport: str = "grpc", request_type=service.ListCryptoKeysRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_crypto_keys), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.ListCryptoKeysResponse(
            next_page_token="next_page_token_value", total_size=1086,
        )

        response = client.list_crypto_keys(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.ListCryptoKeysRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, pagers.ListCryptoKeysPager)

    assert response.next_page_token == "next_page_token_value"

    assert response.total_size == 1086


def test_list_crypto_keys_from_dict():
    test_list_crypto_keys(request_type=dict)


@pytest.mark.asyncio
async def test_list_crypto_keys_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.ListCryptoKeysRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_crypto_keys), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.ListCryptoKeysResponse(
                next_page_token="next_page_token_value", total_size=1086,
            )
        )

        response = await client.list_crypto_keys(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, pagers.ListCryptoKeysAsyncPager)

    assert response.next_page_token == "next_page_token_value"

    assert response.total_size == 1086


def test_list_crypto_keys_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.ListCryptoKeysRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_crypto_keys), "__call__"
    ) as call:
        call.return_value = service.ListCryptoKeysResponse()

        client.list_crypto_keys(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_list_crypto_keys_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.ListCryptoKeysRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_crypto_keys), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.ListCryptoKeysResponse()
        )

        await client.list_crypto_keys(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


def test_list_crypto_keys_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_crypto_keys), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.ListCryptoKeysResponse()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.list_crypto_keys(parent="parent_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"


def test_list_crypto_keys_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.list_crypto_keys(
            service.ListCryptoKeysRequest(), parent="parent_value",
        )


@pytest.mark.asyncio
async def test_list_crypto_keys_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_crypto_keys), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.ListCryptoKeysResponse()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.ListCryptoKeysResponse()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.list_crypto_keys(parent="parent_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"


@pytest.mark.asyncio
async def test_list_crypto_keys_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.list_crypto_keys(
            service.ListCryptoKeysRequest(), parent="parent_value",
        )


def test_list_crypto_keys_pager():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials,)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_crypto_keys), "__call__"
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListCryptoKeysResponse(
                crypto_keys=[
                    resources.CryptoKey(),
                    resources.CryptoKey(),
                    resources.CryptoKey(),
                ],
                next_page_token="abc",
            ),
            service.ListCryptoKeysResponse(crypto_keys=[], next_page_token="def",),
            service.ListCryptoKeysResponse(
                crypto_keys=[resources.CryptoKey(),], next_page_token="ghi",
            ),
            service.ListCryptoKeysResponse(
                crypto_keys=[resources.CryptoKey(), resources.CryptoKey(),],
            ),
            RuntimeError,
        )

        metadata = ()
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", ""),)),
        )
        pager = client.list_crypto_keys(request={})

        assert pager._metadata == metadata

        results = [i for i in pager]
        assert len(results) == 6
        assert all(isinstance(i, resources.CryptoKey) for i in results)


def test_list_crypto_keys_pages():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials,)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_crypto_keys), "__call__"
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListCryptoKeysResponse(
                crypto_keys=[
                    resources.CryptoKey(),
                    resources.CryptoKey(),
                    resources.CryptoKey(),
                ],
                next_page_token="abc",
            ),
            service.ListCryptoKeysResponse(crypto_keys=[], next_page_token="def",),
            service.ListCryptoKeysResponse(
                crypto_keys=[resources.CryptoKey(),], next_page_token="ghi",
            ),
            service.ListCryptoKeysResponse(
                crypto_keys=[resources.CryptoKey(), resources.CryptoKey(),],
            ),
            RuntimeError,
        )
        pages = list(client.list_crypto_keys(request={}).pages)
        for page_, token in zip(pages, ["abc", "def", "ghi", ""]):
            assert page_.raw_page.next_page_token == token


@pytest.mark.asyncio
async def test_list_crypto_keys_async_pager():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials,
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_crypto_keys),
        "__call__",
        new_callable=mock.AsyncMock,
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListCryptoKeysResponse(
                crypto_keys=[
                    resources.CryptoKey(),
                    resources.CryptoKey(),
                    resources.CryptoKey(),
                ],
                next_page_token="abc",
            ),
            service.ListCryptoKeysResponse(crypto_keys=[], next_page_token="def",),
            service.ListCryptoKeysResponse(
                crypto_keys=[resources.CryptoKey(),], next_page_token="ghi",
            ),
            service.ListCryptoKeysResponse(
                crypto_keys=[resources.CryptoKey(), resources.CryptoKey(),],
            ),
            RuntimeError,
        )
        async_pager = await client.list_crypto_keys(request={},)
        assert async_pager.next_page_token == "abc"
        responses = []
        async for response in async_pager:
            responses.append(response)

        assert len(responses) == 6
        assert all(isinstance(i, resources.CryptoKey) for i in responses)


@pytest.mark.asyncio
async def test_list_crypto_keys_async_pages():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials,
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_crypto_keys),
        "__call__",
        new_callable=mock.AsyncMock,
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListCryptoKeysResponse(
                crypto_keys=[
                    resources.CryptoKey(),
                    resources.CryptoKey(),
                    resources.CryptoKey(),
                ],
                next_page_token="abc",
            ),
            service.ListCryptoKeysResponse(crypto_keys=[], next_page_token="def",),
            service.ListCryptoKeysResponse(
                crypto_keys=[resources.CryptoKey(),], next_page_token="ghi",
            ),
            service.ListCryptoKeysResponse(
                crypto_keys=[resources.CryptoKey(), resources.CryptoKey(),],
            ),
            RuntimeError,
        )
        pages = []
        async for page_ in (await client.list_crypto_keys(request={})).pages:
            pages.append(page_)
        for page_, token in zip(pages, ["abc", "def", "ghi", ""]):
            assert page_.raw_page.next_page_token == token


def test_list_crypto_key_versions(
    transport: str = "grpc", request_type=service.ListCryptoKeyVersionsRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_crypto_key_versions), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.ListCryptoKeyVersionsResponse(
            next_page_token="next_page_token_value", total_size=1086,
        )

        response = client.list_crypto_key_versions(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.ListCryptoKeyVersionsRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, pagers.ListCryptoKeyVersionsPager)

    assert response.next_page_token == "next_page_token_value"

    assert response.total_size == 1086


def test_list_crypto_key_versions_from_dict():
    test_list_crypto_key_versions(request_type=dict)


@pytest.mark.asyncio
async def test_list_crypto_key_versions_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.ListCryptoKeyVersionsRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_crypto_key_versions), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.ListCryptoKeyVersionsResponse(
                next_page_token="next_page_token_value", total_size=1086,
            )
        )

        response = await client.list_crypto_key_versions(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, pagers.ListCryptoKeyVersionsAsyncPager)

    assert response.next_page_token == "next_page_token_value"

    assert response.total_size == 1086


def test_list_crypto_key_versions_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.ListCryptoKeyVersionsRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_crypto_key_versions), "__call__"
    ) as call:
        call.return_value = service.ListCryptoKeyVersionsResponse()

        client.list_crypto_key_versions(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_list_crypto_key_versions_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.ListCryptoKeyVersionsRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_crypto_key_versions), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.ListCryptoKeyVersionsResponse()
        )

        await client.list_crypto_key_versions(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


def test_list_crypto_key_versions_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_crypto_key_versions), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.ListCryptoKeyVersionsResponse()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.list_crypto_key_versions(parent="parent_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"


def test_list_crypto_key_versions_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.list_crypto_key_versions(
            service.ListCryptoKeyVersionsRequest(), parent="parent_value",
        )


@pytest.mark.asyncio
async def test_list_crypto_key_versions_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_crypto_key_versions), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.ListCryptoKeyVersionsResponse()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.ListCryptoKeyVersionsResponse()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.list_crypto_key_versions(parent="parent_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"


@pytest.mark.asyncio
async def test_list_crypto_key_versions_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.list_crypto_key_versions(
            service.ListCryptoKeyVersionsRequest(), parent="parent_value",
        )


def test_list_crypto_key_versions_pager():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials,)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_crypto_key_versions), "__call__"
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[
                    resources.CryptoKeyVersion(),
                    resources.CryptoKeyVersion(),
                    resources.CryptoKeyVersion(),
                ],
                next_page_token="abc",
            ),
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[], next_page_token="def",
            ),
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[resources.CryptoKeyVersion(),],
                next_page_token="ghi",
            ),
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[
                    resources.CryptoKeyVersion(),
                    resources.CryptoKeyVersion(),
                ],
            ),
            RuntimeError,
        )

        metadata = ()
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", ""),)),
        )
        pager = client.list_crypto_key_versions(request={})

        assert pager._metadata == metadata

        results = [i for i in pager]
        assert len(results) == 6
        assert all(isinstance(i, resources.CryptoKeyVersion) for i in results)


def test_list_crypto_key_versions_pages():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials,)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_crypto_key_versions), "__call__"
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[
                    resources.CryptoKeyVersion(),
                    resources.CryptoKeyVersion(),
                    resources.CryptoKeyVersion(),
                ],
                next_page_token="abc",
            ),
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[], next_page_token="def",
            ),
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[resources.CryptoKeyVersion(),],
                next_page_token="ghi",
            ),
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[
                    resources.CryptoKeyVersion(),
                    resources.CryptoKeyVersion(),
                ],
            ),
            RuntimeError,
        )
        pages = list(client.list_crypto_key_versions(request={}).pages)
        for page_, token in zip(pages, ["abc", "def", "ghi", ""]):
            assert page_.raw_page.next_page_token == token


@pytest.mark.asyncio
async def test_list_crypto_key_versions_async_pager():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials,
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_crypto_key_versions),
        "__call__",
        new_callable=mock.AsyncMock,
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[
                    resources.CryptoKeyVersion(),
                    resources.CryptoKeyVersion(),
                    resources.CryptoKeyVersion(),
                ],
                next_page_token="abc",
            ),
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[], next_page_token="def",
            ),
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[resources.CryptoKeyVersion(),],
                next_page_token="ghi",
            ),
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[
                    resources.CryptoKeyVersion(),
                    resources.CryptoKeyVersion(),
                ],
            ),
            RuntimeError,
        )
        async_pager = await client.list_crypto_key_versions(request={},)
        assert async_pager.next_page_token == "abc"
        responses = []
        async for response in async_pager:
            responses.append(response)

        assert len(responses) == 6
        assert all(isinstance(i, resources.CryptoKeyVersion) for i in responses)


@pytest.mark.asyncio
async def test_list_crypto_key_versions_async_pages():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials,
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_crypto_key_versions),
        "__call__",
        new_callable=mock.AsyncMock,
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[
                    resources.CryptoKeyVersion(),
                    resources.CryptoKeyVersion(),
                    resources.CryptoKeyVersion(),
                ],
                next_page_token="abc",
            ),
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[], next_page_token="def",
            ),
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[resources.CryptoKeyVersion(),],
                next_page_token="ghi",
            ),
            service.ListCryptoKeyVersionsResponse(
                crypto_key_versions=[
                    resources.CryptoKeyVersion(),
                    resources.CryptoKeyVersion(),
                ],
            ),
            RuntimeError,
        )
        pages = []
        async for page_ in (await client.list_crypto_key_versions(request={})).pages:
            pages.append(page_)
        for page_, token in zip(pages, ["abc", "def", "ghi", ""]):
            assert page_.raw_page.next_page_token == token


def test_list_import_jobs(
    transport: str = "grpc", request_type=service.ListImportJobsRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_import_jobs), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.ListImportJobsResponse(
            next_page_token="next_page_token_value", total_size=1086,
        )

        response = client.list_import_jobs(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.ListImportJobsRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, pagers.ListImportJobsPager)

    assert response.next_page_token == "next_page_token_value"

    assert response.total_size == 1086


def test_list_import_jobs_from_dict():
    test_list_import_jobs(request_type=dict)


@pytest.mark.asyncio
async def test_list_import_jobs_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.ListImportJobsRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_import_jobs), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.ListImportJobsResponse(
                next_page_token="next_page_token_value", total_size=1086,
            )
        )

        response = await client.list_import_jobs(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, pagers.ListImportJobsAsyncPager)

    assert response.next_page_token == "next_page_token_value"

    assert response.total_size == 1086


def test_list_import_jobs_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.ListImportJobsRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_import_jobs), "__call__"
    ) as call:
        call.return_value = service.ListImportJobsResponse()

        client.list_import_jobs(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_list_import_jobs_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.ListImportJobsRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_import_jobs), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.ListImportJobsResponse()
        )

        await client.list_import_jobs(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


def test_list_import_jobs_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_import_jobs), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.ListImportJobsResponse()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.list_import_jobs(parent="parent_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"


def test_list_import_jobs_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.list_import_jobs(
            service.ListImportJobsRequest(), parent="parent_value",
        )


@pytest.mark.asyncio
async def test_list_import_jobs_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_import_jobs), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.ListImportJobsResponse()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.ListImportJobsResponse()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.list_import_jobs(parent="parent_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"


@pytest.mark.asyncio
async def test_list_import_jobs_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.list_import_jobs(
            service.ListImportJobsRequest(), parent="parent_value",
        )


def test_list_import_jobs_pager():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials,)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_import_jobs), "__call__"
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListImportJobsResponse(
                import_jobs=[
                    resources.ImportJob(),
                    resources.ImportJob(),
                    resources.ImportJob(),
                ],
                next_page_token="abc",
            ),
            service.ListImportJobsResponse(import_jobs=[], next_page_token="def",),
            service.ListImportJobsResponse(
                import_jobs=[resources.ImportJob(),], next_page_token="ghi",
            ),
            service.ListImportJobsResponse(
                import_jobs=[resources.ImportJob(), resources.ImportJob(),],
            ),
            RuntimeError,
        )

        metadata = ()
        metadata = tuple(metadata) + (
            gapic_v1.routing_header.to_grpc_metadata((("parent", ""),)),
        )
        pager = client.list_import_jobs(request={})

        assert pager._metadata == metadata

        results = [i for i in pager]
        assert len(results) == 6
        assert all(isinstance(i, resources.ImportJob) for i in results)


def test_list_import_jobs_pages():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials,)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.list_import_jobs), "__call__"
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListImportJobsResponse(
                import_jobs=[
                    resources.ImportJob(),
                    resources.ImportJob(),
                    resources.ImportJob(),
                ],
                next_page_token="abc",
            ),
            service.ListImportJobsResponse(import_jobs=[], next_page_token="def",),
            service.ListImportJobsResponse(
                import_jobs=[resources.ImportJob(),], next_page_token="ghi",
            ),
            service.ListImportJobsResponse(
                import_jobs=[resources.ImportJob(), resources.ImportJob(),],
            ),
            RuntimeError,
        )
        pages = list(client.list_import_jobs(request={}).pages)
        for page_, token in zip(pages, ["abc", "def", "ghi", ""]):
            assert page_.raw_page.next_page_token == token


@pytest.mark.asyncio
async def test_list_import_jobs_async_pager():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials,
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_import_jobs),
        "__call__",
        new_callable=mock.AsyncMock,
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListImportJobsResponse(
                import_jobs=[
                    resources.ImportJob(),
                    resources.ImportJob(),
                    resources.ImportJob(),
                ],
                next_page_token="abc",
            ),
            service.ListImportJobsResponse(import_jobs=[], next_page_token="def",),
            service.ListImportJobsResponse(
                import_jobs=[resources.ImportJob(),], next_page_token="ghi",
            ),
            service.ListImportJobsResponse(
                import_jobs=[resources.ImportJob(), resources.ImportJob(),],
            ),
            RuntimeError,
        )
        async_pager = await client.list_import_jobs(request={},)
        assert async_pager.next_page_token == "abc"
        responses = []
        async for response in async_pager:
            responses.append(response)

        assert len(responses) == 6
        assert all(isinstance(i, resources.ImportJob) for i in responses)


@pytest.mark.asyncio
async def test_list_import_jobs_async_pages():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials,
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.list_import_jobs),
        "__call__",
        new_callable=mock.AsyncMock,
    ) as call:
        # Set the response to a series of pages.
        call.side_effect = (
            service.ListImportJobsResponse(
                import_jobs=[
                    resources.ImportJob(),
                    resources.ImportJob(),
                    resources.ImportJob(),
                ],
                next_page_token="abc",
            ),
            service.ListImportJobsResponse(import_jobs=[], next_page_token="def",),
            service.ListImportJobsResponse(
                import_jobs=[resources.ImportJob(),], next_page_token="ghi",
            ),
            service.ListImportJobsResponse(
                import_jobs=[resources.ImportJob(), resources.ImportJob(),],
            ),
            RuntimeError,
        )
        pages = []
        async for page_ in (await client.list_import_jobs(request={})).pages:
            pages.append(page_)
        for page_, token in zip(pages, ["abc", "def", "ghi", ""]):
            assert page_.raw_page.next_page_token == token


def test_get_key_ring(transport: str = "grpc", request_type=service.GetKeyRingRequest):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_key_ring), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.KeyRing(name="name_value",)

        response = client.get_key_ring(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.GetKeyRingRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.KeyRing)

    assert response.name == "name_value"


def test_get_key_ring_from_dict():
    test_get_key_ring(request_type=dict)


@pytest.mark.asyncio
async def test_get_key_ring_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.GetKeyRingRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_key_ring), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.KeyRing(name="name_value",)
        )

        response = await client.get_key_ring(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.KeyRing)

    assert response.name == "name_value"


def test_get_key_ring_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.GetKeyRingRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_key_ring), "__call__") as call:
        call.return_value = resources.KeyRing()

        client.get_key_ring(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_get_key_ring_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.GetKeyRingRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_key_ring), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.KeyRing())

        await client.get_key_ring(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


def test_get_key_ring_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_key_ring), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.KeyRing()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.get_key_ring(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


def test_get_key_ring_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.get_key_ring(
            service.GetKeyRingRequest(), name="name_value",
        )


@pytest.mark.asyncio
async def test_get_key_ring_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_key_ring), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.KeyRing()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.KeyRing())
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.get_key_ring(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


@pytest.mark.asyncio
async def test_get_key_ring_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.get_key_ring(
            service.GetKeyRingRequest(), name="name_value",
        )


def test_get_crypto_key(
    transport: str = "grpc", request_type=service.GetCryptoKeyRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_crypto_key), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKey(
            name="name_value",
            purpose=resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
            rotation_period=duration.Duration(seconds=751),
        )

        response = client.get_crypto_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.GetCryptoKeyRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKey)

    assert response.name == "name_value"

    assert response.purpose == resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT


def test_get_crypto_key_from_dict():
    test_get_crypto_key(request_type=dict)


@pytest.mark.asyncio
async def test_get_crypto_key_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.GetCryptoKeyRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_crypto_key), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKey(
                name="name_value",
                purpose=resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
            )
        )

        response = await client.get_crypto_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKey)

    assert response.name == "name_value"

    assert response.purpose == resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT


def test_get_crypto_key_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.GetCryptoKeyRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_crypto_key), "__call__") as call:
        call.return_value = resources.CryptoKey()

        client.get_crypto_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_get_crypto_key_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.GetCryptoKeyRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_crypto_key), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.CryptoKey())

        await client.get_crypto_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


def test_get_crypto_key_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_crypto_key), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKey()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.get_crypto_key(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


def test_get_crypto_key_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.get_crypto_key(
            service.GetCryptoKeyRequest(), name="name_value",
        )


@pytest.mark.asyncio
async def test_get_crypto_key_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_crypto_key), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKey()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.CryptoKey())
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.get_crypto_key(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


@pytest.mark.asyncio
async def test_get_crypto_key_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.get_crypto_key(
            service.GetCryptoKeyRequest(), name="name_value",
        )


def test_get_crypto_key_version(
    transport: str = "grpc", request_type=service.GetCryptoKeyVersionRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.get_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion(
            name="name_value",
            state=resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION,
            protection_level=resources.ProtectionLevel.SOFTWARE,
            algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
            import_job="import_job_value",
            import_failure_reason="import_failure_reason_value",
        )

        response = client.get_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.GetCryptoKeyVersionRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKeyVersion)

    assert response.name == "name_value"

    assert (
        response.state
        == resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.import_job == "import_job_value"

    assert response.import_failure_reason == "import_failure_reason_value"


def test_get_crypto_key_version_from_dict():
    test_get_crypto_key_version(request_type=dict)


@pytest.mark.asyncio
async def test_get_crypto_key_version_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.GetCryptoKeyVersionRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion(
                name="name_value",
                state=resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION,
                protection_level=resources.ProtectionLevel.SOFTWARE,
                algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
                import_job="import_job_value",
                import_failure_reason="import_failure_reason_value",
            )
        )

        response = await client.get_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKeyVersion)

    assert response.name == "name_value"

    assert (
        response.state
        == resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.import_job == "import_job_value"

    assert response.import_failure_reason == "import_failure_reason_value"


def test_get_crypto_key_version_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.GetCryptoKeyVersionRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.get_crypto_key_version), "__call__"
    ) as call:
        call.return_value = resources.CryptoKeyVersion()

        client.get_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_get_crypto_key_version_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.GetCryptoKeyVersionRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_crypto_key_version), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion()
        )

        await client.get_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


def test_get_crypto_key_version_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.get_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.get_crypto_key_version(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


def test_get_crypto_key_version_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.get_crypto_key_version(
            service.GetCryptoKeyVersionRequest(), name="name_value",
        )


@pytest.mark.asyncio
async def test_get_crypto_key_version_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.get_crypto_key_version(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


@pytest.mark.asyncio
async def test_get_crypto_key_version_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.get_crypto_key_version(
            service.GetCryptoKeyVersionRequest(), name="name_value",
        )


def test_get_public_key(
    transport: str = "grpc", request_type=service.GetPublicKeyRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_public_key), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.PublicKey(
            pem="pem_value",
            algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
            name="name_value",
        )

        response = client.get_public_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.GetPublicKeyRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.PublicKey)

    assert response.pem == "pem_value"

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.name == "name_value"


def test_get_public_key_from_dict():
    test_get_public_key(request_type=dict)


@pytest.mark.asyncio
async def test_get_public_key_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.GetPublicKeyRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_public_key), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.PublicKey(
                pem="pem_value",
                algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
                name="name_value",
            )
        )

        response = await client.get_public_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.PublicKey)

    assert response.pem == "pem_value"

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.name == "name_value"


def test_get_public_key_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.GetPublicKeyRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_public_key), "__call__") as call:
        call.return_value = resources.PublicKey()

        client.get_public_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_get_public_key_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.GetPublicKeyRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_public_key), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.PublicKey())

        await client.get_public_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


def test_get_public_key_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_public_key), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.PublicKey()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.get_public_key(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


def test_get_public_key_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.get_public_key(
            service.GetPublicKeyRequest(), name="name_value",
        )


@pytest.mark.asyncio
async def test_get_public_key_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_public_key), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.PublicKey()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.PublicKey())
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.get_public_key(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


@pytest.mark.asyncio
async def test_get_public_key_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.get_public_key(
            service.GetPublicKeyRequest(), name="name_value",
        )


def test_get_import_job(
    transport: str = "grpc", request_type=service.GetImportJobRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_import_job), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.ImportJob(
            name="name_value",
            import_method=resources.ImportJob.ImportMethod.RSA_OAEP_3072_SHA1_AES_256,
            protection_level=resources.ProtectionLevel.SOFTWARE,
            state=resources.ImportJob.ImportJobState.PENDING_GENERATION,
        )

        response = client.get_import_job(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.GetImportJobRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.ImportJob)

    assert response.name == "name_value"

    assert (
        response.import_method
        == resources.ImportJob.ImportMethod.RSA_OAEP_3072_SHA1_AES_256
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert response.state == resources.ImportJob.ImportJobState.PENDING_GENERATION


def test_get_import_job_from_dict():
    test_get_import_job(request_type=dict)


@pytest.mark.asyncio
async def test_get_import_job_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.GetImportJobRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_import_job), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.ImportJob(
                name="name_value",
                import_method=resources.ImportJob.ImportMethod.RSA_OAEP_3072_SHA1_AES_256,
                protection_level=resources.ProtectionLevel.SOFTWARE,
                state=resources.ImportJob.ImportJobState.PENDING_GENERATION,
            )
        )

        response = await client.get_import_job(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.ImportJob)

    assert response.name == "name_value"

    assert (
        response.import_method
        == resources.ImportJob.ImportMethod.RSA_OAEP_3072_SHA1_AES_256
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert response.state == resources.ImportJob.ImportJobState.PENDING_GENERATION


def test_get_import_job_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.GetImportJobRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_import_job), "__call__") as call:
        call.return_value = resources.ImportJob()

        client.get_import_job(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_get_import_job_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.GetImportJobRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_import_job), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.ImportJob())

        await client.get_import_job(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


def test_get_import_job_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_import_job), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.ImportJob()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.get_import_job(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


def test_get_import_job_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.get_import_job(
            service.GetImportJobRequest(), name="name_value",
        )


@pytest.mark.asyncio
async def test_get_import_job_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_import_job), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.ImportJob()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.ImportJob())
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.get_import_job(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


@pytest.mark.asyncio
async def test_get_import_job_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.get_import_job(
            service.GetImportJobRequest(), name="name_value",
        )


def test_create_key_ring(
    transport: str = "grpc", request_type=service.CreateKeyRingRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.create_key_ring), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.KeyRing(name="name_value",)

        response = client.create_key_ring(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.CreateKeyRingRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.KeyRing)

    assert response.name == "name_value"


def test_create_key_ring_from_dict():
    test_create_key_ring(request_type=dict)


@pytest.mark.asyncio
async def test_create_key_ring_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.CreateKeyRingRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.create_key_ring), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.KeyRing(name="name_value",)
        )

        response = await client.create_key_ring(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.KeyRing)

    assert response.name == "name_value"


def test_create_key_ring_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.CreateKeyRingRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.create_key_ring), "__call__") as call:
        call.return_value = resources.KeyRing()

        client.create_key_ring(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_create_key_ring_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.CreateKeyRingRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.create_key_ring), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.KeyRing())

        await client.create_key_ring(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


def test_create_key_ring_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.create_key_ring), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.KeyRing()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.create_key_ring(
            parent="parent_value",
            key_ring_id="key_ring_id_value",
            key_ring=resources.KeyRing(name="name_value"),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"

        assert args[0].key_ring_id == "key_ring_id_value"

        assert args[0].key_ring == resources.KeyRing(name="name_value")


def test_create_key_ring_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.create_key_ring(
            service.CreateKeyRingRequest(),
            parent="parent_value",
            key_ring_id="key_ring_id_value",
            key_ring=resources.KeyRing(name="name_value"),
        )


@pytest.mark.asyncio
async def test_create_key_ring_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.create_key_ring), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.KeyRing()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.KeyRing())
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.create_key_ring(
            parent="parent_value",
            key_ring_id="key_ring_id_value",
            key_ring=resources.KeyRing(name="name_value"),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"

        assert args[0].key_ring_id == "key_ring_id_value"

        assert args[0].key_ring == resources.KeyRing(name="name_value")


@pytest.mark.asyncio
async def test_create_key_ring_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.create_key_ring(
            service.CreateKeyRingRequest(),
            parent="parent_value",
            key_ring_id="key_ring_id_value",
            key_ring=resources.KeyRing(name="name_value"),
        )


def test_create_crypto_key(
    transport: str = "grpc", request_type=service.CreateCryptoKeyRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.create_crypto_key), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKey(
            name="name_value",
            purpose=resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
            rotation_period=duration.Duration(seconds=751),
        )

        response = client.create_crypto_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.CreateCryptoKeyRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKey)

    assert response.name == "name_value"

    assert response.purpose == resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT


def test_create_crypto_key_from_dict():
    test_create_crypto_key(request_type=dict)


@pytest.mark.asyncio
async def test_create_crypto_key_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.CreateCryptoKeyRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.create_crypto_key), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKey(
                name="name_value",
                purpose=resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
            )
        )

        response = await client.create_crypto_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKey)

    assert response.name == "name_value"

    assert response.purpose == resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT


def test_create_crypto_key_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.CreateCryptoKeyRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.create_crypto_key), "__call__"
    ) as call:
        call.return_value = resources.CryptoKey()

        client.create_crypto_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_create_crypto_key_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.CreateCryptoKeyRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.create_crypto_key), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.CryptoKey())

        await client.create_crypto_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


def test_create_crypto_key_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.create_crypto_key), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKey()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.create_crypto_key(
            parent="parent_value",
            crypto_key_id="crypto_key_id_value",
            crypto_key=resources.CryptoKey(name="name_value"),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"

        assert args[0].crypto_key_id == "crypto_key_id_value"

        assert args[0].crypto_key == resources.CryptoKey(name="name_value")


def test_create_crypto_key_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.create_crypto_key(
            service.CreateCryptoKeyRequest(),
            parent="parent_value",
            crypto_key_id="crypto_key_id_value",
            crypto_key=resources.CryptoKey(name="name_value"),
        )


@pytest.mark.asyncio
async def test_create_crypto_key_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.create_crypto_key), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKey()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.CryptoKey())
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.create_crypto_key(
            parent="parent_value",
            crypto_key_id="crypto_key_id_value",
            crypto_key=resources.CryptoKey(name="name_value"),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"

        assert args[0].crypto_key_id == "crypto_key_id_value"

        assert args[0].crypto_key == resources.CryptoKey(name="name_value")


@pytest.mark.asyncio
async def test_create_crypto_key_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.create_crypto_key(
            service.CreateCryptoKeyRequest(),
            parent="parent_value",
            crypto_key_id="crypto_key_id_value",
            crypto_key=resources.CryptoKey(name="name_value"),
        )


def test_create_crypto_key_version(
    transport: str = "grpc", request_type=service.CreateCryptoKeyVersionRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.create_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion(
            name="name_value",
            state=resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION,
            protection_level=resources.ProtectionLevel.SOFTWARE,
            algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
            import_job="import_job_value",
            import_failure_reason="import_failure_reason_value",
        )

        response = client.create_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.CreateCryptoKeyVersionRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKeyVersion)

    assert response.name == "name_value"

    assert (
        response.state
        == resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.import_job == "import_job_value"

    assert response.import_failure_reason == "import_failure_reason_value"


def test_create_crypto_key_version_from_dict():
    test_create_crypto_key_version(request_type=dict)


@pytest.mark.asyncio
async def test_create_crypto_key_version_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.CreateCryptoKeyVersionRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.create_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion(
                name="name_value",
                state=resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION,
                protection_level=resources.ProtectionLevel.SOFTWARE,
                algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
                import_job="import_job_value",
                import_failure_reason="import_failure_reason_value",
            )
        )

        response = await client.create_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKeyVersion)

    assert response.name == "name_value"

    assert (
        response.state
        == resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.import_job == "import_job_value"

    assert response.import_failure_reason == "import_failure_reason_value"


def test_create_crypto_key_version_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.CreateCryptoKeyVersionRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.create_crypto_key_version), "__call__"
    ) as call:
        call.return_value = resources.CryptoKeyVersion()

        client.create_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_create_crypto_key_version_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.CreateCryptoKeyVersionRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.create_crypto_key_version), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion()
        )

        await client.create_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


def test_create_crypto_key_version_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.create_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.create_crypto_key_version(
            parent="parent_value",
            crypto_key_version=resources.CryptoKeyVersion(name="name_value"),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"

        assert args[0].crypto_key_version == resources.CryptoKeyVersion(
            name="name_value"
        )


def test_create_crypto_key_version_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.create_crypto_key_version(
            service.CreateCryptoKeyVersionRequest(),
            parent="parent_value",
            crypto_key_version=resources.CryptoKeyVersion(name="name_value"),
        )


@pytest.mark.asyncio
async def test_create_crypto_key_version_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.create_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.create_crypto_key_version(
            parent="parent_value",
            crypto_key_version=resources.CryptoKeyVersion(name="name_value"),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"

        assert args[0].crypto_key_version == resources.CryptoKeyVersion(
            name="name_value"
        )


@pytest.mark.asyncio
async def test_create_crypto_key_version_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.create_crypto_key_version(
            service.CreateCryptoKeyVersionRequest(),
            parent="parent_value",
            crypto_key_version=resources.CryptoKeyVersion(name="name_value"),
        )


def test_import_crypto_key_version(
    transport: str = "grpc", request_type=service.ImportCryptoKeyVersionRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.import_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion(
            name="name_value",
            state=resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION,
            protection_level=resources.ProtectionLevel.SOFTWARE,
            algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
            import_job="import_job_value",
            import_failure_reason="import_failure_reason_value",
        )

        response = client.import_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.ImportCryptoKeyVersionRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKeyVersion)

    assert response.name == "name_value"

    assert (
        response.state
        == resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.import_job == "import_job_value"

    assert response.import_failure_reason == "import_failure_reason_value"


def test_import_crypto_key_version_from_dict():
    test_import_crypto_key_version(request_type=dict)


@pytest.mark.asyncio
async def test_import_crypto_key_version_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.ImportCryptoKeyVersionRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.import_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion(
                name="name_value",
                state=resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION,
                protection_level=resources.ProtectionLevel.SOFTWARE,
                algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
                import_job="import_job_value",
                import_failure_reason="import_failure_reason_value",
            )
        )

        response = await client.import_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKeyVersion)

    assert response.name == "name_value"

    assert (
        response.state
        == resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.import_job == "import_job_value"

    assert response.import_failure_reason == "import_failure_reason_value"


def test_import_crypto_key_version_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.ImportCryptoKeyVersionRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.import_crypto_key_version), "__call__"
    ) as call:
        call.return_value = resources.CryptoKeyVersion()

        client.import_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_import_crypto_key_version_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.ImportCryptoKeyVersionRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.import_crypto_key_version), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion()
        )

        await client.import_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


def test_create_import_job(
    transport: str = "grpc", request_type=service.CreateImportJobRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.create_import_job), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.ImportJob(
            name="name_value",
            import_method=resources.ImportJob.ImportMethod.RSA_OAEP_3072_SHA1_AES_256,
            protection_level=resources.ProtectionLevel.SOFTWARE,
            state=resources.ImportJob.ImportJobState.PENDING_GENERATION,
        )

        response = client.create_import_job(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.CreateImportJobRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.ImportJob)

    assert response.name == "name_value"

    assert (
        response.import_method
        == resources.ImportJob.ImportMethod.RSA_OAEP_3072_SHA1_AES_256
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert response.state == resources.ImportJob.ImportJobState.PENDING_GENERATION


def test_create_import_job_from_dict():
    test_create_import_job(request_type=dict)


@pytest.mark.asyncio
async def test_create_import_job_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.CreateImportJobRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.create_import_job), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.ImportJob(
                name="name_value",
                import_method=resources.ImportJob.ImportMethod.RSA_OAEP_3072_SHA1_AES_256,
                protection_level=resources.ProtectionLevel.SOFTWARE,
                state=resources.ImportJob.ImportJobState.PENDING_GENERATION,
            )
        )

        response = await client.create_import_job(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.ImportJob)

    assert response.name == "name_value"

    assert (
        response.import_method
        == resources.ImportJob.ImportMethod.RSA_OAEP_3072_SHA1_AES_256
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert response.state == resources.ImportJob.ImportJobState.PENDING_GENERATION


def test_create_import_job_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.CreateImportJobRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.create_import_job), "__call__"
    ) as call:
        call.return_value = resources.ImportJob()

        client.create_import_job(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_create_import_job_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.CreateImportJobRequest()
    request.parent = "parent/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.create_import_job), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.ImportJob())

        await client.create_import_job(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "parent=parent/value",) in kw["metadata"]


def test_create_import_job_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.create_import_job), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.ImportJob()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.create_import_job(
            parent="parent_value",
            import_job_id="import_job_id_value",
            import_job=resources.ImportJob(name="name_value"),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"

        assert args[0].import_job_id == "import_job_id_value"

        assert args[0].import_job == resources.ImportJob(name="name_value")


def test_create_import_job_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.create_import_job(
            service.CreateImportJobRequest(),
            parent="parent_value",
            import_job_id="import_job_id_value",
            import_job=resources.ImportJob(name="name_value"),
        )


@pytest.mark.asyncio
async def test_create_import_job_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.create_import_job), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.ImportJob()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.ImportJob())
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.create_import_job(
            parent="parent_value",
            import_job_id="import_job_id_value",
            import_job=resources.ImportJob(name="name_value"),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].parent == "parent_value"

        assert args[0].import_job_id == "import_job_id_value"

        assert args[0].import_job == resources.ImportJob(name="name_value")


@pytest.mark.asyncio
async def test_create_import_job_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.create_import_job(
            service.CreateImportJobRequest(),
            parent="parent_value",
            import_job_id="import_job_id_value",
            import_job=resources.ImportJob(name="name_value"),
        )


def test_update_crypto_key(
    transport: str = "grpc", request_type=service.UpdateCryptoKeyRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.update_crypto_key), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKey(
            name="name_value",
            purpose=resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
            rotation_period=duration.Duration(seconds=751),
        )

        response = client.update_crypto_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.UpdateCryptoKeyRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKey)

    assert response.name == "name_value"

    assert response.purpose == resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT


def test_update_crypto_key_from_dict():
    test_update_crypto_key(request_type=dict)


@pytest.mark.asyncio
async def test_update_crypto_key_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.UpdateCryptoKeyRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.update_crypto_key), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKey(
                name="name_value",
                purpose=resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
            )
        )

        response = await client.update_crypto_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKey)

    assert response.name == "name_value"

    assert response.purpose == resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT


def test_update_crypto_key_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.UpdateCryptoKeyRequest()
    request.crypto_key.name = "crypto_key.name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.update_crypto_key), "__call__"
    ) as call:
        call.return_value = resources.CryptoKey()

        client.update_crypto_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "crypto_key.name=crypto_key.name/value",) in kw[
        "metadata"
    ]


@pytest.mark.asyncio
async def test_update_crypto_key_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.UpdateCryptoKeyRequest()
    request.crypto_key.name = "crypto_key.name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.update_crypto_key), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.CryptoKey())

        await client.update_crypto_key(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "crypto_key.name=crypto_key.name/value",) in kw[
        "metadata"
    ]


def test_update_crypto_key_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.update_crypto_key), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKey()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.update_crypto_key(
            crypto_key=resources.CryptoKey(name="name_value"),
            update_mask=field_mask.FieldMask(paths=["paths_value"]),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].crypto_key == resources.CryptoKey(name="name_value")

        assert args[0].update_mask == field_mask.FieldMask(paths=["paths_value"])


def test_update_crypto_key_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.update_crypto_key(
            service.UpdateCryptoKeyRequest(),
            crypto_key=resources.CryptoKey(name="name_value"),
            update_mask=field_mask.FieldMask(paths=["paths_value"]),
        )


@pytest.mark.asyncio
async def test_update_crypto_key_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.update_crypto_key), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKey()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.CryptoKey())
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.update_crypto_key(
            crypto_key=resources.CryptoKey(name="name_value"),
            update_mask=field_mask.FieldMask(paths=["paths_value"]),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].crypto_key == resources.CryptoKey(name="name_value")

        assert args[0].update_mask == field_mask.FieldMask(paths=["paths_value"])


@pytest.mark.asyncio
async def test_update_crypto_key_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.update_crypto_key(
            service.UpdateCryptoKeyRequest(),
            crypto_key=resources.CryptoKey(name="name_value"),
            update_mask=field_mask.FieldMask(paths=["paths_value"]),
        )


def test_update_crypto_key_version(
    transport: str = "grpc", request_type=service.UpdateCryptoKeyVersionRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.update_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion(
            name="name_value",
            state=resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION,
            protection_level=resources.ProtectionLevel.SOFTWARE,
            algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
            import_job="import_job_value",
            import_failure_reason="import_failure_reason_value",
        )

        response = client.update_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.UpdateCryptoKeyVersionRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKeyVersion)

    assert response.name == "name_value"

    assert (
        response.state
        == resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.import_job == "import_job_value"

    assert response.import_failure_reason == "import_failure_reason_value"


def test_update_crypto_key_version_from_dict():
    test_update_crypto_key_version(request_type=dict)


@pytest.mark.asyncio
async def test_update_crypto_key_version_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.UpdateCryptoKeyVersionRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.update_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion(
                name="name_value",
                state=resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION,
                protection_level=resources.ProtectionLevel.SOFTWARE,
                algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
                import_job="import_job_value",
                import_failure_reason="import_failure_reason_value",
            )
        )

        response = await client.update_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKeyVersion)

    assert response.name == "name_value"

    assert (
        response.state
        == resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.import_job == "import_job_value"

    assert response.import_failure_reason == "import_failure_reason_value"


def test_update_crypto_key_version_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.UpdateCryptoKeyVersionRequest()
    request.crypto_key_version.name = "crypto_key_version.name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.update_crypto_key_version), "__call__"
    ) as call:
        call.return_value = resources.CryptoKeyVersion()

        client.update_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert (
        "x-goog-request-params",
        "crypto_key_version.name=crypto_key_version.name/value",
    ) in kw["metadata"]


@pytest.mark.asyncio
async def test_update_crypto_key_version_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.UpdateCryptoKeyVersionRequest()
    request.crypto_key_version.name = "crypto_key_version.name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.update_crypto_key_version), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion()
        )

        await client.update_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert (
        "x-goog-request-params",
        "crypto_key_version.name=crypto_key_version.name/value",
    ) in kw["metadata"]


def test_update_crypto_key_version_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.update_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.update_crypto_key_version(
            crypto_key_version=resources.CryptoKeyVersion(name="name_value"),
            update_mask=field_mask.FieldMask(paths=["paths_value"]),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].crypto_key_version == resources.CryptoKeyVersion(
            name="name_value"
        )

        assert args[0].update_mask == field_mask.FieldMask(paths=["paths_value"])


def test_update_crypto_key_version_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.update_crypto_key_version(
            service.UpdateCryptoKeyVersionRequest(),
            crypto_key_version=resources.CryptoKeyVersion(name="name_value"),
            update_mask=field_mask.FieldMask(paths=["paths_value"]),
        )


@pytest.mark.asyncio
async def test_update_crypto_key_version_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.update_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.update_crypto_key_version(
            crypto_key_version=resources.CryptoKeyVersion(name="name_value"),
            update_mask=field_mask.FieldMask(paths=["paths_value"]),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].crypto_key_version == resources.CryptoKeyVersion(
            name="name_value"
        )

        assert args[0].update_mask == field_mask.FieldMask(paths=["paths_value"])


@pytest.mark.asyncio
async def test_update_crypto_key_version_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.update_crypto_key_version(
            service.UpdateCryptoKeyVersionRequest(),
            crypto_key_version=resources.CryptoKeyVersion(name="name_value"),
            update_mask=field_mask.FieldMask(paths=["paths_value"]),
        )


def test_encrypt(transport: str = "grpc", request_type=service.EncryptRequest):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.encrypt), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.EncryptResponse(
            name="name_value",
            ciphertext=b"ciphertext_blob",
            verified_plaintext_crc32c=True,
            verified_additional_authenticated_data_crc32c=True,
        )

        response = client.encrypt(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.EncryptRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, service.EncryptResponse)

    assert response.name == "name_value"

    assert response.ciphertext == b"ciphertext_blob"

    assert response.verified_plaintext_crc32c is True

    assert response.verified_additional_authenticated_data_crc32c is True


def test_encrypt_from_dict():
    test_encrypt(request_type=dict)


@pytest.mark.asyncio
async def test_encrypt_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.EncryptRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._client._transport.encrypt), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.EncryptResponse(
                name="name_value",
                ciphertext=b"ciphertext_blob",
                verified_plaintext_crc32c=True,
                verified_additional_authenticated_data_crc32c=True,
            )
        )

        response = await client.encrypt(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, service.EncryptResponse)

    assert response.name == "name_value"

    assert response.ciphertext == b"ciphertext_blob"

    assert response.verified_plaintext_crc32c is True

    assert response.verified_additional_authenticated_data_crc32c is True


def test_encrypt_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.EncryptRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.encrypt), "__call__") as call:
        call.return_value = service.EncryptResponse()

        client.encrypt(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_encrypt_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.EncryptRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._client._transport.encrypt), "__call__") as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.EncryptResponse()
        )

        await client.encrypt(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


def test_encrypt_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.encrypt), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.EncryptResponse()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.encrypt(
            name="name_value", plaintext=b"plaintext_blob",
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"

        assert args[0].plaintext == b"plaintext_blob"


def test_encrypt_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.encrypt(
            service.EncryptRequest(), name="name_value", plaintext=b"plaintext_blob",
        )


@pytest.mark.asyncio
async def test_encrypt_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._client._transport.encrypt), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.EncryptResponse()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.EncryptResponse()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.encrypt(name="name_value", plaintext=b"plaintext_blob",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"

        assert args[0].plaintext == b"plaintext_blob"


@pytest.mark.asyncio
async def test_encrypt_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.encrypt(
            service.EncryptRequest(), name="name_value", plaintext=b"plaintext_blob",
        )


def test_decrypt(transport: str = "grpc", request_type=service.DecryptRequest):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.decrypt), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.DecryptResponse(plaintext=b"plaintext_blob",)

        response = client.decrypt(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.DecryptRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, service.DecryptResponse)

    assert response.plaintext == b"plaintext_blob"


def test_decrypt_from_dict():
    test_decrypt(request_type=dict)


@pytest.mark.asyncio
async def test_decrypt_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.DecryptRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._client._transport.decrypt), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.DecryptResponse(plaintext=b"plaintext_blob",)
        )

        response = await client.decrypt(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, service.DecryptResponse)

    assert response.plaintext == b"plaintext_blob"


def test_decrypt_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.DecryptRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.decrypt), "__call__") as call:
        call.return_value = service.DecryptResponse()

        client.decrypt(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_decrypt_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.DecryptRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._client._transport.decrypt), "__call__") as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.DecryptResponse()
        )

        await client.decrypt(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


def test_decrypt_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.decrypt), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.DecryptResponse()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.decrypt(
            name="name_value", ciphertext=b"ciphertext_blob",
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"

        assert args[0].ciphertext == b"ciphertext_blob"


def test_decrypt_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.decrypt(
            service.DecryptRequest(), name="name_value", ciphertext=b"ciphertext_blob",
        )


@pytest.mark.asyncio
async def test_decrypt_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._client._transport.decrypt), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.DecryptResponse()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.DecryptResponse()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.decrypt(
            name="name_value", ciphertext=b"ciphertext_blob",
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"

        assert args[0].ciphertext == b"ciphertext_blob"


@pytest.mark.asyncio
async def test_decrypt_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.decrypt(
            service.DecryptRequest(), name="name_value", ciphertext=b"ciphertext_blob",
        )


def test_asymmetric_sign(
    transport: str = "grpc", request_type=service.AsymmetricSignRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.asymmetric_sign), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.AsymmetricSignResponse(
            signature=b"signature_blob", verified_digest_crc32c=True, name="name_value",
        )

        response = client.asymmetric_sign(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.AsymmetricSignRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, service.AsymmetricSignResponse)

    assert response.signature == b"signature_blob"

    assert response.verified_digest_crc32c is True

    assert response.name == "name_value"


def test_asymmetric_sign_from_dict():
    test_asymmetric_sign(request_type=dict)


@pytest.mark.asyncio
async def test_asymmetric_sign_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.AsymmetricSignRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.asymmetric_sign), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.AsymmetricSignResponse(
                signature=b"signature_blob",
                verified_digest_crc32c=True,
                name="name_value",
            )
        )

        response = await client.asymmetric_sign(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, service.AsymmetricSignResponse)

    assert response.signature == b"signature_blob"

    assert response.verified_digest_crc32c is True

    assert response.name == "name_value"


def test_asymmetric_sign_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.AsymmetricSignRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.asymmetric_sign), "__call__") as call:
        call.return_value = service.AsymmetricSignResponse()

        client.asymmetric_sign(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_asymmetric_sign_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.AsymmetricSignRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.asymmetric_sign), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.AsymmetricSignResponse()
        )

        await client.asymmetric_sign(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


def test_asymmetric_sign_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.asymmetric_sign), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.AsymmetricSignResponse()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.asymmetric_sign(
            name="name_value", digest=service.Digest(sha256=b"sha256_blob"),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"

        assert args[0].digest == service.Digest(sha256=b"sha256_blob")


def test_asymmetric_sign_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.asymmetric_sign(
            service.AsymmetricSignRequest(),
            name="name_value",
            digest=service.Digest(sha256=b"sha256_blob"),
        )


@pytest.mark.asyncio
async def test_asymmetric_sign_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.asymmetric_sign), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.AsymmetricSignResponse()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.AsymmetricSignResponse()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.asymmetric_sign(
            name="name_value", digest=service.Digest(sha256=b"sha256_blob"),
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"

        assert args[0].digest == service.Digest(sha256=b"sha256_blob")


@pytest.mark.asyncio
async def test_asymmetric_sign_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.asymmetric_sign(
            service.AsymmetricSignRequest(),
            name="name_value",
            digest=service.Digest(sha256=b"sha256_blob"),
        )


def test_asymmetric_decrypt(
    transport: str = "grpc", request_type=service.AsymmetricDecryptRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.asymmetric_decrypt), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.AsymmetricDecryptResponse(
            plaintext=b"plaintext_blob", verified_ciphertext_crc32c=True,
        )

        response = client.asymmetric_decrypt(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.AsymmetricDecryptRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, service.AsymmetricDecryptResponse)

    assert response.plaintext == b"plaintext_blob"

    assert response.verified_ciphertext_crc32c is True


def test_asymmetric_decrypt_from_dict():
    test_asymmetric_decrypt(request_type=dict)


@pytest.mark.asyncio
async def test_asymmetric_decrypt_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.AsymmetricDecryptRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.asymmetric_decrypt), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.AsymmetricDecryptResponse(
                plaintext=b"plaintext_blob", verified_ciphertext_crc32c=True,
            )
        )

        response = await client.asymmetric_decrypt(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, service.AsymmetricDecryptResponse)

    assert response.plaintext == b"plaintext_blob"

    assert response.verified_ciphertext_crc32c is True


def test_asymmetric_decrypt_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.AsymmetricDecryptRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.asymmetric_decrypt), "__call__"
    ) as call:
        call.return_value = service.AsymmetricDecryptResponse()

        client.asymmetric_decrypt(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_asymmetric_decrypt_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.AsymmetricDecryptRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.asymmetric_decrypt), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.AsymmetricDecryptResponse()
        )

        await client.asymmetric_decrypt(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


def test_asymmetric_decrypt_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.asymmetric_decrypt), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.AsymmetricDecryptResponse()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.asymmetric_decrypt(
            name="name_value", ciphertext=b"ciphertext_blob",
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"

        assert args[0].ciphertext == b"ciphertext_blob"


def test_asymmetric_decrypt_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.asymmetric_decrypt(
            service.AsymmetricDecryptRequest(),
            name="name_value",
            ciphertext=b"ciphertext_blob",
        )


@pytest.mark.asyncio
async def test_asymmetric_decrypt_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.asymmetric_decrypt), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = service.AsymmetricDecryptResponse()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            service.AsymmetricDecryptResponse()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.asymmetric_decrypt(
            name="name_value", ciphertext=b"ciphertext_blob",
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"

        assert args[0].ciphertext == b"ciphertext_blob"


@pytest.mark.asyncio
async def test_asymmetric_decrypt_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.asymmetric_decrypt(
            service.AsymmetricDecryptRequest(),
            name="name_value",
            ciphertext=b"ciphertext_blob",
        )


def test_update_crypto_key_primary_version(
    transport: str = "grpc", request_type=service.UpdateCryptoKeyPrimaryVersionRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.update_crypto_key_primary_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKey(
            name="name_value",
            purpose=resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
            rotation_period=duration.Duration(seconds=751),
        )

        response = client.update_crypto_key_primary_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.UpdateCryptoKeyPrimaryVersionRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKey)

    assert response.name == "name_value"

    assert response.purpose == resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT


def test_update_crypto_key_primary_version_from_dict():
    test_update_crypto_key_primary_version(request_type=dict)


@pytest.mark.asyncio
async def test_update_crypto_key_primary_version_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.UpdateCryptoKeyPrimaryVersionRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.update_crypto_key_primary_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKey(
                name="name_value",
                purpose=resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
            )
        )

        response = await client.update_crypto_key_primary_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKey)

    assert response.name == "name_value"

    assert response.purpose == resources.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT


def test_update_crypto_key_primary_version_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.UpdateCryptoKeyPrimaryVersionRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.update_crypto_key_primary_version), "__call__"
    ) as call:
        call.return_value = resources.CryptoKey()

        client.update_crypto_key_primary_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_update_crypto_key_primary_version_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.UpdateCryptoKeyPrimaryVersionRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.update_crypto_key_primary_version), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.CryptoKey())

        await client.update_crypto_key_primary_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


def test_update_crypto_key_primary_version_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.update_crypto_key_primary_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKey()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.update_crypto_key_primary_version(
            name="name_value", crypto_key_version_id="crypto_key_version_id_value",
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"

        assert args[0].crypto_key_version_id == "crypto_key_version_id_value"


def test_update_crypto_key_primary_version_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.update_crypto_key_primary_version(
            service.UpdateCryptoKeyPrimaryVersionRequest(),
            name="name_value",
            crypto_key_version_id="crypto_key_version_id_value",
        )


@pytest.mark.asyncio
async def test_update_crypto_key_primary_version_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.update_crypto_key_primary_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKey()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(resources.CryptoKey())
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.update_crypto_key_primary_version(
            name="name_value", crypto_key_version_id="crypto_key_version_id_value",
        )

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"

        assert args[0].crypto_key_version_id == "crypto_key_version_id_value"


@pytest.mark.asyncio
async def test_update_crypto_key_primary_version_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.update_crypto_key_primary_version(
            service.UpdateCryptoKeyPrimaryVersionRequest(),
            name="name_value",
            crypto_key_version_id="crypto_key_version_id_value",
        )


def test_destroy_crypto_key_version(
    transport: str = "grpc", request_type=service.DestroyCryptoKeyVersionRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.destroy_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion(
            name="name_value",
            state=resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION,
            protection_level=resources.ProtectionLevel.SOFTWARE,
            algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
            import_job="import_job_value",
            import_failure_reason="import_failure_reason_value",
        )

        response = client.destroy_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.DestroyCryptoKeyVersionRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKeyVersion)

    assert response.name == "name_value"

    assert (
        response.state
        == resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.import_job == "import_job_value"

    assert response.import_failure_reason == "import_failure_reason_value"


def test_destroy_crypto_key_version_from_dict():
    test_destroy_crypto_key_version(request_type=dict)


@pytest.mark.asyncio
async def test_destroy_crypto_key_version_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.DestroyCryptoKeyVersionRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.destroy_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion(
                name="name_value",
                state=resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION,
                protection_level=resources.ProtectionLevel.SOFTWARE,
                algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
                import_job="import_job_value",
                import_failure_reason="import_failure_reason_value",
            )
        )

        response = await client.destroy_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKeyVersion)

    assert response.name == "name_value"

    assert (
        response.state
        == resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.import_job == "import_job_value"

    assert response.import_failure_reason == "import_failure_reason_value"


def test_destroy_crypto_key_version_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.DestroyCryptoKeyVersionRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.destroy_crypto_key_version), "__call__"
    ) as call:
        call.return_value = resources.CryptoKeyVersion()

        client.destroy_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_destroy_crypto_key_version_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.DestroyCryptoKeyVersionRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.destroy_crypto_key_version), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion()
        )

        await client.destroy_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


def test_destroy_crypto_key_version_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.destroy_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.destroy_crypto_key_version(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


def test_destroy_crypto_key_version_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.destroy_crypto_key_version(
            service.DestroyCryptoKeyVersionRequest(), name="name_value",
        )


@pytest.mark.asyncio
async def test_destroy_crypto_key_version_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.destroy_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.destroy_crypto_key_version(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


@pytest.mark.asyncio
async def test_destroy_crypto_key_version_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.destroy_crypto_key_version(
            service.DestroyCryptoKeyVersionRequest(), name="name_value",
        )


def test_restore_crypto_key_version(
    transport: str = "grpc", request_type=service.RestoreCryptoKeyVersionRequest
):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = request_type()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.restore_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion(
            name="name_value",
            state=resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION,
            protection_level=resources.ProtectionLevel.SOFTWARE,
            algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
            import_job="import_job_value",
            import_failure_reason="import_failure_reason_value",
        )

        response = client.restore_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == service.RestoreCryptoKeyVersionRequest()

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKeyVersion)

    assert response.name == "name_value"

    assert (
        response.state
        == resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.import_job == "import_job_value"

    assert response.import_failure_reason == "import_failure_reason_value"


def test_restore_crypto_key_version_from_dict():
    test_restore_crypto_key_version(request_type=dict)


@pytest.mark.asyncio
async def test_restore_crypto_key_version_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = service.RestoreCryptoKeyVersionRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.restore_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion(
                name="name_value",
                state=resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION,
                protection_level=resources.ProtectionLevel.SOFTWARE,
                algorithm=resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
                import_job="import_job_value",
                import_failure_reason="import_failure_reason_value",
            )
        )

        response = await client.restore_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, resources.CryptoKeyVersion)

    assert response.name == "name_value"

    assert (
        response.state
        == resources.CryptoKeyVersion.CryptoKeyVersionState.PENDING_GENERATION
    )

    assert response.protection_level == resources.ProtectionLevel.SOFTWARE

    assert (
        response.algorithm
        == resources.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
    )

    assert response.import_job == "import_job_value"

    assert response.import_failure_reason == "import_failure_reason_value"


def test_restore_crypto_key_version_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.RestoreCryptoKeyVersionRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.restore_crypto_key_version), "__call__"
    ) as call:
        call.return_value = resources.CryptoKeyVersion()

        client.restore_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_restore_crypto_key_version_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = service.RestoreCryptoKeyVersionRequest()
    request.name = "name/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.restore_crypto_key_version), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion()
        )

        await client.restore_crypto_key_version(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "name=name/value",) in kw["metadata"]


def test_restore_crypto_key_version_flattened():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.restore_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion()

        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        client.restore_crypto_key_version(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


def test_restore_crypto_key_version_flattened_error():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        client.restore_crypto_key_version(
            service.RestoreCryptoKeyVersionRequest(), name="name_value",
        )


@pytest.mark.asyncio
async def test_restore_crypto_key_version_flattened_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.restore_crypto_key_version), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = resources.CryptoKeyVersion()

        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            resources.CryptoKeyVersion()
        )
        # Call the method with a truthy value for each flattened field,
        # using the keyword arguments to the method.
        response = await client.restore_crypto_key_version(name="name_value",)

        # Establish that the underlying call was made with the expected
        # request object values.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0].name == "name_value"


@pytest.mark.asyncio
async def test_restore_crypto_key_version_flattened_error_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Attempting to call a method with both a request object and flattened
    # fields is an error.
    with pytest.raises(ValueError):
        await client.restore_crypto_key_version(
            service.RestoreCryptoKeyVersionRequest(), name="name_value",
        )


def test_credentials_transport_error():
    # It is an error to provide credentials and a transport instance.
    transport = transports.KeyManagementServiceGrpcTransport(
        credentials=credentials.AnonymousCredentials(),
    )
    with pytest.raises(ValueError):
        client = KeyManagementServiceClient(
            credentials=credentials.AnonymousCredentials(), transport=transport,
        )

    # It is an error to provide a credentials file and a transport instance.
    transport = transports.KeyManagementServiceGrpcTransport(
        credentials=credentials.AnonymousCredentials(),
    )
    with pytest.raises(ValueError):
        client = KeyManagementServiceClient(
            client_options={"credentials_file": "credentials.json"},
            transport=transport,
        )

    # It is an error to provide scopes and a transport instance.
    transport = transports.KeyManagementServiceGrpcTransport(
        credentials=credentials.AnonymousCredentials(),
    )
    with pytest.raises(ValueError):
        client = KeyManagementServiceClient(
            client_options={"scopes": ["1", "2"]}, transport=transport,
        )


def test_transport_instance():
    # A client may be instantiated with a custom transport instance.
    transport = transports.KeyManagementServiceGrpcTransport(
        credentials=credentials.AnonymousCredentials(),
    )
    client = KeyManagementServiceClient(transport=transport)
    assert client._transport is transport


def test_transport_get_channel():
    # A client may be instantiated with a custom transport instance.
    transport = transports.KeyManagementServiceGrpcTransport(
        credentials=credentials.AnonymousCredentials(),
    )
    channel = transport.grpc_channel
    assert channel

    transport = transports.KeyManagementServiceGrpcAsyncIOTransport(
        credentials=credentials.AnonymousCredentials(),
    )
    channel = transport.grpc_channel
    assert channel


@pytest.mark.parametrize(
    "transport_class",
    [
        transports.KeyManagementServiceGrpcTransport,
        transports.KeyManagementServiceGrpcAsyncIOTransport,
    ],
)
def test_transport_adc(transport_class):
    # Test default credentials are used if not provided.
    with mock.patch.object(auth, "default") as adc:
        adc.return_value = (credentials.AnonymousCredentials(), None)
        transport_class()
        adc.assert_called_once()


def test_transport_grpc_default():
    # A client should use the gRPC transport by default.
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)
    assert isinstance(client._transport, transports.KeyManagementServiceGrpcTransport,)


def test_key_management_service_base_transport_error():
    # Passing both a credentials object and credentials_file should raise an error
    with pytest.raises(exceptions.DuplicateCredentialArgs):
        transport = transports.KeyManagementServiceTransport(
            credentials=credentials.AnonymousCredentials(),
            credentials_file="credentials.json",
        )


def test_key_management_service_base_transport():
    # Instantiate the base transport.
    with mock.patch(
        "google.cloud.kms_v1.services.key_management_service.transports.KeyManagementServiceTransport.__init__"
    ) as Transport:
        Transport.return_value = None
        transport = transports.KeyManagementServiceTransport(
            credentials=credentials.AnonymousCredentials(),
        )

    # Every method on the transport should just blindly
    # raise NotImplementedError.
    methods = (
        "list_key_rings",
        "list_crypto_keys",
        "list_crypto_key_versions",
        "list_import_jobs",
        "get_key_ring",
        "get_crypto_key",
        "get_crypto_key_version",
        "get_public_key",
        "get_import_job",
        "create_key_ring",
        "create_crypto_key",
        "create_crypto_key_version",
        "import_crypto_key_version",
        "create_import_job",
        "update_crypto_key",
        "update_crypto_key_version",
        "encrypt",
        "decrypt",
        "asymmetric_sign",
        "asymmetric_decrypt",
        "update_crypto_key_primary_version",
        "destroy_crypto_key_version",
        "restore_crypto_key_version",
        "set_iam_policy",
        "get_iam_policy",
        "test_iam_permissions",
    )
    for method in methods:
        with pytest.raises(NotImplementedError):
            getattr(transport, method)(request=object())


def test_key_management_service_base_transport_with_credentials_file():
    # Instantiate the base transport with a credentials file
    with mock.patch.object(
        auth, "load_credentials_from_file"
    ) as load_creds, mock.patch(
        "google.cloud.kms_v1.services.key_management_service.transports.KeyManagementServiceTransport._prep_wrapped_messages"
    ) as Transport:
        Transport.return_value = None
        load_creds.return_value = (credentials.AnonymousCredentials(), None)
        transport = transports.KeyManagementServiceTransport(
            credentials_file="credentials.json", quota_project_id="octopus",
        )
        load_creds.assert_called_once_with(
            "credentials.json",
            scopes=(
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/cloudkms",
            ),
            quota_project_id="octopus",
        )


def test_key_management_service_base_transport_with_adc():
    # Test the default credentials are used if credentials and credentials_file are None.
    with mock.patch.object(auth, "default") as adc, mock.patch(
        "google.cloud.kms_v1.services.key_management_service.transports.KeyManagementServiceTransport._prep_wrapped_messages"
    ) as Transport:
        Transport.return_value = None
        adc.return_value = (credentials.AnonymousCredentials(), None)
        transport = transports.KeyManagementServiceTransport()
        adc.assert_called_once()


def test_key_management_service_auth_adc():
    # If no credentials are provided, we should use ADC credentials.
    with mock.patch.object(auth, "default") as adc:
        adc.return_value = (credentials.AnonymousCredentials(), None)
        KeyManagementServiceClient()
        adc.assert_called_once_with(
            scopes=(
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/cloudkms",
            ),
            quota_project_id=None,
        )


def test_key_management_service_transport_auth_adc():
    # If credentials and host are not provided, the transport class should use
    # ADC credentials.
    with mock.patch.object(auth, "default") as adc:
        adc.return_value = (credentials.AnonymousCredentials(), None)
        transports.KeyManagementServiceGrpcTransport(
            host="squid.clam.whelk", quota_project_id="octopus"
        )
        adc.assert_called_once_with(
            scopes=(
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/cloudkms",
            ),
            quota_project_id="octopus",
        )


def test_key_management_service_host_no_port():
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(),
        client_options=client_options.ClientOptions(
            api_endpoint="cloudkms.googleapis.com"
        ),
    )
    assert client._transport._host == "cloudkms.googleapis.com:443"


def test_key_management_service_host_with_port():
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(),
        client_options=client_options.ClientOptions(
            api_endpoint="cloudkms.googleapis.com:8000"
        ),
    )
    assert client._transport._host == "cloudkms.googleapis.com:8000"


def test_key_management_service_grpc_transport_channel():
    channel = grpc.insecure_channel("http://localhost/")

    # Check that channel is used if provided.
    transport = transports.KeyManagementServiceGrpcTransport(
        host="squid.clam.whelk", channel=channel,
    )
    assert transport.grpc_channel == channel
    assert transport._host == "squid.clam.whelk:443"


def test_key_management_service_grpc_asyncio_transport_channel():
    channel = aio.insecure_channel("http://localhost/")

    # Check that channel is used if provided.
    transport = transports.KeyManagementServiceGrpcAsyncIOTransport(
        host="squid.clam.whelk", channel=channel,
    )
    assert transport.grpc_channel == channel
    assert transport._host == "squid.clam.whelk:443"


@pytest.mark.parametrize(
    "transport_class",
    [
        transports.KeyManagementServiceGrpcTransport,
        transports.KeyManagementServiceGrpcAsyncIOTransport,
    ],
)
def test_key_management_service_transport_channel_mtls_with_client_cert_source(
    transport_class,
):
    with mock.patch(
        "grpc.ssl_channel_credentials", autospec=True
    ) as grpc_ssl_channel_cred:
        with mock.patch.object(
            transport_class, "create_channel", autospec=True
        ) as grpc_create_channel:
            mock_ssl_cred = mock.Mock()
            grpc_ssl_channel_cred.return_value = mock_ssl_cred

            mock_grpc_channel = mock.Mock()
            grpc_create_channel.return_value = mock_grpc_channel

            cred = credentials.AnonymousCredentials()
            with pytest.warns(DeprecationWarning):
                with mock.patch.object(auth, "default") as adc:
                    adc.return_value = (cred, None)
                    transport = transport_class(
                        host="squid.clam.whelk",
                        api_mtls_endpoint="mtls.squid.clam.whelk",
                        client_cert_source=client_cert_source_callback,
                    )
                    adc.assert_called_once()

            grpc_ssl_channel_cred.assert_called_once_with(
                certificate_chain=b"cert bytes", private_key=b"key bytes"
            )
            grpc_create_channel.assert_called_once_with(
                "mtls.squid.clam.whelk:443",
                credentials=cred,
                credentials_file=None,
                scopes=(
                    "https://www.googleapis.com/auth/cloud-platform",
                    "https://www.googleapis.com/auth/cloudkms",
                ),
                ssl_credentials=mock_ssl_cred,
                quota_project_id=None,
            )
            assert transport.grpc_channel == mock_grpc_channel


@pytest.mark.parametrize(
    "transport_class",
    [
        transports.KeyManagementServiceGrpcTransport,
        transports.KeyManagementServiceGrpcAsyncIOTransport,
    ],
)
def test_key_management_service_transport_channel_mtls_with_adc(transport_class):
    mock_ssl_cred = mock.Mock()
    with mock.patch.multiple(
        "google.auth.transport.grpc.SslCredentials",
        __init__=mock.Mock(return_value=None),
        ssl_credentials=mock.PropertyMock(return_value=mock_ssl_cred),
    ):
        with mock.patch.object(
            transport_class, "create_channel", autospec=True
        ) as grpc_create_channel:
            mock_grpc_channel = mock.Mock()
            grpc_create_channel.return_value = mock_grpc_channel
            mock_cred = mock.Mock()

            with pytest.warns(DeprecationWarning):
                transport = transport_class(
                    host="squid.clam.whelk",
                    credentials=mock_cred,
                    api_mtls_endpoint="mtls.squid.clam.whelk",
                    client_cert_source=None,
                )

            grpc_create_channel.assert_called_once_with(
                "mtls.squid.clam.whelk:443",
                credentials=mock_cred,
                credentials_file=None,
                scopes=(
                    "https://www.googleapis.com/auth/cloud-platform",
                    "https://www.googleapis.com/auth/cloudkms",
                ),
                ssl_credentials=mock_ssl_cred,
                quota_project_id=None,
            )
            assert transport.grpc_channel == mock_grpc_channel


def test_crypto_key_path():
    project = "squid"
    location = "clam"
    key_ring = "whelk"
    crypto_key = "octopus"

    expected = "projects/{project}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{crypto_key}".format(
        project=project, location=location, key_ring=key_ring, crypto_key=crypto_key,
    )
    actual = KeyManagementServiceClient.crypto_key_path(
        project, location, key_ring, crypto_key
    )
    assert expected == actual


def test_parse_crypto_key_path():
    expected = {
        "project": "oyster",
        "location": "nudibranch",
        "key_ring": "cuttlefish",
        "crypto_key": "mussel",
    }
    path = KeyManagementServiceClient.crypto_key_path(**expected)

    # Check that the path construction is reversible.
    actual = KeyManagementServiceClient.parse_crypto_key_path(path)
    assert expected == actual


def test_crypto_key_version_path():
    project = "squid"
    location = "clam"
    key_ring = "whelk"
    crypto_key = "octopus"
    crypto_key_version = "oyster"

    expected = "projects/{project}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{crypto_key}/cryptoKeyVersions/{crypto_key_version}".format(
        project=project,
        location=location,
        key_ring=key_ring,
        crypto_key=crypto_key,
        crypto_key_version=crypto_key_version,
    )
    actual = KeyManagementServiceClient.crypto_key_version_path(
        project, location, key_ring, crypto_key, crypto_key_version
    )
    assert expected == actual


def test_parse_crypto_key_version_path():
    expected = {
        "project": "nudibranch",
        "location": "cuttlefish",
        "key_ring": "mussel",
        "crypto_key": "winkle",
        "crypto_key_version": "nautilus",
    }
    path = KeyManagementServiceClient.crypto_key_version_path(**expected)

    # Check that the path construction is reversible.
    actual = KeyManagementServiceClient.parse_crypto_key_version_path(path)
    assert expected == actual


def test_import_job_path():
    project = "squid"
    location = "clam"
    key_ring = "whelk"
    import_job = "octopus"

    expected = "projects/{project}/locations/{location}/keyRings/{key_ring}/importJobs/{import_job}".format(
        project=project, location=location, key_ring=key_ring, import_job=import_job,
    )
    actual = KeyManagementServiceClient.import_job_path(
        project, location, key_ring, import_job
    )
    assert expected == actual


def test_parse_import_job_path():
    expected = {
        "project": "oyster",
        "location": "nudibranch",
        "key_ring": "cuttlefish",
        "import_job": "mussel",
    }
    path = KeyManagementServiceClient.import_job_path(**expected)

    # Check that the path construction is reversible.
    actual = KeyManagementServiceClient.parse_import_job_path(path)
    assert expected == actual


def test_key_ring_path():
    project = "squid"
    location = "clam"
    key_ring = "whelk"

    expected = "projects/{project}/locations/{location}/keyRings/{key_ring}".format(
        project=project, location=location, key_ring=key_ring,
    )
    actual = KeyManagementServiceClient.key_ring_path(project, location, key_ring)
    assert expected == actual


def test_parse_key_ring_path():
    expected = {
        "project": "octopus",
        "location": "oyster",
        "key_ring": "nudibranch",
    }
    path = KeyManagementServiceClient.key_ring_path(**expected)

    # Check that the path construction is reversible.
    actual = KeyManagementServiceClient.parse_key_ring_path(path)
    assert expected == actual


def test_client_withDEFAULT_CLIENT_INFO():
    client_info = gapic_v1.client_info.ClientInfo()

    with mock.patch.object(
        transports.KeyManagementServiceTransport, "_prep_wrapped_messages"
    ) as prep:
        client = KeyManagementServiceClient(
            credentials=credentials.AnonymousCredentials(), client_info=client_info,
        )
        prep.assert_called_once_with(client_info)

    with mock.patch.object(
        transports.KeyManagementServiceTransport, "_prep_wrapped_messages"
    ) as prep:
        transport_class = KeyManagementServiceClient.get_transport_class()
        transport = transport_class(
            credentials=credentials.AnonymousCredentials(), client_info=client_info,
        )
        prep.assert_called_once_with(client_info)


def test_set_iam_policy(transport: str = "grpc"):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = iam_policy.SetIamPolicyRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.set_iam_policy), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = policy.Policy(version=774, etag=b"etag_blob",)

        response = client.set_iam_policy(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, policy.Policy)

    assert response.version == 774

    assert response.etag == b"etag_blob"


@pytest.mark.asyncio
async def test_set_iam_policy_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = iam_policy.SetIamPolicyRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.set_iam_policy), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            policy.Policy(version=774, etag=b"etag_blob",)
        )

        response = await client.set_iam_policy(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, policy.Policy)

    assert response.version == 774

    assert response.etag == b"etag_blob"


def test_set_iam_policy_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = iam_policy.SetIamPolicyRequest()
    request.resource = "resource/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.set_iam_policy), "__call__") as call:
        call.return_value = policy.Policy()

        client.set_iam_policy(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "resource=resource/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_set_iam_policy_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = iam_policy.SetIamPolicyRequest()
    request.resource = "resource/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.set_iam_policy), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(policy.Policy())

        await client.set_iam_policy(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "resource=resource/value",) in kw["metadata"]


def test_set_iam_policy_from_dict():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)
    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.set_iam_policy), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = policy.Policy()

        response = client.set_iam_policy(
            request={
                "resource": "resource_value",
                "policy": policy.Policy(version=774),
            }
        )
        call.assert_called()


def test_get_iam_policy(transport: str = "grpc"):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = iam_policy.GetIamPolicyRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_iam_policy), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = policy.Policy(version=774, etag=b"etag_blob",)

        response = client.get_iam_policy(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, policy.Policy)

    assert response.version == 774

    assert response.etag == b"etag_blob"


@pytest.mark.asyncio
async def test_get_iam_policy_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = iam_policy.GetIamPolicyRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_iam_policy), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            policy.Policy(version=774, etag=b"etag_blob",)
        )

        response = await client.get_iam_policy(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, policy.Policy)

    assert response.version == 774

    assert response.etag == b"etag_blob"


def test_get_iam_policy_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = iam_policy.GetIamPolicyRequest()
    request.resource = "resource/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_iam_policy), "__call__") as call:
        call.return_value = policy.Policy()

        client.get_iam_policy(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "resource=resource/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_get_iam_policy_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = iam_policy.GetIamPolicyRequest()
    request.resource = "resource/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.get_iam_policy), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(policy.Policy())

        await client.get_iam_policy(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "resource=resource/value",) in kw["metadata"]


def test_get_iam_policy_from_dict():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)
    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(type(client._transport.get_iam_policy), "__call__") as call:
        # Designate an appropriate return value for the call.
        call.return_value = policy.Policy()

        response = client.get_iam_policy(
            request={
                "resource": "resource_value",
                "options": options.GetPolicyOptions(requested_policy_version=2598),
            }
        )
        call.assert_called()


def test_test_iam_permissions(transport: str = "grpc"):
    client = KeyManagementServiceClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = iam_policy.TestIamPermissionsRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.test_iam_permissions), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = iam_policy.TestIamPermissionsResponse(
            permissions=["permissions_value"],
        )

        response = client.test_iam_permissions(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, iam_policy.TestIamPermissionsResponse)

    assert response.permissions == ["permissions_value"]


@pytest.mark.asyncio
async def test_test_iam_permissions_async(transport: str = "grpc_asyncio"):
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(), transport=transport,
    )

    # Everything is optional in proto3 as far as the runtime is concerned,
    # and we are mocking out the actual API, so just send an empty request.
    request = iam_policy.TestIamPermissionsRequest()

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.test_iam_permissions), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            iam_policy.TestIamPermissionsResponse(permissions=["permissions_value"],)
        )

        response = await client.test_iam_permissions(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]

        assert args[0] == request

    # Establish that the response is the type that we expect.
    assert isinstance(response, iam_policy.TestIamPermissionsResponse)

    assert response.permissions == ["permissions_value"]


def test_test_iam_permissions_field_headers():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = iam_policy.TestIamPermissionsRequest()
    request.resource = "resource/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.test_iam_permissions), "__call__"
    ) as call:
        call.return_value = iam_policy.TestIamPermissionsResponse()

        client.test_iam_permissions(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls) == 1
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "resource=resource/value",) in kw["metadata"]


@pytest.mark.asyncio
async def test_test_iam_permissions_field_headers_async():
    client = KeyManagementServiceAsyncClient(
        credentials=credentials.AnonymousCredentials(),
    )

    # Any value that is part of the HTTP/1.1 URI should be sent as
    # a field header. Set these to a non-empty value.
    request = iam_policy.TestIamPermissionsRequest()
    request.resource = "resource/value"

    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._client._transport.test_iam_permissions), "__call__"
    ) as call:
        call.return_value = grpc_helpers_async.FakeUnaryUnaryCall(
            iam_policy.TestIamPermissionsResponse()
        )

        await client.test_iam_permissions(request)

        # Establish that the underlying gRPC stub method was called.
        assert len(call.mock_calls)
        _, args, _ = call.mock_calls[0]
        assert args[0] == request

    # Establish that the field header was sent.
    _, _, kw = call.mock_calls[0]
    assert ("x-goog-request-params", "resource=resource/value",) in kw["metadata"]


def test_test_iam_permissions_from_dict():
    client = KeyManagementServiceClient(credentials=credentials.AnonymousCredentials(),)
    # Mock the actual call within the gRPC stub, and fake the request.
    with mock.patch.object(
        type(client._transport.test_iam_permissions), "__call__"
    ) as call:
        # Designate an appropriate return value for the call.
        call.return_value = iam_policy.TestIamPermissionsResponse()

        response = client.test_iam_permissions(
            request={
                "resource": "resource_value",
                "permissions": ["permissions_value"],
            }
        )
        call.assert_called()
