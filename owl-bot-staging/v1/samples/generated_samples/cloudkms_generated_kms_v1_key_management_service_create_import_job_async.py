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
# Generated code. DO NOT EDIT!
#
# Snippet for CreateImportJob
# NOTE: This snippet has been automatically generated for illustrative purposes only.
# It may require modifications to work in your environment.

# To install the latest published package dependency, execute the following:
#   python3 -m pip install google-cloud-kms


# [START cloudkms_generated_kms_v1_KeyManagementService_CreateImportJob_async]
from google.cloud import kms_v1


async def sample_create_import_job():
    # Create a client
    client = kms_v1.KeyManagementServiceAsyncClient()

    # Initialize request argument(s)
    import_job = kms_v1.ImportJob()
    import_job.import_method = "RSA_OAEP_4096_SHA1_AES_256"
    import_job.protection_level = "EXTERNAL_VPC"

    request = kms_v1.CreateImportJobRequest(
        parent="parent_value",
        import_job_id="import_job_id_value",
        import_job=import_job,
    )

    # Make the request
    response = await client.create_import_job(request=request)

    # Handle response
    print(response)

# [END cloudkms_generated_kms_v1_KeyManagementService_CreateImportJob_async]
