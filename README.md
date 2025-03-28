# Encrypted Repository Plugin for OpenSearch®

Encrypted Repository for OpenSearch®  is a plugin that offers 
client-side encryption for snapshotting repositories and could be combined 
with all official supported repository plugins: 
`File Systsem`, `Google Cloud Storage`, `Amazon S3` and `Microsoft Azure`.

- [Features](#features)
- [Compatibility Matrix](#compatibility-matrix)
- [Plugin Configuration](#plugin-configuration)
- [Repository Settings](#repository-settings)
- [Installation](#installation)
- [Build from Source](#build-from-source)
- [Testing](#testing)
- [Contribute](#Contribute)
- [Security](#security)
- [License](#license)
- [Copyright](#copyright)

## Features
* Support for AES 256 bits keys
* AES GCM with AAD encryption support

## Compatibility Matrix
| OpenSearch |  Plugin | Release date |
|------------:|--------:|-------------:|
|    3.0.0-alpha2 | v3.0.0.0-alpha1 | Mar 21, 2025 | 
|    2.19.1 | 2.19.1.0 | Mar 21, 2025 | 
|    2.18.0 | 2.18.0.0 | Mar 21, 2025 | 
|    2.14.0 | 2.14.0.0 | Jun 09, 2024 | 
|    2.13.0 | 2.13.0.0 | Mai 09, 2024 | 

## Plugin Configuration
* OpenSearch keystore settings
  * `encrypted.<storage_type>.<client_name>.private_key` - RSA private key
  * `encrypted.<storage_type>.<client_name>.public_key` - RSA public key,
    
  where `storage_type` is one of `azure`, `fs`, `gcs` and `s3` and `client` the name of the client delegated repository to be used   
   
## Repository Settings
* `storage_type` - delegated repository type, supported values are: `azure`, `fs`, `gcs` and `s3`
* `chunk_size` - chunk size as a value and unit, for example: `1MB`, `1GB`, `1TB`. 
                 Default value is: `1GB`, min value - `500MB`, max value - `64GB`
* `client` - the name of a client for `Azure`, `FS`, `GCS` and `S3` repository to use
* `compress` - compress snapshot metadata, default is `true`

## Installation
* Download the latest release from [releases](https://github.com/aiven/encrypted-repository/releases/latest)
* Extract selected archive into OpenSearch `plugins` directory
* Generate RSA key pair: 
  ```bash
  openssl genrsa -out key.pem 2048 # Private key
  openssl rsa -in key.pem -outform PEM -pubout -out public.pem # Public key
  ```
* Create OpenSearch keystore:
  ```bash
  opensearch-keystore create
  ```
* Import generated RSA keys into OpenSearch keystore
    * Azure
      ```bash
      opensearch-keystore add-file --force encrypted.azure.default.private_key ~/key.pem
      opensearch-keystore add-file --force encrypted.azure.default.public_key ~/public.pem
      ```
    * File System
      ```bash
      opensearch-keystore add-file --force encrypted.fs.default.private_key ~/key.pem
      opensearch-keystore add-file --force encrypted.fs.default.public_key ~/public.pem
      ```
    * GCS
      ```bash
      opensearch-keystore add-file --force encrypted.gcs.default.private_key ~/key.pem
      opensearch-keystore add-file --force encrypted.gcs.default.public_key ~/public.pem
      ```
    * Amazon S3
      ```bash
      opensearch-keystore add-file --force encrypted.s3.default.private_key ~/key.pem
      opensearch-keystore add-file --force encrypted.s3.default.public_key ~/public.pem
      ```
* Start OpenSearch
    * Configure repository using Azure:
      ```bash
      PUT _snapshot/repository_name
        {
          "type": "encrypted",
          "settings": {
            "storage_type": "azure",   
            "client": "secondary",
            "container": "my-azure-container",
            "base_path" : "cluster1"
          }
        }
      ```
    * Configure repository using file system:
      ```bash
      PUT _snapshot/repository_name
        {
          "type": "encrypted",
          "settings": {
            "storage_type": "fs",   
            "client": "secondary",
            "location": "/mount/backups/my_fs_backup_location"            
          }
        }
      ```
    * Configure repository using GCS:
      ```bash
      PUT _snapshot/repository_name
        {
          "type": "encrypted",
          "settings": {
            "storage_type": "gcs",   
            "client": "secondary",
            "bucket": "name-of-gcs-bucket",
            "compress": true
          }
        }
      ```
    * Configure repository using S3:
      ```bash
      PUT _snapshot/repository_name
        {
          "type": "encrypted",
          "settings": {
            "storage_type": "s3",   
            "client": "secondary",
            "bucket": "name-of-bucket",
            "region": "region-of-bucket-same-as-cluster"
          }
        }
      ```

### Build from Source
The project in this package uses the [Gradle](https://docs.gradle.org/current/userguide/userguide.html) build system. Gradle comes with excellent documentation that should be your first stop when trying to figure out how to operate or modify the build.
To build the plugin you need at least `JDK 11`:
```bash
./gradlew clean build 
```

### Testing
Complete test suite is run using:
```bash
./gradlew clean assemble check
```

### Contribute
See [CONTRIBUTING](CONTRIBUTING.md) for more information.

### Security
See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License
This code is licensed under the Apache 2.0 License. See [LICENSE.txt](LICENSE.txt).

## Copyright
Copyright OpenSearch Contributors. See [NOTICE](NOTICE.txt) for details.
