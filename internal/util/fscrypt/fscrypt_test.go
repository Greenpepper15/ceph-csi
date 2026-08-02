/*
Copyright 2026 The Ceph-CSI Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fscrypt

import (
	"testing"

	fscryptmetadata "github.com/google/fscrypt/metadata"
	"github.com/stretchr/testify/require"

	"github.com/ceph/ceph-csi/internal/kms"
	"github.com/ceph/ceph-csi/internal/util"
)

// TestSourceType is the regression guard for the fscrypt protector source of
// the three DEK arrangements. Existing encrypted volumes stop opening when
// the outcome changes for their arrangement:
//
//   - a KMS with an integrated DEK store (default, vault, vaulttokens,
//     vaulttenantsa, azure-kv) uses a raw 32 byte key,
//   - a KMS that hands out its secret (metadata) uses a custom passphrase,
//   - a KMS that can only wrap and unwrap the DEK (kmip, aws-metadata,
//     aws-sts-metadata, ibmkeyprotect) has a DEK store configured with
//     SetDEKStore and uses a raw 32 byte key.
func TestSourceType(t *testing.T) {
	t.Parallel()
	secrets := map[string]string{
		"encryptionPassphrase": "test",
	}

	kmsProvider, err := kms.GetDefaultKMS(secrets)
	require.NoError(t, err)

	// integrated DEK store, the store is set by NewVolumeEncryption
	ve, err := util.NewVolumeEncryption("", kmsProvider, nil)
	require.NoError(t, err)
	require.Equal(t, fscryptmetadata.SourceType_raw_key, sourceType(ve))

	// a KMS that supports GetSecret gets no DEK store configured
	ve = &util.VolumeEncryption{KMS: kmsProvider}
	require.Equal(t, fscryptmetadata.SourceType_custom_passphrase, sourceType(ve))

	// a KMS that can only wrap and unwrap the DEK gets a DEK store
	// configured by the driver
	dekStore, ok := kmsProvider.(kms.DEKStore)
	require.True(t, ok)
	ve.SetDEKStore(dekStore)
	require.Equal(t, fscryptmetadata.SourceType_raw_key, sourceType(ve))
}
