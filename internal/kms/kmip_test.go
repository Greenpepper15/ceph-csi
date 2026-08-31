/*
Copyright 2022 The Ceph-CSI Authors.

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

package kms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKMIPKMSRegistered(t *testing.T) {
	t.Parallel()
	_, ok := kmsManager.providers[kmsTypeKMIP]
	require.True(t, ok)
	_, ok = kmsManager.providers[kmsTypeKMIPMetadata]
	require.True(t, ok)
}

// TestSupportsVolumeDEKStore pins which providers may store their wrapped
// DEK in the metadata of the volume. Changing the answer for an existing
// provider relocates the DEK of every new volume, so the list must only
// ever grow.
func TestSupportsVolumeDEKStore(t *testing.T) {
	t.Parallel()
	require.True(t, SupportsVolumeDEKStore(&kmipMetadataKMS{}))
	require.True(t, SupportsVolumeDEKStore(&awsMetadataKMS{}))
	require.True(t, SupportsVolumeDEKStore(&awsSTSMetadataKMS{}))
	require.True(t, SupportsVolumeDEKStore(&keyProtectKMS{}))

	require.False(t, SupportsVolumeDEKStore(&kmipKMS{}))
	require.False(t, SupportsVolumeDEKStore(secretsMetadataKMS{}))
}

func TestKMIPMetadataGetSecretUnsupported(t *testing.T) {
	t.Parallel()

	kms := &kmipMetadataKMS{}
	_, err := kms.GetSecret(context.TODO(), "")
	require.ErrorIs(t, err, ErrGetSecretUnsupported)
}
