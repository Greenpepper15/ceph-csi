/*
Copyright 2021 Ceph-CSI authors.

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

package util

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ceph/ceph-csi/internal/kms"
	"github.com/ceph/ceph-csi/pkg/util/crypto"
)

func TestGenerateNewEncryptionPassphrase(t *testing.T) {
	t.Parallel()
	b64Passphrase, err := generateNewEncryptionPassphrase(defaultEncryptionPassphraseSize)
	require.NoError(t, err)

	// b64Passphrase is URL-encoded, decode to verify the length of the
	// passphrase
	passphrase, err := base64.URLEncoding.DecodeString(b64Passphrase)
	require.NoError(t, err)
	require.Len(t, passphrase, defaultEncryptionPassphraseSize)
}

func TestHasDEKStore(t *testing.T) {
	t.Parallel()
	secrets := map[string]string{
		"encryptionPassphrase": "workflow test",
	}

	// the default KMS is an integrated DEK store
	kmsProvider, err := kms.GetDefaultKMS(secrets)
	require.NoError(t, err)

	ve, err := NewVolumeEncryption("", kmsProvider, nil)
	require.NoError(t, err)
	require.True(t, ve.HasDEKStore())

	// a KMS that returns ErrDEKStoreNeeded has no DEK store until one is
	// configured with SetDEKStore
	ve = &VolumeEncryption{KMS: kmsProvider}
	require.False(t, ve.HasDEKStore())

	dekStore, ok := kmsProvider.(kms.DEKStore)
	require.True(t, ok)
	ve.SetDEKStore(dekStore)
	require.True(t, ve.HasDEKStore())
}

func TestDEKStoreNotConfigured(t *testing.T) {
	t.Parallel()
	secrets := map[string]string{
		"encryptionPassphrase": "workflow test",
	}

	kmsProvider, err := kms.GetDefaultKMS(secrets)
	require.NoError(t, err)

	// a VolumeEncryption without a DEK store must return
	// ErrDEKStoreNotFound instead of panicking
	ve := &VolumeEncryption{KMS: kmsProvider}
	ctx := t.Context()

	err = ve.StoreCryptoPassphrase(ctx, "volume-id", "passphrase")
	require.ErrorIs(t, err, ErrDEKStoreNotFound)

	_, err = ve.GetCryptoPassphrase(ctx, "volume-id")
	require.ErrorIs(t, err, ErrDEKStoreNotFound)

	err = ve.RemoveDEK(ctx, "volume-id")
	require.ErrorIs(t, err, ErrDEKStoreNotFound)
}

func TestKMSWorkflow(t *testing.T) {
	t.Parallel()
	secrets := map[string]string{
		// FIXME: use encryptionPassphraseKey from SecretsKMS
		"encryptionPassphrase": "workflow test",
	}

	kmsProvider, err := kms.GetDefaultKMS(secrets)
	require.NoError(t, err)
	require.NotNil(t, kmsProvider)

	ve, err := NewVolumeEncryption("", kmsProvider, nil)
	require.NoError(t, err)
	require.NotNil(t, ve)
	require.Equal(t, kms.DefaultKMSType, ve.GetID())

	volumeID := "volume-id"
	ctx := t.Context()

	err = ve.StoreNewCryptoPassphrase(ctx, volumeID, defaultEncryptionPassphraseSize)
	require.NoError(t, err)

	passphrase, err := ve.GetCryptoPassphrase(ctx, volumeID)
	require.NoError(t, err)
	require.Equal(t, secrets["encryptionPassphrase"], passphrase)
}

func TestFetchEncryptionType(t *testing.T) {
	t.Parallel()
	volOpts := map[string]string{}
	require.Equal(t, crypto.EncryptionTypeBlock, FetchEncryptionType(volOpts, crypto.EncryptionTypeBlock))
	require.Equal(t, crypto.EncryptionTypeFile, FetchEncryptionType(volOpts, crypto.EncryptionTypeFile))
	require.Equal(t, crypto.EncryptionTypeNone, FetchEncryptionType(volOpts, crypto.EncryptionTypeNone))
	volOpts["encryptionType"] = ""
	require.Equal(t, crypto.EncryptionTypeInvalid, FetchEncryptionType(volOpts, crypto.EncryptionTypeNone))
	volOpts["encryptionType"] = "block"
	require.Equal(t, crypto.EncryptionTypeBlock, FetchEncryptionType(volOpts, crypto.EncryptionTypeNone))
	volOpts["encryptionType"] = "file"
	require.Equal(t, crypto.EncryptionTypeFile, FetchEncryptionType(volOpts, crypto.EncryptionTypeNone))
	volOpts["encryptionType"] = "INVALID"
	require.Equal(t, crypto.EncryptionTypeInvalid, FetchEncryptionType(volOpts, crypto.EncryptionTypeNone))
}
