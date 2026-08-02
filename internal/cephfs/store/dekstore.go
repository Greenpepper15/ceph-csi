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

package store

import (
	"context"
	"fmt"

	"github.com/ceph/ceph-csi/internal/cephfs/core"
	"github.com/ceph/ceph-csi/internal/kms"
)

// cephfsMetadataDEK is the key in the subvolume metadata where the encrypted
// DEK is stored. It is intentionally not prefixed with a dot, so that it is
// mirrored along with the subvolume.
const cephfsMetadataDEK = "cephfs.csi.ceph.com/dek"

// uuidLength is the length of the ObjectUUID that both the volume ID and the
// subvolume name end in.
const uuidLength = 36

// subVolumeDEKStore implements kms.DEKStore on the metadata of a CephFS
// subvolume, for KMS services that can only encrypt and decrypt a DEK and
// not store it.
type subVolumeDEKStore struct {
	// vo describes the subvolume that holds the DEK. The subvolume client
	// is created on every operation, because the subvolume name is not
	// known yet when the store is configured on the node.
	vo *VolumeOptions
}

// newSubVolumeDEKStore returns a DEKStore that keeps the encrypted DEK in the
// metadata of the subvolume described by the VolumeOptions.
func newSubVolumeDEKStore(vo *VolumeOptions) kms.DEKStore {
	return &subVolumeDEKStore{vo: vo}
}

// StoreDEK saves the encrypted DEK in the subvolume metadata.
func (s *subVolumeDEKStore) StoreDEK(ctx context.Context, volumeID, dek string) error {
	if err := s.validateVolumeID(volumeID); err != nil {
		return err
	}

	volClient := core.NewSubVolume(s.vo.GetConnection(), &s.vo.SubVolume, s.vo.ClusterID, "")

	// ErrSubVolMetadataNotSupported is fatal here, unlike for the optional
	// bookkeeping metadata: silently skipping the write would create a
	// volume that can never be opened.
	err := volClient.SetMetadata(cephfsMetadataDEK, dek)
	if err != nil {
		return fmt.Errorf("failed to store the DEK for %q: %w", volumeID, err)
	}

	return nil
}

// FetchDEK reads the encrypted DEK from the subvolume metadata.
func (s *subVolumeDEKStore) FetchDEK(ctx context.Context, volumeID string) (string, error) {
	if err := s.validateVolumeID(volumeID); err != nil {
		return "", err
	}

	volClient := core.NewSubVolume(s.vo.GetConnection(), &s.vo.SubVolume, s.vo.ClusterID, "")

	dek, err := volClient.GetMetadata(cephfsMetadataDEK)
	if err != nil {
		return "", fmt.Errorf("failed to fetch the DEK for %q: %w", volumeID, err)
	}

	return dek, nil
}

// RemoveDEK does not need to remove the DEK from the subvolume metadata, the
// subvolume is most likely getting purged along with its metadata.
func (s *subVolumeDEKStore) RemoveDEK(ctx context.Context, volumeID string) error {
	return s.validateVolumeID(volumeID)
}

// validateVolumeID confirms that the volumeID the DEK is keyed by belongs to
// the subvolume this store wraps. The volume ID and the subvolume name both
// end in the ObjectUUID of the volume, so a mismatch is a programming error,
// not a lookup failure.
func (s *subVolumeDEKStore) validateVolumeID(volumeID string) error {
	if s.vo.VolID == "" {
		// only provisioned volumes have a subvolume that can hold the
		// DEK, and for those the subvolume name is resolved before the
		// store is used
		return fmt.Errorf("the DEK store for %q requires a provisioned subvolume, "+
			"static and pre-provisioned volumes are not supported", volumeID)
	}

	if len(volumeID) < uuidLength || len(s.vo.VolID) < uuidLength ||
		volumeID[len(volumeID)-uuidLength:] != s.vo.VolID[len(s.vo.VolID)-uuidLength:] {
		return fmt.Errorf("subvolume %q can not store the DEK for %q", s.vo.VolID, volumeID)
	}

	return nil
}

// snapshotDEKStore implements kms.DEKStore on the metadata of a CephFS
// subvolume snapshot. The DEK of an encrypted volume is stored under the
// snapshot ID when the snapshot is taken, so that a volume created from the
// snapshot can receive the same DEK.
type snapshotDEKStore struct {
	// vo describes the parent subvolume of the snapshot.
	vo *VolumeOptions
	// snapshotName is the name of the subvolume snapshot that holds the
	// DEK.
	snapshotName string
}

// newSnapshotDEKStore returns a DEKStore that keeps the encrypted DEK in the
// metadata of the named snapshot of the subvolume described by the
// VolumeOptions.
func newSnapshotDEKStore(vo *VolumeOptions, snapshotName string) kms.DEKStore {
	return &snapshotDEKStore{vo: vo, snapshotName: snapshotName}
}

// StoreDEK saves the encrypted DEK in the snapshot metadata.
func (s *snapshotDEKStore) StoreDEK(ctx context.Context, volumeID, dek string) error {
	if err := s.validateSnapshotID(volumeID); err != nil {
		return err
	}

	snapClient := core.NewSnapshot(s.vo.GetConnection(), s.snapshotName, s.vo.ClusterID, "", &s.vo.SubVolume)

	// ErrSubVolSnapMetadataNotSupported is fatal here, unlike for the
	// optional bookkeeping metadata: silently skipping the write would
	// produce a snapshot that can not be restored.
	err := snapClient.SetSnapshotMetadata(cephfsMetadataDEK, dek)
	if err != nil {
		return fmt.Errorf("failed to store the DEK for snapshot %q: %w", volumeID, err)
	}

	return nil
}

// FetchDEK reads the encrypted DEK from the snapshot metadata.
func (s *snapshotDEKStore) FetchDEK(ctx context.Context, volumeID string) (string, error) {
	if err := s.validateSnapshotID(volumeID); err != nil {
		return "", err
	}

	snapClient := core.NewSnapshot(s.vo.GetConnection(), s.snapshotName, s.vo.ClusterID, "", &s.vo.SubVolume)

	dek, err := snapClient.GetSnapshotMetadata(cephfsMetadataDEK)
	if err != nil {
		return "", fmt.Errorf("failed to fetch the DEK for snapshot %q: %w", volumeID, err)
	}

	return dek, nil
}

// RemoveDEK does not need to remove the DEK from the snapshot metadata, the
// snapshot is most likely getting removed along with its metadata.
func (s *snapshotDEKStore) RemoveDEK(ctx context.Context, volumeID string) error {
	return s.validateSnapshotID(volumeID)
}

// validateSnapshotID confirms that the snapshotID the DEK is keyed by
// belongs to the snapshot this store wraps. The snapshot ID and the snapshot
// name both end in the ObjectUUID of the snapshot.
func (s *snapshotDEKStore) validateSnapshotID(snapshotID string) error {
	if s.snapshotName == "" || s.vo.VolID == "" {
		return fmt.Errorf("the snapshot DEK store for %q requires a provisioned subvolume snapshot",
			snapshotID)
	}

	if len(snapshotID) < uuidLength || len(s.snapshotName) < uuidLength ||
		snapshotID[len(snapshotID)-uuidLength:] != s.snapshotName[len(s.snapshotName)-uuidLength:] {
		return fmt.Errorf("snapshot %q can not store the DEK for %q", s.snapshotName, snapshotID)
	}

	return nil
}
