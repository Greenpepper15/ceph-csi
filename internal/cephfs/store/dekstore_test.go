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
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testUUID      = "8a838aac-2b88-4a9d-9505-a9870bee0930"
	testOtherUUID = "f31fe1ba-58fe-4a72-ba78-6ba26b731d5f"
)

func TestSubVolumeDEKStoreValidateVolumeID(t *testing.T) {
	t.Parallel()

	volumeID := "0001-0009-rook-ceph-0000000000000001-" + testUUID

	vo := &VolumeOptions{}
	dekStore := &subVolumeDEKStore{vo: vo}

	// the subvolume name is not resolved yet, for example on a static
	// volume
	require.Error(t, dekStore.validateVolumeID(volumeID))

	// the subvolume of the volume ID
	vo.VolID = "csi-vol-" + testUUID
	require.NoError(t, dekStore.validateVolumeID(volumeID))

	// a custom volume name prefix keeps the ObjectUUID suffix
	vo.VolID = "prefixed-" + testUUID
	require.NoError(t, dekStore.validateVolumeID(volumeID))

	// the subvolume of a different volume
	vo.VolID = "csi-vol-" + testOtherUUID
	require.Error(t, dekStore.validateVolumeID(volumeID))

	// a volume ID that is too short to contain an ObjectUUID
	vo.VolID = "csi-vol-" + testUUID
	require.Error(t, dekStore.validateVolumeID("too-short"))
}

func TestSnapshotDEKStoreValidateSnapshotID(t *testing.T) {
	t.Parallel()

	snapshotID := "0001-0009-rook-ceph-0000000000000001-" + testUUID

	vo := &VolumeOptions{}
	vo.VolID = "csi-vol-" + testOtherUUID
	dekStore := &snapshotDEKStore{vo: vo}

	// the snapshot name is not resolved yet
	require.Error(t, dekStore.validateSnapshotID(snapshotID))

	// the snapshot of the snapshot ID
	dekStore.snapshotName = "csi-snap-" + testUUID
	require.NoError(t, dekStore.validateSnapshotID(snapshotID))

	// a different snapshot
	dekStore.snapshotName = "csi-snap-" + testOtherUUID
	require.Error(t, dekStore.validateSnapshotID(snapshotID))
}
