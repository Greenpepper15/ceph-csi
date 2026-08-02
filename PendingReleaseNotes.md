# v3.18 Pending Release Notes

## Breaking changes

## Features

1. Added `GetReplicationDestinationInfo` RPC to map source volume/volume
   group IDs to destination IDs across mirrored clusters. This enables DR
   orchestrators to discover the correct destination volume IDs when pools
   have different IDs across clusters. The RPC supports:
    - Volume replication: Maps source volume ID to destination volume ID
    - Volume group replication: Maps source group ID and all member volume
      IDs to their destination IDs
    - Pool name-based mapping via `replicationDestination` ConfigMap
      configuration
    - Backward compatibility with existing cluster-mapping.json via
      ClientProfileMapping integration
1. CephFS: fscrypt file encryption now works with KMS services that can only
   encrypt and decrypt the DEK and can not store it: `aws-metadata`,
   `aws-sts-metadata`, `ibmkeyprotect` and the new `kmip-metadata` provider,
   which reuses the configuration and credentials of `kmip`. The wrapped DEK
   is stored in the metadata of the subvolume, or of the subvolume snapshot
   for snapshots. RBD with `encryptionType: file` supports the same four
   services, storing the wrapped DEK in the image metadata.

## NOTE

- Encrypted CephFS volumes under the four KMS services above need a Ceph
  cluster that supports subvolume metadata, and subvolume snapshot metadata
  for snapshots. Such volumes can not be staged by older Ceph-CSI releases,
  which have no DEK store for CephFS. Snapshot-backed, static and
  pre-provisioned volumes are not supported with these services.
