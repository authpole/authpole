package cache

import (
	"hash/fnv"
	"fmt"
)

// ShardKey computes a deterministic sharding key partition from orgID and appID (without KeyID).
// This guarantees that all certificates, signing keys, app metadata, and upstream IDP settings for a given
// organization app are co-located on the same shard node, minimizing overall server memory footprint.
func ShardKey(orgID, appID string) string {
	if appID == "" {
		return orgID
	}
	return fmt.Sprintf("%s:%s", orgID, appID)
}

// ShardHash calculates a uint32 hash value for a given orgID and appID for consistent node routing.
func ShardHash(orgID, appID string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ShardKey(orgID, appID)))
	return h.Sum32()
}

// DetermineNode index for a given number of nodes using consistent hash ring math.
func DetermineNode(orgID, appID string, numNodes int) int {
	if numNodes <= 1 {
		return 0
	}
	return int(ShardHash(orgID, appID) % uint32(numNodes))
}
