package cache

import (
	"hash/fnv"
	"fmt"
)

// ShardKey computes a deterministic sharding key partition from tenantID and appID (without KeyID).
// This guarantees that all certificates, signing keys, app metadata, and upstream IDP settings for a given
// tenant app are co-located on the same shard node, minimizing overall server memory footprint.
func ShardKey(tenantID, appID string) string {
	if appID == "" {
		return tenantID
	}
	return fmt.Sprintf("%s:%s", tenantID, appID)
}

// ShardHash calculates a uint32 hash value for a given tenantID and appID for consistent node routing.
func ShardHash(tenantID, appID string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ShardKey(tenantID, appID)))
	return h.Sum32()
}

// DetermineNode index for a given number of nodes using consistent hash ring math.
func DetermineNode(tenantID, appID string, numNodes int) int {
	if numNodes <= 1 {
		return 0
	}
	return int(ShardHash(tenantID, appID) % uint32(numNodes))
}
