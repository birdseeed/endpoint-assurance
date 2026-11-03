package cvepipeline

import "context"

// AssessEstateProductsForDevice is AssessEstateProducts (PAT-2028) narrowed
// to one device's own installations, for PAT-2156's GET /v1/portal/software
// ?device_id= filter. AssessEstateProducts deliberately rolls a product's
// state up across every installation in the WHOLE tenant; that is wrong for
// a device-scoped row, whose contract promises "CVE assessment state ...
// for that device's versions": a device with a stale/queued installation of
// a product that happens to be assessed on some OTHER device in the tenant
// must not borrow that other device's clean state.
//
// It is the same implementation as AssessEstateProducts with the device as
// a parameter (assessEstateProducts), not a copy, so the two views cannot
// drift: the same three-state rule, per-platform mappings
// (mappingIndex.MappedOn), exact-token automatic mappings
// (cvematch.MappingCovers), mapping_under_review / no_mapping reason
// (OpenProposals scoped to the requested products), mapping_basis, queue
// and findings source, and the same degrade to not_assessed.
func AssessEstateProductsForDevice(ctx context.Context, q DB, tenantID, deviceID string, keys []EstateProductKey) (map[EstateProductKey]EstateAssessment, error) {
	return assessEstateProductsOrDegrade(ctx, q, tenantID, deviceID, keys, identifierExact)
}
