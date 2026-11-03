package handlers

// PAT-2404: staff review of an observed, signed software identity into a
// reviewed catalogue alias, and its retirement. Internal listener only,
// guarded by ADMIN_API_TOKEN through requireInternalToken like every /admin/*
// route. Every write is audited in software_catalogue_audit, in the
// transaction that makes the change, with the PAT-1135 actor split
// (server-established actor, untrusted claimed_actor, source address).
//
// Deliberately not under /admin/catalogue/*: that prefix is the quarantined
// legacy package catalogue. This is identity, not packaging.
//
//	GET  /admin/software-catalogue/candidates?platform=&query=&limit=
//	GET  /admin/software-catalogue/aliases[?platform=&limit=]
//	POST /admin/software-catalogue/reviews
//	POST /admin/software-catalogue/aliases/{id}/retire
//
// What makes this a trust boundary: a reviewed alias resolves installations of
// that identity for every tenant on their next report, and is what a tenant
// declaration may resolve to. The caller therefore never supplies an identity.
// The four key fields of a review only name which observed identity is meant;
// the server reads it back from current installations, and refuses unless the
// signing evidence across every tenant clears the bar in catalogueVerdict.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/softwaregov"
)

const (
	catalogueCandidateDefaultLimit = 50
	catalogueCandidateMaxLimit     = 200
	catalogueAliasDefaultLimit     = 200
	catalogueAliasMaxLimit         = 1000
	catalogueObservedValueCap      = 10
	catalogueAfterCommitTimeout    = 10 * time.Second
)

// catalogueReviewKinds is the one identity kind per platform that can be
// promoted: the kinds that carry a vendor-bound companion. Every other kind
// (bundle only, publisher-less native, Winget, MSIX, MSI, name based,
// Homebrew, tooling) is refused.
var catalogueReviewKinds = map[string]string{
	"macos":   "macos_bundle_team",
	"windows": "windows_native_publisher",
}

var catalogueTeamIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// MountSoftwareCatalogueAdminRoutes registers the routes above on the
// internal router. It must never be mounted on the public or portal routers.
func MountSoftwareCatalogueAdminRoutes(r chi.Router, pool *pgxpool.Pool) {
	r.Get("/admin/software-catalogue/candidates", SoftwareCatalogueCandidatesHandler(pool))
	r.Get("/admin/software-catalogue/aliases", SoftwareCatalogueAliasesHandler(pool))
	r.Post("/admin/software-catalogue/reviews", SoftwareCatalogueReviewHandler(pool))
	r.Post("/admin/software-catalogue/aliases/{id}/retire", SoftwareCatalogueRetireHandler(pool))
}

// catalogueEvidence is the signing evidence over the current installations of
// one identity, across every tenant. "Current" is
// softwaregov.CurrentInstallationSQL, and each installation contributes its
// latest observation only.
type catalogueEvidence struct {
	DeviceCount int
	TenantCount int
	Names       []string
	Publishers  []string
	// States counts installations by verdict: the macOS signing_status or the
	// Windows Authenticode signature_state. not_reported is an installation
	// whose latest observation carried no verdict, or that has no observation.
	States map[string]int
	// Windows only, over valid installations.
	RootKinds     []string
	TrustedValid  int      // valid and chained to a microsoft or public root
	PublisherKeys []string // distinct softwaregov.AuthenticodePublisherKey values among TrustedValid
}

type catalogueEvidenceJSON struct {
	SigningStates     map[string]int `json:"signing_states"`
	RootKinds         []string       `json:"root_kinds,omitempty"`
	PublisherKeyCount *int           `json:"authenticode_publisher_key_count,omitempty"`
}

func (e catalogueEvidence) summary(platform string) catalogueEvidenceJSON {
	out := catalogueEvidenceJSON{SigningStates: e.States}
	if platform == "windows" {
		n := len(e.PublisherKeys)
		out.PublisherKeyCount = &n
		out.RootKinds = e.RootKinds
		if out.RootKinds == nil {
			out.RootKinds = []string{}
		}
	}
	return out
}

// Refusal codes, also the candidate list's blocked_reason.
const (
	catalogueBlockedBadSignature   = "bad_signature_present"
	catalogueBlockedTeamID         = "team_id_malformed"
	catalogueBlockedNoSigned       = "no_signed_installation"
	catalogueBlockedNoPublisher    = "publisher_missing"
	catalogueBlockedNoAuthenticode = "no_valid_authenticode"
	catalogueBlockedEnterpriseRoot = "enterprise_root_only"
)

var catalogueBlockedMessages = map[string]string{
	catalogueBlockedBadSignature:   "a current installation of this identity is ad hoc signed, unsigned, untrusted or has an invalid signature",
	catalogueBlockedTeamID:         "the Team ID is not a ten character Apple Team ID",
	catalogueBlockedNoSigned:       "no current installation of this identity is reported as signed",
	catalogueBlockedNoPublisher:    "the identity has no publisher",
	catalogueBlockedNoAuthenticode: "no current installation of this identity has a valid Authenticode signature; a registry publisher alone is not evidence",
	catalogueBlockedEnterpriseRoot: "the valid signatures chain only to an enterprise root, which cannot be verified independently",
}

// catalogueVerdict is the evidence bar. It is the only statement of it: the
// candidate list and the review route both call it.
//
//   - Positively bad evidence on ANY current installation is a hard refusal:
//     macOS adhoc, unsigned, untrusted or invalid; Windows invalid or unsigned.
//   - Missing evidence (no verdict, unknown, error) neither blocks nor
//     qualifies.
//   - macOS qualifies on a well-formed Team ID and at least one installation
//     reported signed.
//   - Windows qualifies on a publisher and at least one valid Authenticode
//     signature chained to a microsoft or public root. A valid signature under
//     an enterprise root does not qualify and does not block. Several distinct
//     publisher keys are allowed and reported.
func catalogueVerdict(platform, companion string, e catalogueEvidence) (promotable bool, blocked string) {
	switch platform {
	case "macos":
		switch {
		case e.States["adhoc"]+e.States["unsigned"]+e.States["untrusted"]+e.States["invalid"] > 0:
			return false, catalogueBlockedBadSignature
		case !catalogueTeamIDPattern.MatchString(companion):
			return false, catalogueBlockedTeamID
		case e.States["signed"] == 0:
			return false, catalogueBlockedNoSigned
		}
		return true, ""
	case "windows":
		switch {
		case e.States["invalid"]+e.States["unsigned"] > 0:
			return false, catalogueBlockedBadSignature
		case strings.TrimSpace(companion) == "":
			return false, catalogueBlockedNoPublisher
		case e.TrustedValid == 0 && e.States["valid"] > 0 && len(e.RootKinds) == 1 && e.RootKinds[0] == "enterprise":
			return false, catalogueBlockedEnterpriseRoot
		case e.TrustedValid == 0:
			return false, catalogueBlockedNoAuthenticode
		}
		return true, ""
	}
	return false, catalogueBlockedNoSigned
}

// catalogueEvidenceStates is the fixed set of verdicts the aggregate counts,
// in scan order. The first six are macOS signing_status values, valid and
// unknown are Windows only, invalid and unsigned are shared.
var catalogueEvidenceStates = []string{"signed", "adhoc", "unsigned", "untrusted", "invalid", "error", "valid", "unknown", "not_reported"}

// catalogueEvidenceSQL aggregates current installations of one platform and
// kind per identity. filter is appended to the installation predicate and
// tail after GROUP BY. $1 is the platform and $2 the kind.
func catalogueEvidenceSQL(filter, tail string) string {
	var counts strings.Builder
	for _, s := range catalogueEvidenceStates {
		if s == "not_reported" {
			counts.WriteString(",\n  count(*) FILTER (WHERE c.state IS NULL)")
			continue
		}
		counts.WriteString(",\n  count(*) FILTER (WHERE c.state='" + s + "')")
	}
	return `
WITH cur AS (
  SELECT si.identity_value_normalized AS value, si.companion_value_normalized AS companion,
         si.device_id, si.tenant_id, si.current_name, si.current_publisher,
         CASE WHEN si.platform='macos' THEN o.observed_signing_status ELSE o.observed_signature_state END AS state,
         o.observed_authenticode_root_kind AS root_kind,
         o.observed_authenticode_root_thumbprint AS root_thumbprint,
         o.observed_authenticode_signer AS signer
  FROM software_installations si
  LEFT JOIN software_observations o ON o.id=si.latest_observation_id AND o.tenant_id=si.tenant_id
  WHERE si.platform=$1 AND si.identity_kind=$2
    AND ` + softwaregov.CurrentInstallationSQL + filter + `
)
SELECT c.value, c.companion, count(DISTINCT c.device_id), count(DISTINCT c.tenant_id),
  (array_agg(DISTINCT c.current_name))[1:` + strconv.Itoa(catalogueObservedValueCap) + `],
  COALESCE((array_agg(DISTINCT c.current_publisher) FILTER (WHERE c.current_publisher IS NOT NULL))[1:` + strconv.Itoa(catalogueObservedValueCap) + `], '{}'),
  COALESCE(array_agg(DISTINCT c.root_kind) FILTER (WHERE c.state='valid' AND c.root_kind IS NOT NULL), '{}'),
  count(*) FILTER (WHERE c.state='valid' AND c.root_kind IN ('microsoft','public')),
  COALESCE(jsonb_agg(DISTINCT jsonb_build_array(c.root_thumbprint, c.signer))
    FILTER (WHERE c.state='valid' AND c.root_kind IN ('microsoft','public')
            AND c.root_thumbprint IS NOT NULL AND c.signer IS NOT NULL), '[]'::jsonb)` + counts.String() + `
FROM cur c
GROUP BY c.value, c.companion` + tail
}

type catalogueIdentityEvidence struct {
	Value, Companion string
	Evidence         catalogueEvidence
}

func scanCatalogueEvidence(rows pgx.Rows) ([]catalogueIdentityEvidence, error) {
	defer rows.Close()
	var out []catalogueIdentityEvidence
	for rows.Next() {
		var row catalogueIdentityEvidence
		var tuples []byte
		counts := make([]int, len(catalogueEvidenceStates))
		dest := []any{&row.Value, &row.Companion, &row.Evidence.DeviceCount, &row.Evidence.TenantCount,
			&row.Evidence.Names, &row.Evidence.Publishers, &row.Evidence.RootKinds, &row.Evidence.TrustedValid, &tuples}
		for i := range counts {
			dest = append(dest, &counts[i])
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		row.Evidence.States = map[string]int{}
		for i, s := range catalogueEvidenceStates {
			if counts[i] > 0 {
				row.Evidence.States[s] = counts[i]
			}
		}
		var pairs [][2]string
		if err := json.Unmarshal(tuples, &pairs); err != nil {
			return nil, err
		}
		keys := map[string]bool{}
		for _, p := range pairs {
			if k := softwaregov.AuthenticodePublisherKey(p[0], p[1]); k != "" {
				keys[k] = true
			}
		}
		for k := range keys {
			row.Evidence.PublisherKeys = append(row.Evidence.PublisherKeys, k)
		}
		sort.Strings(row.Evidence.PublisherKeys)
		sort.Strings(row.Evidence.RootKinds)
		out = append(out, row)
	}
	return out, rows.Err()
}

// catalogueLiveAliasSQL is "this identity already has an alias that is not
// retired", whatever wrote it. si is the installation.
const catalogueLiveAliasSQL = `EXISTS (SELECT 1 FROM software_product_aliases a
      WHERE a.platform=si.platform AND a.identity_kind=si.identity_kind
        AND a.identity_value_normalized=si.identity_value_normalized
        AND a.companion_value_normalized=si.companion_value_normalized AND a.retired_at IS NULL)`

type catalogueCandidate struct {
	Platform      string                `json:"platform"`
	Kind          string                `json:"identity_kind"`
	Value         string                `json:"identity_value_normalized"`
	Companion     string                `json:"companion_value_normalized"`
	Names         []string              `json:"observed_names"`
	Publishers    []string              `json:"observed_publishers"`
	DeviceCount   int                   `json:"device_count"`
	TenantCount   int                   `json:"tenant_count"`
	Evidence      catalogueEvidenceJSON `json:"evidence"`
	Promotable    bool                  `json:"promotable"`
	BlockedReason string                `json:"blocked_reason,omitempty"`
}

// catalogueLimit reads ?limit=. Absent means def. Anything that is not a
// whole number from 1 to max is refused rather than clamped, so a caller never
// gets a shorter or longer page than it asked for without being told.
func catalogueLimit(w http.ResponseWriter, r *http.Request, def, max int) (int, bool) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return def, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > max {
		scError(w, http.StatusBadRequest, "limit must be a whole number from 1 to "+strconv.Itoa(max))
		return 0, false
	}
	return n, true
}

func SoftwareCatalogueCandidatesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := scLogger(r, "software_catalogue_candidates")
		platform := r.URL.Query().Get("platform")
		kind, ok := catalogueReviewKinds[platform]
		if !ok {
			scError(w, http.StatusBadRequest, "platform must be macos or windows")
			return
		}
		query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("query")))
		if len(query) > 128 {
			scError(w, http.StatusBadRequest, "query must be at most 128 characters")
			return
		}
		limit, ok := catalogueLimit(w, r, catalogueCandidateDefaultLimit, catalogueCandidateMaxLimit)
		if !ok {
			return
		}
		// The search is applied to the whole identity (HAVING), never to
		// single installations: filtering rows would hide the very copies
		// whose evidence decides the verdict.
		rows, err := pool.Query(r.Context(), catalogueEvidenceSQL(`
    AND NOT `+catalogueLiveAliasSQL, `
HAVING $3='' OR strpos(c.value,$3)>0 OR strpos(lower(c.companion),$3)>0
    OR bool_or(strpos(lower(c.current_name),$3)>0)
    OR bool_or(strpos(lower(COALESCE(c.current_publisher,'')),$3)>0)
ORDER BY count(DISTINCT c.device_id) DESC, c.value, c.companion
LIMIT $4`), platform, kind, query, limit+1)
		if err != nil {
			logger.Error("list software catalogue candidates", "err", err)
			scError(w, http.StatusInternalServerError, "internal error")
			return
		}
		found, err := scanCatalogueEvidence(rows)
		if err != nil {
			logger.Error("scan software catalogue candidates", "err", err)
			scError(w, http.StatusInternalServerError, "internal error")
			return
		}
		more := len(found) > limit
		if more {
			found = found[:limit]
		}
		out := make([]catalogueCandidate, 0, len(found))
		for _, f := range found {
			c := catalogueCandidate{Platform: platform, Kind: kind, Value: f.Value, Companion: f.Companion,
				Names: f.Evidence.Names, Publishers: f.Evidence.Publishers,
				DeviceCount: f.Evidence.DeviceCount, TenantCount: f.Evidence.TenantCount, Evidence: f.Evidence.summary(platform)}
			c.Promotable, c.BlockedReason = catalogueVerdict(platform, f.Companion, f.Evidence)
			out = append(out, c)
		}
		scWriteJSON(w, http.StatusOK, map[string]any{"candidates": out, "total": len(out), "has_more": more})
	}
}

type catalogueAlias struct {
	ID             string          `json:"alias_id"`
	ProductID      string          `json:"product_id"`
	Name           string          `json:"canonical_name"`
	Vendor         *string         `json:"vendor_name"`
	Lifecycle      string          `json:"lifecycle_state"`
	Platform       string          `json:"platform"`
	Kind           string          `json:"identity_kind"`
	Value          string          `json:"identity_value_normalized"`
	Companion      string          `json:"companion_value_normalized"`
	Confidence     string          `json:"match_confidence"`
	Provenance     string          `json:"provenance"`
	Evidence       json.RawMessage `json:"evidence"`
	CreatedBy      *string         `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
	LastReviewedAt *time.Time      `json:"last_reviewed_at"`
	RetiredAt      *time.Time      `json:"retired_at"`
}

const catalogueAliasSelect = `SELECT a.id::text,a.product_id::text,sp.canonical_name,sp.vendor_name,sp.lifecycle_state,a.platform,a.identity_kind,
 a.identity_value_normalized,a.companion_value_normalized,a.match_confidence,a.provenance,a.evidence,a.created_by,a.created_at,
 (SELECT max(l.at) FROM software_catalogue_audit l WHERE l.alias_id=a.id AND l.action='review'),a.retired_at
 FROM software_product_aliases a JOIN software_products sp ON sp.id=a.product_id `

func scanCatalogueAlias(row pgx.Row) (catalogueAlias, error) {
	var a catalogueAlias
	var evidence []byte
	err := row.Scan(&a.ID, &a.ProductID, &a.Name, &a.Vendor, &a.Lifecycle, &a.Platform, &a.Kind, &a.Value, &a.Companion,
		&a.Confidence, &a.Provenance, &evidence, &a.CreatedBy, &a.CreatedAt, &a.LastReviewedAt, &a.RetiredAt)
	a.Evidence = json.RawMessage(evidence)
	return a, err
}

// SoftwareCatalogueAliasesHandler lists reviewed aliases, retired ones
// included, newest first.
func SoftwareCatalogueAliasesHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := scLogger(r, "software_catalogue_aliases")
		platform := r.URL.Query().Get("platform")
		if platform != "" && platform != "macos" && platform != "windows" {
			scError(w, http.StatusBadRequest, "platform must be macos or windows")
			return
		}
		limit, ok := catalogueLimit(w, r, catalogueAliasDefaultLimit, catalogueAliasMaxLimit)
		if !ok {
			return
		}
		rows, err := pool.Query(r.Context(), catalogueAliasSelect+`WHERE a.provenance='reviewed' AND ($1='' OR a.platform=$1)
 ORDER BY a.created_at DESC, a.id LIMIT $2`, platform, limit+1)
		if err != nil {
			logger.Error("list software catalogue aliases", "err", err)
			scError(w, http.StatusInternalServerError, "internal error")
			return
		}
		defer rows.Close()
		out := []catalogueAlias{}
		for rows.Next() {
			a, err := scanCatalogueAlias(rows)
			if err != nil {
				logger.Error("scan software catalogue alias", "err", err)
				scError(w, http.StatusInternalServerError, "internal error")
				return
			}
			out = append(out, a)
		}
		if err := rows.Err(); err != nil {
			logger.Error("list software catalogue aliases", "err", err)
			scError(w, http.StatusInternalServerError, "internal error")
			return
		}
		more := len(out) > limit
		if more {
			out = out[:limit]
		}
		scWriteJSON(w, http.StatusOK, map[string]any{"aliases": out, "total": len(out), "has_more": more})
	}
}

// catalogueBody reads a strict JSON object: unknown fields, case or fold
// variants of known ones, trailing content and anything that is not an
// object are refused.
func catalogueBody(w http.ResponseWriter, r *http.Request, out any) bool {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxSoftwareCategoryBodyBytes+1))
	if err != nil || len(b) > maxSoftwareCategoryBodyBytes || decodeStrictJSON(b, out) != nil {
		scError(w, http.StatusBadRequest, "the body must be a JSON object with only the documented fields")
		return false
	}
	return true
}

// catalogueRefusal is a decided refusal: a status and the message to return.
type catalogueRefusal struct {
	status int
	msg    string
}

func (e *catalogueRefusal) Error() string { return e.msg }

func catalogueRefuse(status int, msg string) error {
	return &catalogueRefusal{status: status, msg: msg}
}

func catalogueFail(w http.ResponseWriter, logger *slog.Logger, err error) {
	var refusal *catalogueRefusal
	var pg *pgconn.PgError
	switch {
	case errors.As(err, &refusal):
		scError(w, refusal.status, refusal.msg)
	case errors.As(err, &pg) && pg.Code == "23505":
		// The identity lock makes this unreachable for two reviews; it remains
		// for any other writer of the alias or product tables.
		scError(w, http.StatusConflict, "this identity or product was changed by another request; reload and try again")
	default:
		logger.Error("software catalogue write failed", "err", err)
		scError(w, http.StatusInternalServerError, "internal error")
	}
}

type catalogueReviewRequest struct {
	Platform  string `json:"platform"`
	Kind      string `json:"identity_kind"`
	Value     string `json:"identity_value_normalized"`
	Companion string `json:"companion_value_normalized"`
	Name      string `json:"canonical_name"`
	Vendor    string `json:"vendor_name"`
	Reason    string `json:"reason"`
	Actor     string `json:"actor"`
}

func SoftwareCatalogueReviewHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := scLogger(r, "software_catalogue_review")
		var req catalogueReviewRequest
		if !catalogueBody(w, r, &req) {
			return
		}
		req.Name, req.Vendor = strings.TrimSpace(req.Name), strings.TrimSpace(req.Vendor)
		req.Reason, req.Actor = strings.TrimSpace(req.Reason), strings.TrimSpace(req.Actor)
		if req.Platform != "macos" && req.Platform != "windows" {
			scError(w, http.StatusBadRequest, "platform must be macos or windows")
			return
		}
		if !declarationText(req.Name, 256) || !declarationText(req.Vendor, 256) || !declarationText(req.Reason, 1000) || !declarationText(req.Actor, 256) {
			scError(w, http.StatusBadRequest, "canonical_name, vendor_name, reason and actor are required")
			return
		}
		// The identity fields are compared as given, never trimmed or folded:
		// they must equal what the extractor stored, or they name nothing.
		if strings.TrimSpace(req.Kind) == "" || strings.TrimSpace(req.Value) == "" || len(req.Value) > 1024 || len(req.Companion) > 1024 {
			scError(w, http.StatusBadRequest, "identity_kind and identity_value_normalized are required")
			return
		}
		if req.Kind != catalogueReviewKinds[req.Platform] {
			scError(w, http.StatusUnprocessableEntity, "only a macOS bundle identifier with its Team ID or a Windows native identifier with its publisher can be reviewed")
			return
		}
		aliasID, revived, err := reviewCatalogueIdentity(r, pool, req)
		if err != nil {
			catalogueFail(w, logger, err)
			return
		}
		if revived {
			// A declaration resolved through this alias is effective again.
			invalidateDeclaredAlias(r.Context(), pool, logger, aliasID)
		}
		alias, err := scanCatalogueAlias(pool.QueryRow(r.Context(), catalogueAliasSelect+`WHERE a.id=$1::uuid`, aliasID))
		if err != nil {
			logger.Error("read reviewed software catalogue alias", "err", err)
			scError(w, http.StatusInternalServerError, "the review was recorded but could not be read back")
			return
		}
		scWriteJSON(w, http.StatusCreated, map[string]any{"alias": alias, "revived": revived})
	}
}

// reviewCatalogueIdentity is the whole review in one transaction: the
// identity lock, the duplicate check, the evidence bar, the product, the
// alias and the audit row. It returns the alias and whether a retired alias
// was revived rather than a new one created.
func reviewCatalogueIdentity(r *http.Request, pool *pgxpool.Pool, req catalogueReviewRequest) (aliasID string, revived bool, err error) {
	ctx := r.Context()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback(ctx)

	// One review of an identity at a time. Two simultaneous reviews would
	// otherwise both pass the duplicate check and race on the unique index.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		strings.Join([]string{"software_catalogue_review", req.Platform, req.Kind, req.Value, req.Companion}, "\x1f")); err != nil {
		return "", false, err
	}

	// The row lock is the same one retirement takes, so a review and a
	// retirement of one alias are serialised and each audits what it did.
	var existingID, existingProduct, existingProvenance string
	var existingRetired *time.Time
	var sameProduct bool
	var before []byte
	err = tx.QueryRow(ctx, `SELECT a.id::text,a.product_id::text,a.provenance,a.retired_at,sp.canonical_key=lower(btrim($5)),to_jsonb(a)
		FROM software_product_aliases a JOIN software_products sp ON sp.id=a.product_id
		WHERE a.platform=$1 AND a.identity_kind=$2 AND a.identity_value_normalized=$3 AND a.companion_value_normalized=$4
		FOR UPDATE OF a`, req.Platform, req.Kind, req.Value, req.Companion, req.Name).
		Scan(&existingID, &existingProduct, &existingProvenance, &existingRetired, &sameProduct, &before)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return "", false, err
	case existingRetired == nil:
		return "", false, catalogueRefuse(http.StatusConflict, "this identity already has a catalogue alias")
	}

	// The identity comes from what devices report now, never from the body.
	rows, err := tx.Query(ctx, catalogueEvidenceSQL(`
    AND si.identity_value_normalized=$3 AND si.companion_value_normalized=$4`, ""),
		req.Platform, req.Kind, req.Value, req.Companion)
	if err != nil {
		return "", false, err
	}
	found, err := scanCatalogueEvidence(rows)
	if err != nil {
		return "", false, err
	}
	if len(found) == 0 || found[0].Evidence.DeviceCount == 0 {
		return "", false, catalogueRefuse(http.StatusNotFound, "no device currently reports this identity")
	}
	evidence := found[0].Evidence
	if ok, blocked := catalogueVerdict(req.Platform, req.Companion, evidence); !ok {
		return "", false, catalogueRefuse(http.StatusUnprocessableEntity, catalogueBlockedMessages[blocked])
	}
	if existingID != "" && !sameProduct {
		return "", false, catalogueRefuse(http.StatusConflict, "this identity was reviewed before under another product; review it again under that product's name")
	}

	var productID string
	err = tx.QueryRow(ctx, `INSERT INTO software_products(canonical_key,canonical_name,vendor_name,lifecycle_state)
		VALUES(lower(btrim($1)),btrim($1),$2,'active') ON CONFLICT (canonical_key) DO NOTHING RETURNING id::text`, req.Name, req.Vendor).Scan(&productID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Reuse. The product is someone else's row too (other aliases,
		// category tags), so it is used as it stands or not at all. The one
		// exception is filling a vendor that was never recorded.
		var lifecycle string
		var vendor *string
		if err = tx.QueryRow(ctx, `SELECT id::text,lifecycle_state,vendor_name FROM software_products WHERE canonical_key=lower(btrim($1)) FOR UPDATE`, req.Name).
			Scan(&productID, &lifecycle, &vendor); err != nil {
			return "", false, err
		}
		switch {
		case lifecycle != "active":
			return "", false, catalogueRefuse(http.StatusConflict, "a product with this name exists and is not active")
		case vendor == nil || strings.TrimSpace(*vendor) == "":
			if _, err = tx.Exec(ctx, `UPDATE software_products SET vendor_name=$2,updated_at=now() WHERE id=$1::uuid`, productID, req.Vendor); err != nil {
				return "", false, err
			}
		case !strings.EqualFold(strings.TrimSpace(*vendor), req.Vendor):
			return "", false, catalogueRefuse(http.StatusConflict, "a product with this name exists under another vendor")
		}
	} else if err != nil {
		return "", false, err
	}

	summary, err := json.Marshal(map[string]any{
		"basis":                            "staff_review",
		"evaluated_at":                     time.Now().UTC().Format(time.RFC3339),
		"device_count":                     evidence.DeviceCount,
		"tenant_count":                     evidence.TenantCount,
		"signing_states":                   evidence.States,
		"root_kinds":                       evidence.RootKinds,
		"authenticode_publisher_key_count": len(evidence.PublisherKeys),
		"authenticode_publisher_keys":      capStrings(evidence.PublisherKeys, catalogueObservedValueCap),
	})
	if err != nil {
		return "", false, err
	}

	if existingID != "" {
		// Revive the same row. The 0111 unique constraint allows one alias per
		// identity for ever, and rows that already reference this one
		// (installations, declarations) reference it by id.
		aliasID, revived = existingID, true
		if _, err = tx.Exec(ctx, `UPDATE software_product_aliases SET retired_at=NULL,created_by=$2,evidence=$3::jsonb,match_confidence='exact' WHERE id=$1::uuid`,
			aliasID, req.Actor, summary); err != nil {
			return "", false, err
		}
	} else {
		before = nil
		if err = tx.QueryRow(ctx, `INSERT INTO software_product_aliases(product_id,platform,identity_kind,identity_value_normalized,companion_value_normalized,match_confidence,provenance,evidence,created_by)
			VALUES($1::uuid,$2,$3,$4,$5,'exact','reviewed',$6::jsonb,$7) RETURNING id::text`,
			productID, req.Platform, req.Kind, req.Value, req.Companion, summary, req.Actor).Scan(&aliasID); err != nil {
			return "", false, err
		}
	}
	if err = writeCatalogueAudit(ctx, tx, r, "review", aliasID, req.Actor, req.Reason, before); err != nil {
		return "", false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", false, err
	}
	return aliasID, revived, nil
}

func capStrings(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	if in == nil {
		return []string{}
	}
	return in
}

// writeCatalogueAudit records one review or retirement inside the caller's
// transaction, snapshotting the alias as it now stands with its product.
func writeCatalogueAudit(ctx context.Context, tx pgx.Tx, r *http.Request, action, aliasID, claimed, reason string, before []byte) error {
	actor, claimedActor, sourceAddr := auditAttribution(r, claimed)
	var beforeArg any
	if before != nil {
		beforeArg = string(before)
	}
	_, err := tx.Exec(ctx, `INSERT INTO software_catalogue_audit(action,alias_id,product_id,actor,claimed_actor,source_addr,reason,before,after)
		SELECT $1,a.id,a.product_id,$3,$4,$5,$6,$7::jsonb,
		       to_jsonb(a) || jsonb_build_object('canonical_name',sp.canonical_name,'vendor_name',sp.vendor_name)
		FROM software_product_aliases a JOIN software_products sp ON sp.id=a.product_id WHERE a.id=$2::uuid`,
		action, aliasID, actor, claimedActor, sourceAddr, reason, beforeArg)
	return err
}

// invalidateDeclaredAlias tells the Unapproved-present summary of every tenant
// with a declaration resolved through the alias that its policy resolver now
// answers differently. No policy row changed, so no trigger can.
//
// After the commit and outside it, as the extractor does for an eligibility
// flip: the write holds no alias lock while it waits on summary state rows. The
// same accepted limitation applies. A failure here leaves that tenant's
// summary stale until its next policy change, so it is logged loudly; the
// policy resolver itself is already correct.
func invalidateDeclaredAlias(reqCtx context.Context, pool *pgxpool.Pool, logger *slog.Logger, aliasID string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), catalogueAfterCommitTimeout)
	defer cancel()
	tenants, err := softwaregov.TenantsDeclaredThroughAlias(ctx, pool, aliasID)
	if err != nil {
		logger.Error("catalogue alias changed but the tenants declared through it could not be listed; their unapproved summaries are stale", "alias_id", aliasID, "err", err)
		return
	}
	for _, tenantID := range tenants {
		if err := softwaregov.MarkPolicyResolutionChanged(ctx, pool, tenantID); err != nil {
			logger.Error("catalogue alias changed but the unapproved summary was not invalidated", "alias_id", aliasID, "tenant_id", tenantID, "err", err)
		}
	}
	if len(tenants) > 0 {
		softwaregov.WakeRunner()
	}
}

func SoftwareCatalogueRetireHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := scLogger(r, "software_catalogue_retire")
		var req struct {
			Reason string `json:"reason"`
			Actor  string `json:"actor"`
		}
		if !catalogueBody(w, r, &req) {
			return
		}
		req.Reason, req.Actor = strings.TrimSpace(req.Reason), strings.TrimSpace(req.Actor)
		if !declarationText(req.Reason, 1000) || !declarationText(req.Actor, 256) {
			scError(w, http.StatusBadRequest, "reason and actor are required")
			return
		}
		aliasID := chi.URLParam(r, "id")
		if !looksLikeUUID(aliasID) {
			scError(w, http.StatusNotFound, "not found")
			return
		}
		if err := retireCatalogueAlias(r, pool, aliasID, req.Actor, req.Reason); err != nil {
			catalogueFail(w, logger, err)
			return
		}
		invalidateDeclaredAlias(r.Context(), pool, logger, aliasID)
		alias, err := scanCatalogueAlias(pool.QueryRow(r.Context(), catalogueAliasSelect+`WHERE a.id=$1::uuid`, aliasID))
		if err != nil {
			logger.Error("read retired software catalogue alias", "err", err)
			scError(w, http.StatusInternalServerError, "the retirement was recorded but could not be read back")
			return
		}
		scWriteJSON(w, http.StatusOK, map[string]any{"alias": alias})
	}
}

func retireCatalogueAlias(r *http.Request, pool *pgxpool.Pool, aliasID, actor, reason string) error {
	ctx := r.Context()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var provenance string
	var retired *time.Time
	var before []byte
	err = tx.QueryRow(ctx, `SELECT a.provenance,a.retired_at,to_jsonb(a) FROM software_product_aliases a WHERE a.id=$1::uuid FOR UPDATE`, aliasID).
		Scan(&provenance, &retired, &before)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return catalogueRefuse(http.StatusNotFound, "not found")
	case err != nil:
		return err
	case provenance != "reviewed":
		return catalogueRefuse(http.StatusConflict, "only an alias created by staff review can be retired here")
	case retired != nil:
		return catalogueRefuse(http.StatusConflict, "this alias is already retired")
	}
	if _, err = tx.Exec(ctx, `UPDATE software_product_aliases SET retired_at=now() WHERE id=$1::uuid`, aliasID); err != nil {
		return err
	}
	if err = writeCatalogueAudit(ctx, tx, r, "retire", aliasID, actor, reason, before); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
