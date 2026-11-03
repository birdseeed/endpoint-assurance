-- PAT-442: cross-estate installed-app inventory by prevalence.
--
-- Feeds the Tier 2 deploy-catalogue ranking (PAT-441): the catalogue is built
-- from the apps most prevalent across real estates, and PAT-441 gates go-live on
-- "% of installed instances covered" by the catalogue. This query produces the
-- ranked list + the cumulative-coverage column that metric reads from.
--
-- Stateless read, no schema changes. Re-runnable as more estates onboard and the
-- catalogue grows:
--
--   ssh root@patched-api-01
--   sudo -u postgres psql -d patched -f /path/to/app-prevalence.sql
--
-- Or for a CSV export:
--   sudo -u postgres psql -d patched --csv -f app-prevalence.sql > app-prevalence.csv
--
-- Columns:
--   app_name             normalised display name (device_apps.name)
--   installed_instances  total install rows across all estates
--   distinct_devices     hosts it appears on
--   distinct_estates     tenants it appears in (cross-estate prevalence signal)
--   version_count        distinct versions seen (spread)
--   macos_instances      install rows on macOS hosts
--   windows_instances    install rows on Windows hosts
--   pct_of_instances     this app's share of all install rows
--   cumulative_pct       running coverage if the catalogue included every app
--                        down to and including this row (the PAT-441 go-live bar)

WITH app_prevalence AS (
    SELECT
        da.name                                       AS app_name,
        count(*)                                       AS installed_instances,
        count(DISTINCT da.device_id)                   AS distinct_devices,
        count(DISTINCT d.tenant_id)                    AS distinct_estates,
        count(DISTINCT da.version)                     AS version_count,
        count(*) FILTER (WHERE d.os = 'macOS')         AS macos_instances,
        count(*) FILTER (WHERE d.os = 'Windows')       AS windows_instances
    FROM device_apps da
    JOIN devices d ON d.id = da.device_id
    GROUP BY da.name
),
total AS (
    SELECT sum(installed_instances) AS total_instances FROM app_prevalence
)
SELECT
    ap.app_name,
    ap.installed_instances,
    ap.distinct_devices,
    ap.distinct_estates,
    ap.version_count,
    ap.macos_instances,
    ap.windows_instances,
    round(100.0 * ap.installed_instances / t.total_instances, 2) AS pct_of_instances,
    round(
        100.0 * sum(ap.installed_instances)
            OVER (ORDER BY ap.installed_instances DESC, ap.distinct_estates DESC, ap.app_name)
        / t.total_instances,
    2) AS cumulative_pct
FROM app_prevalence ap
CROSS JOIN total t
ORDER BY ap.installed_instances DESC, ap.distinct_estates DESC, ap.app_name;
