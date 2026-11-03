-- PAT-2539: seed child joins while leaving every nullable devices column NULL.
WITH app AS (
 INSERT INTO device_apps(device_id,name,identifier,version)
 VALUES ($2::uuid,'Bare Fixture App','com.pat2539.bare','1.0')
), signal AS (
 INSERT INTO compliance_signals(device_id,key,value) VALUES ($2::uuid,'filevault','On')
), run AS (
 INSERT INTO software_inventory_runs(tenant_id,device_id,platform,received_at,provenance)
 VALUES ($1::uuid,$2::uuid,'macos',now(),'backfill_current_snapshot') RETURNING id
), observations AS (
 INSERT INTO software_observations(inventory_run_id,tenant_id,device_id,ordinal,platform,
 observed_name,observed_version,identity_kind,identity_value_normalized,identity_confidence,identity_fingerprint,observed_at)
 SELECT run.id,$1::uuid,$2::uuid,ordinal,'macos',name,'1.0',kind,name,'exact',repeat(digit,64),now()
 FROM run CROSS JOIN (VALUES (0,'bare-formula','homebrew_formula','1'),(1,'bare-package','npm_package','2')) v(ordinal,name,kind,digit)
 RETURNING id,inventory_run_id,ordinal
), hb_state AS (
 INSERT INTO homebrew_device_state(device_id,tenant_id,collection_status,reported_at)
 VALUES ($2::uuid,$1::uuid,'complete',now())
), hb_detail AS (
 INSERT INTO homebrew_observation_details(observation_id,tenant_id,device_id,inventory_run_id,
 package_kind,prefix,name,version,receipt_status,formula_file_status,installed_on_request,observed_at)
 SELECT id,$1::uuid,$2::uuid,inventory_run_id,'formula','/opt/homebrew','bare-formula','1.0','read','read',true,now()
 FROM observations WHERE ordinal=0
), hb_current AS (
 INSERT INTO homebrew_current_entries(device_id,tenant_id,package_kind,prefix,name,version_key,observed_at,inventory_run_id)
 SELECT $2::uuid,$1::uuid,'formula','/opt/homebrew','bare-formula','1.0',now(),id FROM run
), tooling_state AS (
 INSERT INTO tooling_device_state(device_id,tenant_id,block,collection_status,reported_at)
 VALUES ($2::uuid,$1::uuid,'package_managers','complete',now())
), tooling_detail AS (
 INSERT INTO tooling_observation_details(observation_id,tenant_id,device_id,inventory_run_id,
 block,unit,entry_kind,entry_key,attributes,observed_at)
 SELECT id,$1::uuid,$2::uuid,inventory_run_id,'package_managers','npm_global','package',repeat('2',64),
 '{"name":"bare-package","version":"1.0","source":"npm_global"}'::jsonb,now()
 FROM observations WHERE ordinal=1
)
INSERT INTO tooling_current_entries(device_id,tenant_id,block,unit,entry_kind,entry_key,observation_id,observed_at,inventory_run_id)
SELECT $2::uuid,$1::uuid,'package_managers','npm_global','package',repeat('2',64),id,now(),inventory_run_id
FROM observations WHERE ordinal=1;
