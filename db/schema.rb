# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.0].define(version: 2026_04_07_211310) do
  create_schema "vuln_scanner"

  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"

  create_table "agents", force: :cascade do |t|
    t.string "agent_id", null: false
    t.integer "organization_id", default: 1
    t.text "ssh_public_key"
    t.text "ssh_private_key"
    t.string "ssh_key_fingerprint"
    t.integer "tunnel_port", null: false
    t.string "platform"
    t.string "hostname"
    t.string "status", default: "created"
    t.datetime "last_seen"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "network_range"
    t.integer "site_id"
    t.index ["agent_id"], name: "index_agents_on_agent_id", unique: true
  end

  create_table "asset_use_cases", id: :serial, force: :cascade do |t|
    t.integer "asset_id", null: false
    t.integer "use_case_id", null: false
    t.integer "confidence", default: 100
    t.string "detected_method", limit: 50
    t.datetime "created_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.index ["asset_id"], name: "idx_asset_use_case_asset"
    t.index ["use_case_id"], name: "idx_asset_use_case_use_case"
    t.unique_constraint ["asset_id", "use_case_id"], name: "asset_use_cases_asset_id_use_case_id_key"
  end

  create_table "assets", id: :serial, force: :cascade do |t|
    t.integer "organization_id", null: false
    t.inet "ip_address", null: false
    t.string "hostname", limit: 255
    t.string "domain", limit: 255
    t.integer "os_id"
    t.boolean "os_detected", default: false
    t.boolean "is_active", default: true
    t.datetime "last_seen", precision: nil
    t.datetime "created_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.datetime "updated_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.jsonb "scan_config", default: {}
    t.integer "site_id"
    t.string "criticality", default: "unknown"
    t.text "notes"
    t.index ["ip_address"], name: "idx_asset_ip"
    t.index ["is_active"], name: "idx_asset_active", where: "(is_active = true)"
    t.index ["organization_id"], name: "idx_asset_org"
    t.index ["os_id"], name: "idx_asset_os"
    t.unique_constraint ["organization_id", "ip_address"], name: "assets_org_id_ip_address_key"
  end

  create_table "exploit_os_compatibility", id: :serial, force: :cascade do |t|
    t.integer "exploit_id", null: false
    t.integer "os_id", null: false
    t.string "os_family_match", limit: 50
    t.datetime "created_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.index ["exploit_id"], name: "idx_compat_exploit"
    t.index ["os_family_match"], name: "idx_compat_family"
    t.index ["os_id"], name: "idx_compat_os"
    t.unique_constraint ["exploit_id", "os_id"], name: "exploit_os_compatibility_exploit_id_os_id_key"
  end

  create_table "exploit_use_case_relevance", id: :serial, force: :cascade do |t|
    t.integer "exploit_id", null: false
    t.integer "use_case_id", null: false
    t.integer "relevance_score", default: 100
    t.datetime "created_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.index ["exploit_id"], name: "idx_relevance_exploit"
    t.index ["use_case_id"], name: "idx_relevance_use_case"
    t.unique_constraint ["exploit_id", "use_case_id"], name: "exploit_use_case_relevance_exploit_id_use_case_id_key"
  end

  create_table "exploits", id: :serial, force: :cascade do |t|
    t.string "exploit_id", limit: 100, null: false
    t.string "name", limit: 255, null: false
    t.text "description"
    t.string "severity", limit: 20, null: false
    t.string "cve_id", limit: 50
    t.string "metasploit_module", limit: 255
    t.datetime "created_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.string "default_payload", limit: 255
    t.index ["cve_id"], name: "idx_exploit_cve", where: "(cve_id IS NOT NULL)"
    t.index ["severity"], name: "idx_exploit_severity"
    t.unique_constraint ["exploit_id"], name: "exploits_exploit_id_key"
  end

  create_table "findings", id: :serial, force: :cascade do |t|
    t.integer "scan_id", null: false
    t.integer "asset_id", null: false
    t.integer "exploit_id", null: false
    t.string "severity", limit: 20, null: false
    t.string "status", limit: 50, default: "open"
    t.integer "confidence", default: 100
    t.text "evidence"
    t.text "remediation_notes"
    t.datetime "remediated_at", precision: nil
    t.integer "remediated_by"
    t.datetime "discovered_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.datetime "updated_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.index ["asset_id"], name: "idx_finding_asset"
    t.index ["exploit_id"], name: "idx_finding_exploit"
    t.index ["scan_id"], name: "idx_finding_scan"
    t.index ["severity"], name: "idx_finding_severity"
    t.index ["status"], name: "idx_finding_status"
  end

  create_table "operating_systems", id: :serial, force: :cascade do |t|
    t.string "os_family", limit: 50, null: false
    t.string "os_name", limit: 100, null: false
    t.string "os_version", limit: 50
    t.datetime "created_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.index ["os_family"], name: "idx_os_family"
    t.unique_constraint ["os_family", "os_name", "os_version"], name: "operating_systems_os_family_os_name_os_version_key"
  end

  create_table "organizations", id: :serial, force: :cascade do |t|
    t.string "org_name", limit: 200, null: false
    t.string "org_domain", limit: 255
    t.datetime "created_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.datetime "updated_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.index "lower((org_name)::text)", name: "index_organizations_on_lower_org_name", unique: true
    t.unique_constraint ["org_name"], name: "organizations_org_name_key"
  end

  create_table "reports", id: :serial, force: :cascade do |t|
    t.string "report_name", limit: 255, null: false
    t.integer "scan_id"
    t.integer "organization_id", null: false
    t.integer "generated_by"
    t.string "report_type", limit: 50
    t.string "report_format", limit: 20
    t.jsonb "report_data"
    t.string "file_path", limit: 500
    t.datetime "generated_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.bigint "user_id", null: false
    t.index ["organization_id"], name: "idx_report_org"
    t.index ["scan_id"], name: "idx_report_scan"
    t.index ["user_id"], name: "index_reports_on_user_id"
  end

  create_table "scan_exploits", id: :serial, force: :cascade do |t|
    t.integer "scan_id", null: false
    t.integer "asset_id", null: false
    t.integer "exploit_id", null: false
    t.datetime "tested_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.string "result", limit: 50, null: false
    t.integer "execution_time_ms"
    t.index ["asset_id"], name: "idx_scan_exploit_asset"
    t.index ["result"], name: "idx_scan_exploit_result"
    t.index ["scan_id"], name: "idx_scan_exploit_scan"
  end

  create_table "scan_profiles", force: :cascade do |t|
    t.integer "organization_id", null: false
    t.string "name", null: false
    t.text "description"
    t.integer "exploit_ids", default: [], array: true
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["organization_id"], name: "index_scan_profiles_on_organization_id"
  end

  create_table "scan_targets", id: :serial, force: :cascade do |t|
    t.integer "scan_id", null: false
    t.integer "asset_id", null: false
    t.string "target_status", limit: 50, default: "pending"
    t.datetime "started_at", precision: nil
    t.datetime "completed_at", precision: nil
    t.integer "exploits_tested", default: 0
    t.integer "findings_count", default: 0
    t.index ["asset_id"], name: "idx_scan_target_asset"
    t.index ["scan_id"], name: "idx_scan_target_scan"
    t.unique_constraint ["scan_id", "asset_id"], name: "scan_targets_scan_id_asset_id_key"
  end

  create_table "scans", id: :serial, force: :cascade do |t|
    t.string "scan_name", limit: 255, null: false
    t.integer "organization_id", null: false
    t.integer "initiated_by"
    t.string "status", limit: 50, null: false
    t.datetime "start_time", precision: nil
    t.datetime "end_time", precision: nil
    t.integer "total_assets", default: 0
    t.integer "scanned_assets", default: 0
    t.integer "total_exploits_tested", default: 0
    t.integer "findings_count", default: 0
    t.integer "critical_findings", default: 0
    t.integer "high_findings", default: 0
    t.integer "medium_findings", default: 0
    t.integer "low_findings", default: 0
    t.datetime "created_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.index ["organization_id"], name: "idx_scan_org"
    t.index ["start_time", "end_time"], name: "idx_scan_times"
    t.index ["status"], name: "idx_scan_status"
  end

  create_table "sessions", force: :cascade do |t|
    t.bigint "user_id", null: false
    t.string "ip_address"
    t.string "user_agent"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.datetime "last_active_at"
    t.index ["user_id"], name: "index_sessions_on_user_id"
  end

  create_table "sites", force: :cascade do |t|
    t.integer "organization_id", null: false
    t.string "name", null: false
    t.string "network_range"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end

  create_table "solid_queue_blocked_executions", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.string "queue_name", null: false
    t.integer "priority", default: 0, null: false
    t.string "concurrency_key", null: false
    t.datetime "expires_at", null: false
    t.datetime "created_at", null: false
    t.index ["concurrency_key", "priority", "job_id"], name: "index_solid_queue_blocked_executions_for_release"
    t.index ["expires_at", "concurrency_key"], name: "index_solid_queue_blocked_executions_for_maintenance"
    t.index ["job_id"], name: "index_solid_queue_blocked_executions_on_job_id", unique: true
  end

  create_table "solid_queue_claimed_executions", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.bigint "process_id"
    t.datetime "created_at", null: false
    t.index ["job_id"], name: "index_solid_queue_claimed_executions_on_job_id", unique: true
    t.index ["process_id", "job_id"], name: "index_solid_queue_claimed_executions_on_process_id_and_job_id"
  end

  create_table "solid_queue_failed_executions", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.text "error"
    t.datetime "created_at", null: false
    t.index ["job_id"], name: "index_solid_queue_failed_executions_on_job_id", unique: true
  end

  create_table "solid_queue_jobs", force: :cascade do |t|
    t.string "queue_name", null: false
    t.string "class_name", null: false
    t.text "arguments"
    t.integer "priority", default: 0, null: false
    t.string "active_job_id"
    t.datetime "scheduled_at"
    t.datetime "finished_at"
    t.string "concurrency_key"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["active_job_id"], name: "index_solid_queue_jobs_on_active_job_id"
    t.index ["class_name"], name: "index_solid_queue_jobs_on_class_name"
    t.index ["finished_at"], name: "index_solid_queue_jobs_on_finished_at"
    t.index ["queue_name", "finished_at"], name: "index_solid_queue_jobs_for_filtering"
    t.index ["scheduled_at", "finished_at"], name: "index_solid_queue_jobs_for_alerting"
  end

  create_table "solid_queue_pauses", force: :cascade do |t|
    t.string "queue_name", null: false
    t.datetime "created_at", null: false
    t.index ["queue_name"], name: "index_solid_queue_pauses_on_queue_name", unique: true
  end

  create_table "solid_queue_processes", force: :cascade do |t|
    t.string "kind", null: false
    t.datetime "last_heartbeat_at", null: false
    t.bigint "supervisor_id"
    t.integer "pid", null: false
    t.string "hostname"
    t.text "metadata"
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.index ["last_heartbeat_at"], name: "index_solid_queue_processes_on_last_heartbeat_at"
    t.index ["name", "supervisor_id"], name: "index_solid_queue_processes_on_name_and_supervisor_id", unique: true
    t.index ["supervisor_id"], name: "index_solid_queue_processes_on_supervisor_id"
  end

  create_table "solid_queue_ready_executions", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.string "queue_name", null: false
    t.integer "priority", default: 0, null: false
    t.datetime "created_at", null: false
    t.index ["job_id"], name: "index_solid_queue_ready_executions_on_job_id", unique: true
    t.index ["priority", "job_id"], name: "index_solid_queue_poll_all"
    t.index ["queue_name", "priority", "job_id"], name: "index_solid_queue_poll_by_queue"
  end

  create_table "solid_queue_recurring_executions", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.string "task_key", null: false
    t.datetime "run_at", null: false
    t.datetime "created_at", null: false
    t.index ["job_id"], name: "index_solid_queue_recurring_executions_on_job_id", unique: true
    t.index ["task_key", "run_at"], name: "index_solid_queue_recurring_executions_on_task_key_and_run_at", unique: true
  end

  create_table "solid_queue_recurring_tasks", force: :cascade do |t|
    t.string "key", null: false
    t.string "schedule", null: false
    t.string "command", limit: 2048
    t.string "class_name"
    t.text "arguments"
    t.string "queue_name"
    t.integer "priority", default: 0
    t.boolean "static", default: true, null: false
    t.text "description"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["key"], name: "index_solid_queue_recurring_tasks_on_key", unique: true
    t.index ["static"], name: "index_solid_queue_recurring_tasks_on_static"
  end

  create_table "solid_queue_scheduled_executions", force: :cascade do |t|
    t.bigint "job_id", null: false
    t.string "queue_name", null: false
    t.integer "priority", default: 0, null: false
    t.datetime "scheduled_at", null: false
    t.datetime "created_at", null: false
    t.index ["job_id"], name: "index_solid_queue_scheduled_executions_on_job_id", unique: true
    t.index ["scheduled_at", "priority", "job_id"], name: "index_solid_queue_dispatch_all"
  end

  create_table "solid_queue_semaphores", force: :cascade do |t|
    t.string "key", null: false
    t.integer "value", default: 1, null: false
    t.datetime "expires_at", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["expires_at"], name: "index_solid_queue_semaphores_on_expires_at"
    t.index ["key", "value"], name: "index_solid_queue_semaphores_on_key_and_value"
    t.index ["key"], name: "index_solid_queue_semaphores_on_key", unique: true
  end

  create_table "use_cases", id: :serial, force: :cascade do |t|
    t.string "use_case_name", limit: 100, null: false
    t.text "description"
    t.string "category", limit: 50
    t.datetime "created_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }

    t.unique_constraint ["use_case_name"], name: "use_cases_use_case_name_key"
  end

  create_table "users", id: :serial, force: :cascade do |t|
    t.string "name", limit: 200, null: false
    t.string "email_address", limit: 100, null: false
    t.string "password_digest", limit: 255, null: false
    t.integer "organization_id", null: false
    t.string "access_level", limit: 20, null: false
    t.boolean "is_active", default: true
    t.datetime "created_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.datetime "updated_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }
    t.string "api_key"
    t.datetime "email_verified_at"
    t.index "lower((email_address)::text), organization_id", name: "index_users_on_email_and_org", unique: true
    t.index ["api_key"], name: "index_users_on_api_key", unique: true
    t.index ["email_address"], name: "idx_user_email"
    t.index ["organization_id"], name: "idx_user_org"
    t.check_constraint "access_level::text = ANY (ARRAY['admin'::character varying::text, 'read_only'::character varying::text])", name: "users_access_level_check"
  end

  add_foreign_key "asset_use_cases", "assets", name: "asset_use_cases_asset_id_fkey", on_delete: :cascade
  add_foreign_key "asset_use_cases", "use_cases", name: "asset_use_cases_use_case_id_fkey", on_delete: :cascade
  add_foreign_key "assets", "operating_systems", column: "os_id", name: "assets_os_id_fkey", on_delete: :nullify
  add_foreign_key "assets", "organizations", name: "assets_org_id_fkey", on_delete: :cascade
  add_foreign_key "exploit_os_compatibility", "exploits", name: "exploit_os_compatibility_exploit_id_fkey", on_delete: :cascade
  add_foreign_key "exploit_os_compatibility", "operating_systems", column: "os_id", name: "exploit_os_compatibility_os_id_fkey", on_delete: :cascade
  add_foreign_key "exploit_use_case_relevance", "exploits", name: "exploit_use_case_relevance_exploit_id_fkey", on_delete: :cascade
  add_foreign_key "exploit_use_case_relevance", "use_cases", name: "exploit_use_case_relevance_use_case_id_fkey", on_delete: :cascade
  add_foreign_key "findings", "assets", name: "findings_asset_id_fkey", on_delete: :cascade
  add_foreign_key "findings", "exploits", name: "findings_exploit_id_fkey", on_delete: :cascade
  add_foreign_key "findings", "scans", name: "findings_scan_id_fkey", on_delete: :cascade
  add_foreign_key "findings", "users", column: "remediated_by", name: "findings_remediated_by_fkey", on_delete: :nullify
  add_foreign_key "reports", "organizations", name: "reports_org_id_fkey", on_delete: :cascade
  add_foreign_key "reports", "scans", name: "reports_scan_id_fkey", on_delete: :cascade
  add_foreign_key "reports", "users"
  add_foreign_key "reports", "users", column: "generated_by", name: "reports_generated_by_fkey", on_delete: :nullify
  add_foreign_key "scan_exploits", "assets", name: "scan_exploits_asset_id_fkey", on_delete: :cascade
  add_foreign_key "scan_exploits", "exploits", name: "scan_exploits_exploit_id_fkey", on_delete: :cascade
  add_foreign_key "scan_exploits", "scans", name: "scan_exploits_scan_id_fkey", on_delete: :cascade
  add_foreign_key "scan_targets", "assets", name: "scan_targets_asset_id_fkey", on_delete: :cascade
  add_foreign_key "scan_targets", "scans", name: "scan_targets_scan_id_fkey", on_delete: :cascade
  add_foreign_key "scans", "organizations", name: "scans_org_id_fkey", on_delete: :cascade
  add_foreign_key "scans", "users", column: "initiated_by", name: "scans_initiated_by_fkey", on_delete: :nullify
  add_foreign_key "sessions", "users"
  add_foreign_key "solid_queue_blocked_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
  add_foreign_key "solid_queue_claimed_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
  add_foreign_key "solid_queue_failed_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
  add_foreign_key "solid_queue_ready_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
  add_foreign_key "solid_queue_recurring_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
  add_foreign_key "solid_queue_scheduled_executions", "solid_queue_jobs", column: "job_id", on_delete: :cascade
  add_foreign_key "users", "organizations", name: "users_org_id_fkey", on_delete: :cascade
end
