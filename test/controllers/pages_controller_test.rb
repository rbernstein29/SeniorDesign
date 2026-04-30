require "test_helper"

class PagesControllerTest < ActionDispatch::IntegrationTest

  # ── GET /home ────────────────────────────────────────────────────────────────

  test "GET /home redirects unauthenticated to login" do
    get home_path
    assert_redirected_to login_path
  end

  test "GET /home returns 200 for admin" do
    sign_in_as(users(:admin_user))
    get home_path
    assert_response :success
  end

  test "GET /home returns 200 for readonly user" do
    sign_in_as(users(:readonly_user))
    get home_path
    assert_response :success
  end

  # ── GET /scanner ──────────────────────────────────────────────────────────────

  test "GET /scanner redirects unauthenticated to login" do
    get scanner_path
    assert_redirected_to login_path
  end

  test "GET /scanner returns 200 for admin" do
    sign_in_as(users(:admin_user))
    get scanner_path
    assert_response :success
  end

  test "GET /scanner redirects readonly to root" do
    sign_in_as(users(:readonly_user))
    get scanner_path
    assert_redirected_to root_path
  end

  # ── POST /scanner/trigger ────────────────────────────────────────────────────

  test "POST /scanner/trigger redirects unauthenticated to login" do
    post trigger_scan_path
    assert_redirected_to login_path
  end

  test "POST /scanner/trigger redirects readonly to root" do
    sign_in_as(users(:readonly_user))
    post trigger_scan_path
    assert_redirected_to root_path
  end

  test "POST /scanner/trigger queues a scan and redirects admin to scans" do
    sign_in_as(users(:admin_user))
    assert_enqueued_with(job: ScanJob) do
      post trigger_scan_path, params: {
        target_mode: 'asset',
        asset_ids:   [assets(:asset_one).id],
        severities:  ['low'],
        platform:    'any'
      }
    end
    assert_redirected_to scans_path
  end

  # ── GET /scans ────────────────────────────────────────────────────────────────

  test "GET /scans redirects unauthenticated to login" do
    get scans_path
    assert_redirected_to login_path
  end

  test "GET /scans returns 200 for admin" do
    sign_in_as(users(:admin_user))
    get scans_path
    assert_response :success
  end

  test "GET /scans redirects readonly to root" do
    sign_in_as(users(:readonly_user))
    get scans_path
    assert_redirected_to root_path
  end

  # ── POST /scans/stop ─────────────────────────────────────────────────────────

  test "POST /scans/stop redirects unauthenticated to login" do
    post stop_scan_path
    assert_redirected_to login_path
  end

  test "POST /scans/stop cancels a running scan" do
    sign_in_as(users(:admin_user))
    scan = scans(:running_scan)
    post stop_scan_path, params: { scan_id: scan.id }
    assert_redirected_to scans_path
    scan.reload
    assert_equal "cancelled", scan.status
  end

  # ── GET /reports ──────────────────────────────────────────────────────────────

  test "GET /reports redirects unauthenticated to login" do
    get reports_path
    assert_redirected_to login_path
  end

  test "GET /reports returns 200 for authenticated user" do
    sign_in_as(users(:admin_user))
    get reports_path
    assert_response :success
  end

  # ── GET /settings ─────────────────────────────────────────────────────────────

  test "GET /settings redirects unauthenticated to login" do
    get settings_path
    assert_redirected_to login_path
  end

  test "GET /settings returns 200 for authenticated user" do
    sign_in_as(users(:admin_user))
    get settings_path
    assert_response :success
  end

  # ── GET /read_only_accounts ───────────────────────────────────────────────────

  test "GET /read_only_accounts redirects unauthenticated to login" do
    get read_only_accounts_path
    assert_redirected_to login_path
  end

  test "GET /read_only_accounts returns 200 for authenticated user" do
    sign_in_as(users(:admin_user))
    get read_only_accounts_path
    assert_response :success
  end

  # ── GET /api-docs ──────────────────────────────────────────────────────────────

  test "GET /api-docs redirects unauthenticated to login" do
    get api_docs_path
    assert_redirected_to login_path
  end

  test "GET /api-docs returns 200 for admin" do
    sign_in_as(users(:admin_user))
    get api_docs_path
    assert_response :success
  end

  test "GET /api-docs returns 200 for readonly user" do
    sign_in_as(users(:readonly_user))
    get api_docs_path
    assert_response :success
  end

  # ── GET /home/recent_findings (partial) ─────────────────────────────────────

  test "GET /home/recent_findings returns the partial for an authenticated user" do
    sign_in_as(users(:admin_user))
    get home_recent_findings_path
    assert_response :success
  end

  # ── GET /home/stats ─────────────────────────────────────────────────────────

  test "GET /home/stats returns aggregate JSON" do
    sign_in_as(users(:admin_user))
    get home_stats_path
    assert_response :success
    body = JSON.parse(response.body)
    assert body["stats"].key?("total_assets")
    assert body["stats"].key?("active_scans")
    assert body["stat_deltas"].key?("offline_agents")
  end

  test "GET /home/stats reflects offline-agent deltas when an agent is offline" do
    sign_in_as(users(:admin_user))
    Agent.where(organization_id: organizations(:acme).id).update_all(last_seen: 2.days.ago, status: 'disconnected')
    get home_stats_path
    assert_response :success
    body = JSON.parse(response.body)
    assert_equal "Not reachable", body["stat_deltas"]["offline_agents"]
  end

  # ── POST /scanner/trigger edge cases ────────────────────────────────────────

  test "POST /scanner/trigger with no asset ids returns alert" do
    sign_in_as(users(:admin_user))
    post trigger_scan_path, params: { asset_ids: [] }
    assert_redirected_to scanner_path
    assert_not_nil flash[:alert]
  end

  test "POST /scanner/trigger uses scan profile module allowlist when profile selected" do
    sign_in_as(users(:admin_user))
    profile = ScanProfile.create!(
      organization_id: organizations(:acme).id,
      name: "Custom",
      exploit_ids: [exploits(:exploit_one).id],
      safe_mode: true
    )

    assert_enqueued_with(job: ScanJob) do
      post trigger_scan_path, params: {
        asset_ids:  [assets(:asset_one).id],
        profile_id: profile.id
      }
    end
    job = ActiveJob::Base.queue_adapter.enqueued_jobs.last
    filter_params = job[:args][1]
    assert filter_params["module_allowlist"]&.any?
  end

  # ── GET /scans/status ───────────────────────────────────────────────────────

  test "GET /scans/status returns counts and selected scans" do
    sign_in_as(users(:admin_user))
    scan = scans(:running_scan)
    get scans_status_path, params: { ids: [scan.id] }
    assert_response :success
    body = JSON.parse(response.body)
    assert body["stats"].key?("running")
    assert body["scans"].any? { |s| s["id"] == scan.id }
  end

  test "GET /scans/status with no ids returns empty scans array" do
    sign_in_as(users(:admin_user))
    get scans_status_path
    assert_response :success
    assert_equal [], JSON.parse(response.body)["scans"]
  end

  # ── /settings: handle missing org gracefully ────────────────────────────────

  test "GET /settings handles missing organization (rescue branch)" do
    sign_in_as(users(:admin_user))
    Organization.stub(:find_by, ->(*) { raise ActiveRecord::StatementInvalid }) do
      get settings_path
    end
    assert_response :success
  end

  # ── /create_ro_account ──────────────────────────────────────────────────────

  test "GET /create_ro_account renders for admin" do
    sign_in_as(users(:admin_user))
    get create_ro_account_path
    assert_response :success
  end

  test "GET /create_ro_account redirects readonly user to root" do
    sign_in_as(users(:readonly_user))
    get create_ro_account_path
    assert_redirected_to root_path
  end
end
