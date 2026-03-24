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
      post trigger_scan_path, params: { trigger_scan: { exploit_ids: [] } }
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
end
