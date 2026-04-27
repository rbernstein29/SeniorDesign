require "test_helper"

class Api::ScansApiControllerTest < ActionDispatch::IntegrationTest
  def setup
    @admin_key    = users(:admin_user).api_key
    @readonly_key = users(:readonly_user).api_key
  end

  test "GET /api/:key/scans returns list with stats" do
    get "/api/#{@admin_key}/scans"
    assert_response :success
    json = JSON.parse(response.body)
    assert_kind_of Hash,  json["stats"]
    assert_kind_of Array, json["scans"]
    assert json["stats"]["total"] >= 3
  end

  test "GET /api/:key/scans returns list for readonly user" do
    get "/api/#{@readonly_key}/scans"
    assert_response :success
  end

  test "GET /api/:key/scans/:id returns scan" do
    scan = scans(:completed_scan)
    get "/api/#{@admin_key}/scans/#{scan.id}"
    assert_response :success
    json = JSON.parse(response.body)
    assert_equal scan.id,   json["scan"]["id"]
    assert_equal "completed", json["scan"]["status"]
  end

  test "GET /api/:key/scans/:id returns 404 for missing scan" do
    get "/api/#{@admin_key}/scans/0"
    assert_response :not_found
  end

  test "POST /api/:key/scans/trigger queues scan job" do
    asset = assets(:asset_one)
    assert_enqueued_with(job: ScanJob) do
      post "/api/#{@admin_key}/scans/trigger",
           params: { asset_ids: [asset.id], safe_mode: "true" }
    end
    assert_response :accepted
    json = JSON.parse(response.body)
    assert json["queued"]
    assert_equal 1, json["asset_count"]
  end

  test "POST /api/:key/scans/trigger returns 422 with no asset_ids" do
    post "/api/#{@admin_key}/scans/trigger", params: { safe_mode: "true" }
    assert_response :unprocessable_entity
  end

  test "POST /api/:key/scans/trigger returns 403 for readonly user" do
    asset = assets(:asset_one)
    post "/api/#{@readonly_key}/scans/trigger", params: { asset_ids: [asset.id] }
    assert_response :forbidden
  end

  test "POST /api/:key/scans/stop cancels running scan" do
    scan = scans(:running_scan)
    post "/api/#{@admin_key}/scans/stop", params: { scan_id: scan.id }
    assert_response :success
    json = JSON.parse(response.body)
    assert json["stopped"]
    assert_equal scan.id, json["scan_id"]
    scan.reload
    assert_equal "cancelled", scan.status
  end

  test "POST /api/:key/scans/stop returns 404 when no running scan found" do
    post "/api/#{@admin_key}/scans/stop", params: { scan_id: 0 }
    assert_response :not_found
  end

  test "POST /api/:key/scans/stop returns 403 for readonly user" do
    scan = scans(:running_scan)
    post "/api/#{@readonly_key}/scans/stop", params: { scan_id: scan.id }
    assert_response :forbidden
  end

  test "GET /api/:key/scans with invalid key returns 401" do
    get "/api/bad_key/scans"
    assert_response :unauthorized
  end
end
