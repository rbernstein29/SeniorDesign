require "test_helper"

class Api::FindingsApiControllerTest < ActionDispatch::IntegrationTest
  def setup
    @admin_key    = "test_api_key_admin_abc123xyz"
    @readonly_key = "test_api_key_readonly_xyz789"
  end

  test "GET /api/:key/findings returns list" do
    get "/api/#{@admin_key}/findings"
    assert_response :success
    json = JSON.parse(response.body)
    assert_kind_of Array, json["findings"]
  end

  test "GET /api/:key/findings returns list for readonly user" do
    get "/api/#{@readonly_key}/findings"
    assert_response :success
  end

  test "GET /api/:key/findings filters by scan_id" do
    scan = scans(:completed_scan)
    get "/api/#{@admin_key}/findings?scan_id=#{scan.id}"
    assert_response :success
    json = JSON.parse(response.body)
    json["findings"].each do |f|
      assert_equal scan.id, f["scan_id"]
    end
  end

  test "GET /api/:key/findings filters by severity" do
    get "/api/#{@admin_key}/findings?severity=critical"
    assert_response :success
    json = JSON.parse(response.body)
    json["findings"].each do |f|
      assert_equal "critical", f["severity"]
    end
  end

  test "GET /api/:key/findings/:id returns finding" do
    finding = findings(:finding_one)
    get "/api/#{@admin_key}/findings/#{finding.id}"
    assert_response :success
    json = JSON.parse(response.body)
    assert_equal finding.id, json["finding"]["id"]
    assert_equal "critical",  json["finding"]["severity"]
  end

  test "GET /api/:key/findings/:id returns 404 for missing finding" do
    get "/api/#{@admin_key}/findings/0"
    assert_response :not_found
  end

  test "POST /api/:key/findings/:id/ai_remediation caches and returns text" do
    finding = findings(:finding_one)
    stub_text = "**Root Cause:** Test\n**Immediate Steps:** Fix it\n**Long-Term Fix:** Done"
    OllamaService.stub(:remediation_for, stub_text) do
      post "/api/#{@admin_key}/findings/#{finding.id}/ai_remediation"
    end
    assert_response :success
    json = JSON.parse(response.body)
    assert json["text"].present?
  end

  test "POST /api/:key/findings/:id/ai_remediation returns 404 for missing finding" do
    post "/api/#{@admin_key}/findings/0/ai_remediation"
    assert_response :not_found
  end

  test "GET /api/:key/findings with invalid key returns 401" do
    get "/api/bad_key/findings"
    assert_response :unauthorized
  end
end
