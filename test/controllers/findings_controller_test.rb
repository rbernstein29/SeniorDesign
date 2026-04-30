require "test_helper"

class FindingsControllerTest < ActionDispatch::IntegrationTest

  test "POST /findings/:id/ai_remediation redirects unauthenticated to login" do
    finding = findings(:finding_one)
    post ai_remediation_finding_path(finding)
    assert_redirected_to login_path
  end

  test "POST /findings/:id/ai_remediation returns JSON with text for admin" do
    sign_in_as(users(:admin_user))
    finding = findings(:finding_one)
    stub_text = "**Root Cause:** Unpatched SMB\n**Immediate Steps:** Apply MS17-010 patch\n**Long-Term Fix:** Patch management"
    OllamaService.stub(:remediation_for, stub_text) do
      post ai_remediation_finding_path(finding)
    end
    assert_response :success
    json = JSON.parse(response.body)
    assert json["text"].present?
  end

  test "POST /findings/:id/ai_remediation returns JSON for readonly user" do
    sign_in_as(users(:readonly_user))
    finding = findings(:finding_one)
    OllamaService.stub(:remediation_for, "Fix it") do
      post ai_remediation_finding_path(finding)
    end
    assert_response :success
  end

  test "POST /findings/:id/ai_remediation 404 for unknown finding" do
    sign_in_as(users(:admin_user))
    post ai_remediation_finding_path(id: 0)
    assert_response :not_found
    assert_match(/Finding not found/, JSON.parse(response.body)["error"])
  end

  test "POST /findings/:id/ai_remediation does not regenerate when text already present" do
    sign_in_as(users(:admin_user))
    finding = findings(:finding_one)
    finding.update_column(:ai_remediation, "cached")
    called = false
    OllamaService.stub(:remediation_for, ->(*) { called = true; "fresh" }) do
      post ai_remediation_finding_path(finding)
    end
    assert_response :success
    refute called, "OllamaService should not have been called when remediation already exists"
    assert_equal "cached", JSON.parse(response.body)["text"]
  end

  test "GET /findings/:id/ai_remediation_status returns pending/done/text" do
    sign_in_as(users(:admin_user))
    finding = findings(:finding_one)
    finding.update_columns(ai_remediation: "done text", ai_remediation_pending: false)
    get ai_remediation_status_finding_path(finding)
    assert_response :success
    body = JSON.parse(response.body)
    assert_equal false, body["pending"]
    assert_equal true,  body["done"]
    assert_equal "done text", body["text"]
  end

  test "GET /findings/:id/ai_remediation_status 404 for unknown finding" do
    sign_in_as(users(:admin_user))
    get ai_remediation_status_finding_path(id: 0)
    assert_response :not_found
  end
end
