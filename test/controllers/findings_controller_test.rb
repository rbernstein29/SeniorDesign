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
end
