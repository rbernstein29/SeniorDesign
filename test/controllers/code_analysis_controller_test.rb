require "test_helper"

class CodeAnalysisControllerTest < ActionDispatch::IntegrationTest

  test "GET /code-analysis redirects unauthenticated to login" do
    get code_analysis_path
    assert_redirected_to login_path
  end

  test "GET /code-analysis returns 200 for admin" do
    sign_in_as(users(:admin_user))
    get code_analysis_path
    assert_response :success
  end

  test "GET /code-analysis redirects readonly user to root" do
    sign_in_as(users(:readonly_user))
    get code_analysis_path
    assert_redirected_to root_path
  end

  test "POST /code-analysis with file returns CLEAR result" do
    sign_in_as(users(:admin_user))
    OllamaService.stub(:analyze_code, { clear: true }) do
      post code_analysis_submit_path, params: {
        source_file: Rack::Test::UploadedFile.new(
          StringIO.new("def foo; puts 'hello'; end"), "text/plain",
          true, original_filename: "sample.rb"
        )
      }
    end
    assert_response :success
  end

  test "POST /code-analysis with file returns findings" do
    sign_in_as(users(:admin_user))
    findings_text = "---\n**Vulnerability:** SQL Injection\n**Severity:** Critical\n---"
    OllamaService.stub(:analyze_code, { text: findings_text, clear: false }) do
      post code_analysis_submit_path, params: {
        source_file: Rack::Test::UploadedFile.new(
          StringIO.new("User.where(\"id = #{1}\")"), "text/plain",
          true, original_filename: "query.rb"
        )
      }
    end
    assert_response :success
  end

  test "POST /code-analysis with no file redirects with alert" do
    sign_in_as(users(:admin_user))
    post code_analysis_submit_path
    assert_redirected_to code_analysis_path
    assert_not_nil flash[:alert]
  end

  test "POST /code-analysis with oversized file redirects with alert" do
    sign_in_as(users(:admin_user))
    big_content = "x" * (1.megabyte + 1)
    post code_analysis_submit_path, params: {
      source_file: Rack::Test::UploadedFile.new(
        StringIO.new(big_content), "text/plain",
        true, original_filename: "big.rb"
      )
    }
    assert_redirected_to code_analysis_path
    assert_not_nil flash[:alert]
  end

  test "POST /code-analysis redirects readonly user to root" do
    sign_in_as(users(:readonly_user))
    post code_analysis_submit_path, params: { source_file: nil }
    assert_redirected_to root_path
  end
end
