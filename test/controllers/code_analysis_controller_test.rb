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

  test "POST /code-analysis with file returns analysis result" do
    sign_in_as(users(:admin_user))
    stub_result = { clear: true }
    OllamaService.stub(:analyze_code, stub_result) do
      file = fixture_file_upload(
        Rails.root.join("test", "fixtures", "files", "sample.rb"),
        "text/plain"
      ) rescue Rack::Test::UploadedFile.new(
        StringIO.new("def foo; puts 'hello'; end"),
        "text/plain",
        true,
        original_filename: "sample.rb"
      )
      post code_analysis_submit_path, params: { source_file: file }
    end
    # Should render successfully (result rendered inline)
    assert_response :success
  end

  test "POST /code-analysis redirects readonly user to root" do
    sign_in_as(users(:readonly_user))
    post code_analysis_submit_path, params: { content: "some code" }
    assert_redirected_to root_path
  end
end
