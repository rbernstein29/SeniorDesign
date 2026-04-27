require "test_helper"

class Api::CodeAnalysisApiControllerTest < ActionDispatch::IntegrationTest
  def setup
    @admin_key    = users(:admin_user).api_key
    @readonly_key = users(:readonly_user).api_key
  end

  test "POST /api/:key/code-analysis with content param returns result" do
    stub_result = { text: "CLEAR" }
    OllamaService.stub(:analyze_code, stub_result) do
      post "/api/#{@admin_key}/code-analysis",
           params: { content: "def hello; puts 'hi'; end", filename: "test.rb" }
    end
    assert_response :success
    json = JSON.parse(response.body)
    assert json.key?("result")
  end

  test "POST /api/:key/code-analysis returns 403 for readonly user" do
    post "/api/#{@readonly_key}/code-analysis",
         params: { content: "code", filename: "test.rb" }
    assert_response :forbidden
  end

  test "POST /api/:key/code-analysis returns 422 with no content or file" do
    post "/api/#{@admin_key}/code-analysis"
    assert_response :unprocessable_entity
  end

  test "GET /api/:key/code-analysis with invalid key returns 401" do
    post "/api/bad_key/code-analysis", params: { content: "code", filename: "test.rb" }
    assert_response :unauthorized
  end
end
