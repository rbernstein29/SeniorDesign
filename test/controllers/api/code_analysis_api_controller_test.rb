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

  test "POST /api/:key/code-analysis with source_file uses uploaded contents" do
    file = Rack::Test::UploadedFile.new(StringIO.new("puts 1"), "text/plain", original_filename: "u.rb")
    captured = nil
    stub = ->(content, ext, fname) { captured = [content, ext, fname]; "OK" }
    OllamaService.stub(:analyze_code, stub) do
      post "/api/#{@admin_key}/code-analysis", params: { source_file: file }
    end
    assert_response :success
    assert_equal "puts 1", captured[0]
    assert_equal "rb", captured[1]
    assert_equal "u.rb", captured[2]
  end

  test "POST /api/:key/code-analysis rejects oversize uploads" do
    big = Rack::Test::UploadedFile.new(StringIO.new("x" * (Api::CodeAnalysisApiController::MAX_FILE_SIZE + 1)), "text/plain", original_filename: "big.txt")
    post "/api/#{@admin_key}/code-analysis", params: { source_file: big }
    assert_response :unprocessable_entity
    assert_match(/too large/i, JSON.parse(response.body)["error"])
  end

  test "POST /api/:key/code-analysis surfaces service errors as 503" do
    OllamaService.stub(:analyze_code, { error: "ollama down" }) do
      post "/api/#{@admin_key}/code-analysis", params: { content: "x", filename: "x.rb" }
    end
    assert_response :service_unavailable
    assert_equal "ollama down", JSON.parse(response.body)["error"]
  end
end
