require "test_helper"

class OllamaServiceTest < ActiveSupport::TestCase

  # Helper: build a fake Net::HTTP instance that returns a canned response body
  def stub_http(response_body)
    mock_resp = Object.new
    mock_resp.define_singleton_method(:body) { response_body }

    mock_http = Object.new
    mock_http.define_singleton_method(:read_timeout=) { |_| }
    mock_http.define_singleton_method(:request) { |_req| mock_resp }

    mock_http
  end

  def ollama_json(content)
    { "message" => { "content" => content } }.to_json
  end

  # ── analyze_code ──────────────────────────────────────────────────────────────

  test "analyze_code returns hash with :text and :clear keys" do
    Net::HTTP.stub(:new, stub_http(ollama_json("some findings here"))) do
      result = OllamaService.analyze_code("bad_code", "ruby", "app.rb")
      assert result.key?(:text)
      assert result.key?(:clear)
    end
  end

  test "analyze_code :clear is true when response starts with CLEAR" do
    Net::HTTP.stub(:new, stub_http(ollama_json("CLEAR"))) do
      result = OllamaService.analyze_code("safe code", "ruby", "app.rb")
      assert result[:clear]
    end
  end

  test "analyze_code :clear is true for CLEAR with surrounding whitespace" do
    Net::HTTP.stub(:new, stub_http(ollama_json("  clear  "))) do
      result = OllamaService.analyze_code("safe code", "ruby", "app.rb")
      assert result[:clear]
    end
  end

  test "analyze_code :clear is false when response contains findings" do
    findings = "---\n**Vulnerability:** SQL Injection\n**Severity:** Critical\n---"
    Net::HTTP.stub(:new, stub_http(ollama_json(findings))) do
      result = OllamaService.analyze_code("bad_code", "ruby", "app.rb")
      assert_not result[:clear]
      assert_includes result[:text], "SQL Injection"
    end
  end

  test "analyze_code returns :error when network call raises" do
    Net::HTTP.stub(:new, ->(*) { raise Errno::ECONNREFUSED, "Connection refused" }) do
      result = OllamaService.analyze_code("code", "ruby", "app.rb")
      assert result.key?(:error)
      assert_includes result[:error], "Analysis failed"
    end
  end

  test "analyze_code truncates content beyond 30 000 characters" do
    long_code = "x" * 50_000
    received_prompt = nil
    capturing_http = Object.new
    capturing_http.define_singleton_method(:read_timeout=) { |_| }
    capturing_http.define_singleton_method(:request) do |req|
      received_prompt = req.body
      mock_resp = Object.new
      mock_resp.define_singleton_method(:body) { { "message" => { "content" => "CLEAR" } }.to_json }
      mock_resp
    end

    Net::HTTP.stub(:new, capturing_http) do
      OllamaService.analyze_code(long_code, "ruby", "big.rb")
    end
    # The prompt body should not contain all 50k chars
    assert received_prompt.length < 60_000
  end

  # ── remediation_for ──────────────────────────────────────────────────────────

  test "remediation_for returns a string" do
    exploit = exploits(:exploit_one)
    finding = findings(:finding_one)
    Net::HTTP.stub(:new, stub_http(ollama_json("**Root Cause:** Test\n**Immediate Steps:** Fix it"))) do
      result = OllamaService.remediation_for(exploit, finding)
      assert_kind_of String, result
      assert result.present?
    end
  end

  test "remediation_for returns fallback string when network raises" do
    exploit = exploits(:exploit_one)
    finding = findings(:finding_one)
    Net::HTTP.stub(:new, ->(*) { raise Errno::ECONNREFUSED }) do
      result = OllamaService.remediation_for(exploit, finding)
      assert_equal "AI remediation unavailable at this time.", result
    end
  end

  # ── generate_secure_version ──────────────────────────────────────────────────

  test "generate_secure_version returns hash with :secure_code and :explanation" do
    response_text = "<secure_code>\ndef safe_query(id)\n  User.find(id)\nend\n</secure_code>\n" \
                    "<why_this_works>\nUses parameterized lookup.\n</why_this_works>"
    Net::HTTP.stub(:new, stub_http(ollama_json(response_text))) do
      result = OllamaService.generate_secure_version("bad code", "SQL Injection", language: "ruby")
      assert result.key?(:secure_code)
      assert result.key?(:explanation)
      assert_includes result[:secure_code], "safe_query"
      assert_includes result[:explanation], "parameterized"
    end
  end

  test "generate_secure_version falls back to raw text when tags are missing" do
    raw = "Here is the fixed code without proper tags."
    Net::HTTP.stub(:new, stub_http(ollama_json(raw))) do
      result = OllamaService.generate_secure_version("bad code", "XSS", language: "ruby")
      assert_equal raw, result[:secure_code]
      assert_equal "", result[:explanation]
    end
  end

  test "generate_secure_version returns :error on network failure" do
    Net::HTTP.stub(:new, ->(*) { raise Errno::ECONNREFUSED }) do
      result = OllamaService.generate_secure_version("code", "SQLi")
      assert result.key?(:error)
      assert_includes result[:error], "Secure version generation failed"
    end
  end

  # ── environment / configuration ───────────────────────────────────────────────

  test "uses OLLAMA_HOST env variable for API endpoint" do
    assert_equal ENV.fetch("OLLAMA_HOST", "http://localhost:11434"), OllamaService::OLLAMA_HOST
  end

  test "model constant is set" do
    assert OllamaService::MODEL.present?
  end
end
