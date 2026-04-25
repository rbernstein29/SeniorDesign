require 'net/http'
require 'json'

class OllamaService
  MODEL         = 'qwen2.5-coder:7b'
  OLLAMA_HOST   = ENV.fetch('OLLAMA_HOST', 'http://localhost:11434')
  SYSTEM_PROMPT = 'You are a professional security auditor. Provide accurate, educational remediation and PoC exploits.'

  # Feature 2: Whitebox Exploit Generator
  # Drop-in replacement for GeminiService.analyze_code
  # Returns { text: String, clear: Boolean } or { error: String }
  def self.analyze_code(content, language, filename)
    lang = language.presence || 'source'
    prompt = <<~PROMPT
      Act as a Whitebox Security Researcher auditing the following #{lang} file: #{filename}

      For EACH vulnerability found, output a section using this exact format:
      ---
      **Vulnerability:** [name]
      **Severity:** [Critical / High / Medium / Low]
      **Lines:** [approximate line numbers]
      **Description:** [what the vulnerability is and why it is dangerous]
      **PoC:**
      ```
      [A working curl command or Ruby script that proves the exploit — prefer curl for web vulnerabilities, Ruby for internal logic flaws]
      ```
      ---

      If NO vulnerabilities are found, respond with exactly: CLEAR

      Do not include IP addresses, usernames, hostnames, or other identifying data.
      Analyze only what is present in the code.

      ```#{lang}
      #{content.first(30_000)}
      ```
    PROMPT

    text = call_api(prompt)
    { text: text, clear: text.strip.upcase.start_with?('CLEAR') }
  rescue => e
    { error: "Analysis failed: #{e.message}" }
  end

  # Feature 1: Remediation Step
  # Drop-in replacement for GeminiService.remediation_for
  # Takes exploit/finding ActiveRecord objects, returns plain text
  def self.remediation_for(exploit, finding)
    prompt = <<~PROMPT
      A vulnerability was detected during a penetration test. Provide clear, actionable remediation.

      Vulnerability: #{exploit.name}
      Severity: #{exploit.severity}
      CVE: #{exploit.cve_id.presence || 'N/A'}
      CVSS Score: #{exploit.cvss_score.presence || 'N/A'}
      CWE: #{exploit.cwe_id.presence || 'N/A'}
      Description: #{exploit.description}
      Evidence: #{finding.evidence}

      Respond with exactly these three sections:
      **Root Cause:** (1-2 sentences)
      **Immediate Steps:** (numbered list)
      **Long-Term Fix:** (1-2 sentences)

      Keep the total response under 300 words.
    PROMPT

    call_api(prompt)
  rescue => e
    Rails.logger.warn("Ollama remediation failed: #{e.message}")
    'AI remediation unavailable at this time.'
  end

  # Feature 1 (extended): Secure Rewrite
  # Takes raw code + vulnerability type, returns a secure refactored version and explanation.
  # Returns { secure_code: String, explanation: String } or { error: String }
  def self.generate_secure_version(code, vulnerability_type, language: 'source')
    prompt = <<~PROMPT
      You are a secure code reviewer. The following #{language} code contains a #{vulnerability_type} vulnerability.

      Rewrite the code to eliminate the vulnerability without changing its intended functionality.
      Then explain why the new version is secure.

      Output using this exact format:
      <secure_code>
      [full refactored code here]
      </secure_code>
      <why_this_works>
      [explanation of what changed and why it prevents the vulnerability]
      </why_this_works>

      Vulnerable code:
      ```#{language}
      #{code.first(20_000)}
      ```
    PROMPT

    text = call_api(prompt)
    secure = text[/<secure_code>(.*?)<\/secure_code>/m, 1]&.strip
    why    = text[/<why_this_works>(.*?)<\/why_this_works>/m, 1]&.strip
    { secure_code: secure || text, explanation: why || '' }
  rescue => e
    { error: "Secure version generation failed: #{e.message}" }
  end

  class << self
    private

    def call_api(prompt)
      uri  = URI("#{OLLAMA_HOST}/api/chat")
      body = {
        model:    MODEL,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user',   content: prompt }
        ],
        stream: false
      }.to_json
      http              = Net::HTTP.new(uri.host, uri.port)
      http.read_timeout = 900
      request           = Net::HTTP::Post.new(uri.path, 'Content-Type' => 'application/json')
      request.body      = body
      resp              = http.request(request)
      JSON.parse(resp.body).dig('message', 'content') || 'No response from Ollama.'
    end
  end
end
