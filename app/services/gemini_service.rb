require 'net/http'
require 'json'

class GeminiService
  API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent'

  def self.remediation_for(exploit, finding)
    key = ENV['GEMINI_API_KEY']
    return 'Gemini API key not configured. Set the GEMINI_API_KEY environment variable.' if key.blank?

    prompt = <<~PROMPT
      You are a cybersecurity remediation advisor. A vulnerability was detected during a scan.
      Provide clear, actionable remediation steps. Work only with the information given — do not ask for more.

      Vulnerability: #{exploit.name}
      Severity: #{exploit.severity}
      CVE: #{exploit.cve_id.presence || 'N/A'}
      CVSS Score: #{exploit.cvss_score.presence || 'N/A'}
      CWE: #{exploit.cwe_id.presence || 'N/A'}
      Description: #{exploit.description}
      Evidence: #{finding.evidence}

      Respond with exactly these three sections:
      **Root Cause:** (1-2 sentences)
      **Immediate Steps:** (numbered list of actions to take now)
      **Long-Term Fix:** (1-2 sentences)

      Keep the total response under 300 words. Do not include IP addresses, hostnames, or company names.
    PROMPT

    call_api(key, prompt)
  rescue => e
    Rails.logger.warn("Gemini remediation failed: #{e.message}")
    'AI remediation unavailable at this time.'
  end

  def self.analyze_code(content, language, filename)
    key = ENV['GEMINI_API_KEY']
    return { error: 'Gemini API key not configured. Set the GEMINI_API_KEY environment variable.' } if key.blank?

    prompt = <<~PROMPT
      You are a security researcher performing a source code audit.
      Analyze the following #{language.presence || 'source'} code for security vulnerabilities.

      For EACH vulnerability found, provide a section in this exact format:
      ---
      **Vulnerability:** [name]
      **Severity:** [Critical / High / Medium / Low]
      **Lines:** [approximate line numbers]
      **Description:** [what the vulnerability is and why it's dangerous]
      **Python PoC:**
      ```python
      [working Python proof-of-concept exploit script]
      ```
      ---

      If NO vulnerabilities are found, respond with exactly: CLEAR

      Do not include IP addresses, usernames, hostnames, or other identifying data in your response.
      Analyze only what is present in the code.

      File: #{filename}
      ```#{language}
      #{content.first(30_000)}
      ```
    PROMPT

    text = call_api(key, prompt)
    { text: text, clear: text.strip.upcase.start_with?('CLEAR') }
  rescue => e
    { error: "Analysis failed: #{e.message}" }
  end

  def self.call_api(key, prompt)
    uri  = URI("#{API_URL}?key=#{key}")
    body = { contents: [{ parts: [{ text: prompt }] }] }.to_json
    resp = Net::HTTP.post(uri, body, 'Content-Type' => 'application/json')
    JSON.parse(resp.body).dig('candidates', 0, 'content', 'parts', 0, 'text') || 'No response from Gemini.'
  end
  private_class_method :call_api
end
