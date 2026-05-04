class NvdEnrichmentJob < ApplicationJob
  queue_as :default

  def perform(exploit_ids)
    nvd = Aegis.config.nvd
    exploits = Exploit.where(id: exploit_ids, cvss_score: nil).where.not(cve_id: [nil, ''])
    exploits.each_with_index do |exploit, i|
      NvdEnrichmentService.enrich(exploit)
      sleep(nvd.rate_limit_sleep) if i < exploits.size - 1
    end
  end
end
