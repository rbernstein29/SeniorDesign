class NvdEnrichmentJob < ApplicationJob
  queue_as :default

  def perform(exploit_ids)
    nvd = Aegis.config.nvd
    exploits = Exploit.where(id: exploit_ids, cvss_score: nil).where.not(cve_id: [nil, '']).to_a
    # Return the connection to the pool — HTTP calls below are slow and we
    # don't want this thread starving web requests while it waits on NVD.
    ActiveRecord::Base.connection_pool.release_connection

    exploits.each_with_index do |exploit, i|
      NvdEnrichmentService.enrich(exploit)    # HTTP fetch + brief update_columns
      ActiveRecord::Base.connection_pool.release_connection
      sleep(nvd.rate_limit_sleep) if i < exploits.size - 1
    end
  end
end
