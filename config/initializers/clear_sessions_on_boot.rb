Rails.application.config.after_initialize do
  Session.delete_all
rescue => e
  Rails.logger.warn "Could not clear sessions on boot: #{e.message}"
end
