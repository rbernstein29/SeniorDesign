ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"

# Wrap entire test run in a transaction so dev data is preserved.
# fixtures :all truncates tables — this rollback undoes that at the end.
ActiveRecord::Base.establish_connection
ActiveRecord::Base.connection.begin_transaction(joinable: false)
Minitest.after_run do
  ActiveRecord::Base.connection.rollback_transaction
  # Fixture loading calls reset_pk_sequence! which persists across the rollback
  # (sequences are non-transactional). Re-sync all sequences to dev data max IDs.
  %w[scans reports findings scan_exploits scan_targets exploits assets
     organizations users agents sites sessions scan_profiles].each do |t|
    ActiveRecord::Base.connection.execute(
      "SELECT setval(pg_get_serial_sequence('vuln_scanner.#{t}', 'id'), " \
      "COALESCE((SELECT MAX(id) FROM vuln_scanner.#{t}), 1))"
    )
  rescue StandardError
    nil
  end
end

module ActiveSupport
  class TestCase
    # Run tests in parallel with specified workers
    parallelize(workers: 1)

    # Setup all fixtures in test/fixtures/*.yml for all tests in alphabetical order.
    fixtures :all

    # Add more helper methods to be used by all tests here...
  end
end

# Sign-in helper available in all controller/integration tests
class ActionDispatch::IntegrationTest
  def sign_in_as(user)
    post session_path, params: { email_address: user.email_address, password: "password" }
  end
end
