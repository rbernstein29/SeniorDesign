ENV["RAILS_ENV"] ||= "test"
require_relative "../config/environment"
require "rails/test_help"

module ActiveSupport
  class TestCase
    # Run tests in parallel with specified workers
    parallelize(workers: :number_of_processors)

    # Setup all fixtures in test/fixtures/*.yml for all tests in alphabetical order.
    fixtures :all

    # Add more helper methods to be used by all tests here...
  end
end

# Sign-in helper available in all controller/integration tests
class ActionDispatch::IntegrationTest
  def sign_in_as(user)
    session_record = user.sessions.create!(
      user_agent: "TestAgent",
      ip_address: "127.0.0.1",
      last_active_at: Time.current
    )
    cookies.signed[:session_id] = { value: session_record.id, httponly: true }
  end
end
