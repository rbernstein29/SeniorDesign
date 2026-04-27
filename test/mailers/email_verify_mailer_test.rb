require "test_helper"

class EmailVerifyMailerTest < ActionMailer::TestCase

  def setup
    @user = users(:admin_user)
  end

  test "verify sends to the user's email address" do
    mail = EmailVerifyMailer.verify(@user)
    assert_equal [@user.email_address], mail.to
  end

  test "verify has the correct subject" do
    mail = EmailVerifyMailer.verify(@user)
    assert_equal "Verify your email", mail.subject
  end

  test "verify is delivered to the queue" do
    assert_emails 1 do
      EmailVerifyMailer.verify(@user).deliver_now
    end
  end

  test "verify HTML body includes user name" do
    mail = EmailVerifyMailer.verify(@user)
    assert_includes mail.html_part.body.to_s, @user.name
  end

  test "verify HTML body includes a verify link" do
    mail = EmailVerifyMailer.verify(@user)
    assert_includes mail.html_part.body.to_s, "verify_email"
  end

  test "verify link in HTML body contains a token" do
    mail = EmailVerifyMailer.verify(@user)
    body = mail.html_part.body.to_s
    # Link should include the generated token (a non-empty URL parameter)
    assert_match %r{verify_email/\S{10,}}, body
  end

  test "verify text part mentions Aegis" do
    mail = EmailVerifyMailer.verify(@user)
    assert_includes mail.text_part.body.to_s, "Aegis"
  end

  test "verify mentions 30-minute expiry" do
    mail = EmailVerifyMailer.verify(@user)
    combined = mail.html_part.body.to_s + mail.text_part.body.to_s
    assert_includes combined, "30 minutes"
  end
end
