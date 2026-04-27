require "test_helper"

class PasswordsMailerTest < ActionMailer::TestCase

  def setup
    @user = users(:admin_user)
  end

  test "reset sends to the user's email address" do
    mail = PasswordsMailer.reset(@user)
    assert_equal [@user.email_address], mail.to
  end

  test "reset has the correct subject" do
    mail = PasswordsMailer.reset(@user)
    assert_equal "Reset your password", mail.subject
  end

  test "reset is delivered to the queue" do
    assert_emails 1 do
      PasswordsMailer.reset(@user).deliver_now
    end
  end

  test "reset HTML body includes password reset link" do
    mail = PasswordsMailer.reset(@user)
    assert_includes mail.html_part.body.to_s, "password"
  end

  test "reset link contains a reset token" do
    mail = PasswordsMailer.reset(@user)
    body = mail.html_part.body.to_s
    # Link should include a token segment
    assert_match %r{passwords/\S{10,}}, body
  end

  test "reset mentions 15-minute expiry" do
    mail = PasswordsMailer.reset(@user)
    combined = mail.html_part.body.to_s + mail.text_part.body.to_s
    assert_includes combined, "15 minutes"
  end
end
