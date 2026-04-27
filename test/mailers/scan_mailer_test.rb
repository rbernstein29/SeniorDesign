require "test_helper"

class ScanMailerTest < ActionMailer::TestCase
  def setup
    @user = users(:admin_user)
    @scan = scans(:completed_scan)
    @failed_scan = scans(:failed_scan)
  end

  # ── completed ────────────────────────────────────────────────────────────────

  test "completed mail is sent to the user's email" do
    mail = ScanMailer.completed(@user, @scan)
    assert_equal [@user.email_address], mail.to
  end

  test "completed mail has correct subject" do
    mail = ScanMailer.completed(@user, @scan)
    assert_equal "Scan complete — #{@scan.scan_name}", mail.subject
  end

  test "completed mail is delivered" do
    assert_emails 1 do
      ScanMailer.completed(@user, @scan).deliver_now
    end
  end

  # ── failed ───────────────────────────────────────────────────────────────────

  test "failed mail is sent to the user's email" do
    mail = ScanMailer.failed(@user, @failed_scan)
    assert_equal [@user.email_address], mail.to
  end

  test "failed mail has correct subject" do
    mail = ScanMailer.failed(@user, @failed_scan)
    assert_equal "Scan failed — #{@failed_scan.scan_name}", mail.subject
  end

  test "failed mail is delivered" do
    assert_emails 1 do
      ScanMailer.failed(@user, @failed_scan).deliver_now
    end
  end
end
