class ScanMailer < ApplicationMailer
  def completed(user, scan)
    @user = user
    @scan = scan
    mail subject: "Scan complete — #{scan.scan_name}", to: user.email_address
  end

  def failed(user, scan)
    @user = user
    @scan = scan
    mail subject: "Scan failed — #{scan.scan_name}", to: user.email_address
  end
end
