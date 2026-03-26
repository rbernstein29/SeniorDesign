class EmailVerifyMailer < ApplicationMailer
  def verify(user)
    @user = user
    mail subject: "Verify your email", to: user.email_address
  end
end