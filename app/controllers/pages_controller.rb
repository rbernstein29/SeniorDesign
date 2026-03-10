# app/controllers/pages_controller.rb
class PagesController < ApplicationController
  allow_unauthenticated_access only: [:login]

  def login
    # login page
  end

  def home
    @assets = Asset.all rescue []
  end

  def scanner
    # renders app/views/pages/scanner.html.erb (to be built)
  end

  def scans
  end

  def reports
    @reports = Report.where(org_id: Current.session.user.org_id)
                     .order(generated_at: :desc)
  rescue
    @reports = []
  end

  def settings
  end
end
