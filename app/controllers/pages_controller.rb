# app/controllers/pages_controller.rb
class PagesController < ApplicationController
  allow_unauthenticated_access only: [:login]

  def login
    # login page
  end

  def home
    @assets = Asset.where(organization_id: current_org_id).order(created_at: :desc) rescue []
  end

  def scanner
    # renders app/views/pages/scanner.html.erb (to be built)
  end

  def scans
  end

  def reports
    @reports = Report.where(user_id: User.where(organization_id: current_org_id).select(:id)).order(generated_at: :desc)
  end

  def settings
    @org = Organization.find_by(id: Current.session.user.organization_id)
  rescue
    @org = nil
  end
end
