# app/controllers/pages_controller.rb
class PagesController < ApplicationController
  allow_unauthenticated_access only: [:app]

  def app
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
  end

  def settings
  end
end