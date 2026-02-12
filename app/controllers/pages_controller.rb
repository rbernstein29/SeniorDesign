class PagesController < ApplicationController
  allow_unauthenticated_access only: [:app]
 
  def app
    # Renders app html
  end
end
