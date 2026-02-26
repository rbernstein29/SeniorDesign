# config/routes.rb
Rails.application.routes.draw do
  resource :session
  resources :passwords, param: :token

  # Pages
  root "pages#home"
  get "/app",      to: "pages#app"
  get "/home",     to: "pages#home"
  get "/scanner",  to: "pages#scanner"
  get "/scans",    to: "pages#scans",    as: :scans
  get "/reports",  to: "pages#reports",  as: :reports
  get "/settings", to: "pages#settings", as: :settings

  # Assets
  resources :assets, only: [:index, :new, :create, :show], path: 'scan-assets'

  # Agents
  resources :agents, only: [:index, :create, :destroy] do
    member do
      get :download
    end
  end
  post 'agents/:agent_id/heartbeat', to: 'agents#heartbeat', as: :agent_heartbeat

  namespace :api do
    resources :users, only: [:index, :show, :create] do
      collection do
        post :signin
        post :signout
      end
    end
    resources :organizations, only: [:index, :show, :create]
    resources :accounts, only: [:create]
    resources :reports, only: [:index, :show, :create]
  end

  get "up" => "rails/health#show", as: :rails_health_check
end
